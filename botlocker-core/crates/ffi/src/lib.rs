//! C ABI over `botlocker-core`, used by the nginx module.
//! The contract is documented in `include/botlocker.h`.

use std::ffi::{c_char, CStr, CString};
use std::net::IpAddr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use botlocker_core::{Action, Config, Engine, NormalizedRequest};

/// Opaque to C. Wraps the engine so C never sees Rust layout.
pub struct BlEngine(Engine);

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlAction {
    Proxy = 0,
    Challenge = 1,
    Trap = 2,
}

#[repr(C)]
pub struct BlHeader {
    pub name: *const c_char,
    pub name_len: usize,
    pub value: *const c_char,
    pub value_len: usize,
}

#[repr(C)]
pub struct BlRequest {
    pub method: *const c_char,
    pub method_len: usize,
    pub path: *const c_char,
    pub path_len: usize,
    pub query: *const c_char,
    pub query_len: usize,
    pub client_ip: *const c_char,
    pub client_ip_len: usize,
    pub headers: *const BlHeader,
    pub header_count: usize,
}

/// Copies `len` bytes at `ptr` into a String. Invalid UTF-8 becomes U+FFFD.
///
/// # Safety
/// `ptr` must be valid for `len` bytes, or NULL with `len == 0`.
unsafe fn lossy(ptr: *const c_char, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        return String::new();
    }
    String::from_utf8_lossy(slice::from_raw_parts(ptr as *const u8, len)).into_owned()
}

/// # Safety
/// Same contract as [`lossy`].
unsafe fn lossy_opt(ptr: *const c_char, len: usize) -> Option<String> {
    if ptr.is_null() || len == 0 {
        None
    } else {
        Some(lossy(ptr, len))
    }
}

/// # Safety
/// `req` must point to a valid `BlRequest` whose pointers obey the header contract.
unsafe fn normalize(req: &BlRequest) -> Option<NormalizedRequest> {
    let client_ip: IpAddr = lossy(req.client_ip, req.client_ip_len).parse().ok()?;

    let headers = if req.headers.is_null() || req.header_count == 0 {
        Vec::new()
    } else {
        slice::from_raw_parts(req.headers, req.header_count)
            .iter()
            .map(|h| {
                (
                    lossy(h.name, h.name_len).to_ascii_lowercase(),
                    lossy(h.value, h.value_len),
                )
            })
            .collect()
    };

    Some(NormalizedRequest {
        method: lossy(req.method, req.method_len),
        path: lossy(req.path, req.path_len),
        query: lossy_opt(req.query, req.query_len),
        headers,
        client_ip,
        asn: None,
        tls_fingerprint: None,
    })
}

fn to_c_string(s: String) -> *mut c_char {
    CString::new(s).map(CString::into_raw).unwrap_or(ptr::null_mut())
}

fn write_error(err: *mut c_char, err_len: usize, msg: &str) {
    if err.is_null() || err_len == 0 {
        return;
    }
    let bytes = msg.as_bytes();
    let n = bytes.len().min(err_len - 1);
    // SAFETY: the caller promises `err` is valid for `err_len` bytes.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), err as *mut u8, n);
        *err.add(n) = 0;
    }
}

/// # Safety
/// `config_path` must be a NUL-terminated string. `secret` must be valid for
/// `secret_len` bytes. `err` must be valid for `err_len` bytes, or NULL.
#[no_mangle]
pub unsafe extern "C" fn bl_engine_new(
    config_path: *const c_char,
    secret: *const c_char,
    secret_len: usize,
    err: *mut c_char,
    err_len: usize,
) -> *mut BlEngine {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<Engine, String> {
        if config_path.is_null() {
            return Err("config path is NULL".into());
        }
        let path = CStr::from_ptr(config_path)
            .to_str()
            .map_err(|_| "config path is not UTF-8".to_string())?;
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {path}: {e}"))?;
        let cfg = Config::from_toml(&text).map_err(|e| e.to_string())?;
        let secret_bytes = if secret.is_null() {
            Vec::new()
        } else {
            slice::from_raw_parts(secret as *const u8, secret_len).to_vec()
        };
        Engine::new(cfg, secret_bytes).map_err(|e| e.to_string())
    }));

    match result {
        Ok(Ok(engine)) => Box::into_raw(Box::new(BlEngine(engine))),
        Ok(Err(msg)) => {
            write_error(err, err_len, &msg);
            ptr::null_mut()
        }
        Err(_) => {
            write_error(err, err_len, "internal error while creating engine");
            ptr::null_mut()
        }
    }
}

/// # Safety
/// `engine` must be NULL or a pointer from [`bl_engine_new`] that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn bl_engine_free(engine: *mut BlEngine) {
    if !engine.is_null() {
        drop(Box::from_raw(engine));
    }
}

/// # Safety
/// `engine` must be a live engine. `req` must be a valid request.
#[no_mangle]
pub unsafe extern "C" fn bl_classify(
    engine: *const BlEngine,
    req: *const BlRequest,
    now: u64,
) -> BlAction {
    let (Some(engine), Some(req)) = (engine.as_ref(), req.as_ref()) else {
        return BlAction::Proxy;
    };
    catch_unwind(AssertUnwindSafe(|| match normalize(req) {
        Some(normalized) => match engine.0.classify(&normalized, now).action {
            Action::Proxy => BlAction::Proxy,
            Action::Challenge => BlAction::Challenge,
            Action::Trap => BlAction::Trap,
        },
        None => BlAction::Proxy,
    }))
    .unwrap_or(BlAction::Proxy)
}

/// The decision plus why it was made. Free with `bl_decision_free`.
#[repr(C)]
pub struct BlDecision {
    pub action: BlAction,
    pub score: f64,
    /// Short reason label, e.g. "honeypot", "automated", "scored". Owned by the caller.
    pub reason: *mut c_char,
    /// Evidence lines separated by "\n". Owned by the caller.
    pub evidence: *mut c_char,
}

fn empty_decision(action: BlAction) -> BlDecision {
    BlDecision {
        action,
        score: 0.0,
        reason: ptr::null_mut(),
        evidence: ptr::null_mut(),
    }
}

/// Like `bl_classify`, but also returns the reason and evidence. Fails open.
///
/// # Safety
/// Same contract as `bl_classify`.
#[no_mangle]
pub unsafe extern "C" fn bl_classify_detail(
    engine: *const BlEngine,
    req: *const BlRequest,
    now: u64,
) -> BlDecision {
    let (Some(engine), Some(req)) = (engine.as_ref(), req.as_ref()) else {
        return empty_decision(BlAction::Proxy);
    };
    catch_unwind(AssertUnwindSafe(|| match normalize(req) {
        Some(normalized) => {
            let class = engine.0.classify(&normalized, now);
            let action = match class.action {
                Action::Proxy => BlAction::Proxy,
                Action::Challenge => BlAction::Challenge,
                Action::Trap => BlAction::Trap,
            };
            BlDecision {
                action,
                score: class.score.total,
                reason: to_c_string(class.reason.label()),
                evidence: to_c_string(class.evidence.join("\n").replace('\r', " ")),
            }
        }
        None => empty_decision(BlAction::Proxy),
    }))
    .unwrap_or_else(|_| empty_decision(BlAction::Proxy))
}

/// Frees the strings in a decision returned by `bl_classify_detail`.
///
/// # Safety
/// `d` must come from `bl_classify_detail` and not have been freed.
#[no_mangle]
pub unsafe extern "C" fn bl_decision_free(d: BlDecision) {
    bl_string_free(d.reason);
    bl_string_free(d.evidence);
}

/// # Safety
/// `engine` must be a live engine. `path` must be valid for `path_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn bl_maze_html(
    engine: *const BlEngine,
    path: *const c_char,
    path_len: usize,
) -> *mut c_char {
    let Some(engine) = engine.as_ref() else {
        return ptr::null_mut();
    };
    catch_unwind(AssertUnwindSafe(|| {
        to_c_string(engine.0.maze_html(&lossy(path, path_len)))
    }))
    .unwrap_or(ptr::null_mut())
}

fn parse_ip(ip: &str) -> Option<IpAddr> {
    ip.parse().ok()
}

/// # Safety
/// `engine` must be live. `client_ip` must be valid for `client_ip_len` bytes.
/// `next` must be valid for `next_len` bytes, or NULL with `next_len == 0`.
#[no_mangle]
pub unsafe extern "C" fn bl_challenge_html(
    engine: *const BlEngine,
    client_ip: *const c_char,
    client_ip_len: usize,
    now: u64,
    next: *const c_char,
    next_len: usize,
) -> *mut c_char {
    let Some(engine) = engine.as_ref() else {
        return ptr::null_mut();
    };
    let Some(ip) = parse_ip(&lossy(client_ip, client_ip_len)) else {
        return ptr::null_mut();
    };
    let next = lossy_opt(next, next_len);
    catch_unwind(AssertUnwindSafe(|| {
        to_c_string(engine.0.challenge_html(ip, now, next.as_deref()))
    }))
    .unwrap_or(ptr::null_mut())
}

/// # Safety
/// Same contract as [`bl_challenge_html`], with `query` in place of `next`.
#[no_mangle]
pub unsafe extern "C" fn bl_challenge_endpoint_html(
    engine: *const BlEngine,
    client_ip: *const c_char,
    client_ip_len: usize,
    now: u64,
    query: *const c_char,
    query_len: usize,
) -> *mut c_char {
    let Some(engine) = engine.as_ref() else {
        return ptr::null_mut();
    };
    let Some(ip) = parse_ip(&lossy(client_ip, client_ip_len)) else {
        return ptr::null_mut();
    };
    let query = lossy(query, query_len);
    let next = url::form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == "next")
        .map(|(_, v)| v.into_owned());
    catch_unwind(AssertUnwindSafe(|| {
        to_c_string(engine.0.challenge_html(ip, now, next.as_deref()))
    }))
    .unwrap_or(ptr::null_mut())
}

/// Handles a browser report from the challenge page. `query` is the raw query
/// string (`t=...&w=..&h=..&z=..`). Returns a JSON object that the caller must free.
///
/// # Safety
/// `engine` must be a live engine. `client_ip` must be valid for `client_ip_len`
/// bytes. `query` must be valid for `query_len` bytes, or NULL with `query_len == 0`.
#[no_mangle]
pub unsafe extern "C" fn bl_report(
    engine: *const BlEngine,
    client_ip: *const c_char,
    client_ip_len: usize,
    now: u64,
    query: *const c_char,
    query_len: usize,
) -> *mut c_char {
    let Some(engine) = engine.as_ref() else {
        return ptr::null_mut();
    };
    let Some(ip) = parse_ip(&lossy(client_ip, client_ip_len)) else {
        return to_c_string(r#"{"ok":false}"#.to_string());
    };
    let query = lossy(query, query_len);
    catch_unwind(AssertUnwindSafe(|| {
        to_c_string(engine.0.report(ip, now, &query))
    }))
    .unwrap_or(ptr::null_mut())
}

/// # Safety
/// `engine` must be a live engine.
#[no_mangle]
pub unsafe extern "C" fn bl_honeypot_link(engine: *const BlEngine) -> *mut c_char {
    let Some(engine) = engine.as_ref() else {
        return ptr::null_mut();
    };
    catch_unwind(AssertUnwindSafe(|| to_c_string(engine.0.honeypot_link())))
        .unwrap_or(ptr::null_mut())
}

/// # Safety
/// `s` must be NULL or a string returned by this API that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn bl_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::io::Write;

    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn engine_from(toml: &str) -> *mut BlEngine {
        let dir = std::env::temp_dir().join(format!("bl-ffi-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{:x}.toml", rand_suffix()));
        std::fs::File::create(&path)
            .unwrap()
            .write_all(toml.as_bytes())
            .unwrap();
        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        let mut err = [0 as c_char; 256];
        let e = unsafe {
            bl_engine_new(
                cpath.as_ptr(),
                SECRET.as_ptr() as *const c_char,
                SECRET.len(),
                err.as_mut_ptr(),
                err.len(),
            )
        };
        assert!(!e.is_null(), "engine failed: {:?}", unsafe {
            CStr::from_ptr(err.as_ptr())
        });
        e
    }

    fn rand_suffix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    fn request<'a>(path: &'a str, headers: &'a [BlHeader], ip: &'a str) -> BlRequest {
        BlRequest {
            method: b"GET".as_ptr() as *const c_char,
            method_len: 3,
            path: path.as_ptr() as *const c_char,
            path_len: path.len(),
            query: ptr::null(),
            query_len: 0,
            client_ip: ip.as_ptr() as *const c_char,
            client_ip_len: ip.len(),
            headers: headers.as_ptr(),
            header_count: headers.len(),
        }
    }

    fn h(name: &str, value: &str) -> BlHeader {
        BlHeader {
            name: name.as_ptr() as *const c_char,
            name_len: name.len(),
            value: value.as_ptr() as *const c_char,
            value_len: value.len(),
        }
    }

    const BASE_TOML: &str = "origin = \"https://origin.example\"\nmaze_prefix = \"/maze/\"\n";

    #[test]
    fn maze_path_is_trapped_and_browser_is_proxied() {
        let e = engine_from(BASE_TOML);
        let browser = [
            h("User-Agent", "Mozilla/5.0 Chrome/120.0"),
            h("Accept", "text/html"),
            h("Accept-Language", "en-US"),
            h("Sec-Fetch-Site", "none"),
        ];
        let ip = "203.0.113.5";
        let req = request("/", &browser, ip);
        assert_eq!(unsafe { bl_classify(e, &req, 1_700_000_000) }, BlAction::Proxy);

        let trap = request("/maze/x", &browser, ip);
        assert_eq!(unsafe { bl_classify(e, &trap, 1_700_000_000) }, BlAction::Trap);
        unsafe { bl_engine_free(e) };
    }

    #[test]
    fn bad_ip_fails_open_to_proxy() {
        let e = engine_from(BASE_TOML);
        let req = request("/maze/x", &[], "not-an-ip");
        assert_eq!(unsafe { bl_classify(e, &req, 0) }, BlAction::Proxy);
        unsafe { bl_engine_free(e) };
    }

    #[test]
    fn classify_detail_returns_reason_and_evidence() {
        let e = engine_from(BASE_TOML);
        let req = request("/maze/x", &[], "203.0.113.5");
        let d = unsafe { bl_classify_detail(e, &req, 1_700_000_000) };
        assert_eq!(d.action, BlAction::Trap);
        let reason = unsafe { CStr::from_ptr(d.reason) }.to_str().unwrap().to_string();
        let evidence = unsafe { CStr::from_ptr(d.evidence) }.to_str().unwrap().to_string();
        assert_eq!(reason, "honeypot");
        assert!(evidence.contains("maze prefix"));
        unsafe { bl_decision_free(d) };
        unsafe { bl_engine_free(e) };
    }

    #[test]
    fn strings_round_trip_and_free() {
        let e = engine_from(BASE_TOML);
        let maze = CString::new("/maze/abc").unwrap();
        let html = unsafe { bl_maze_html(e, maze.as_ptr(), maze.as_bytes().len()) };
        assert!(!html.is_null());
        let text = unsafe { CStr::from_ptr(html) }.to_str().unwrap().to_string();
        assert!(text.contains("noindex"));
        unsafe { bl_string_free(html) };

        let link = unsafe { bl_honeypot_link(e) };
        let link_text = unsafe { CStr::from_ptr(link) }.to_str().unwrap().to_string();
        assert!(link_text.starts_with("/maze/"));
        unsafe { bl_string_free(link) };
        unsafe { bl_engine_free(e) };
    }

    #[test]
    fn challenge_endpoint_reads_next_from_query() {
        let e = engine_from(BASE_TOML);
        let ip = CString::new("203.0.113.5").unwrap();
        let query = "next=/articles/x";
        let page = unsafe {
            bl_challenge_endpoint_html(
                e,
                ip.as_ptr(),
                ip.as_bytes().len(),
                1_700_000_000,
                query.as_ptr() as *const c_char,
                query.len(),
            )
        };
        let text = unsafe { CStr::from_ptr(page) }.to_str().unwrap().to_string();
        assert!(text.contains("var NEXT = \"/articles/x\";"));
        unsafe { bl_string_free(page) };
        unsafe { bl_engine_free(e) };
    }

    #[test]
    fn missing_config_reports_error() {
        let missing = CString::new("/nonexistent/botlocker.toml").unwrap();
        let mut err = [0 as c_char; 128];
        let e = unsafe {
            bl_engine_new(
                missing.as_ptr(),
                SECRET.as_ptr() as *const c_char,
                SECRET.len(),
                err.as_mut_ptr(),
                err.len(),
            )
        };
        assert!(e.is_null());
        let msg = unsafe { CStr::from_ptr(err.as_ptr()) }.to_str().unwrap();
        assert!(msg.contains("cannot read"));
    }
}

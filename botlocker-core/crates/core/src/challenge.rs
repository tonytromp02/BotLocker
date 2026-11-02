//! Signed tokens and the browser challenge page.
//!
//! Two token kinds, both bound to the client IP and domain-separated so one
//! cannot be used as the other:
//! - challenge token: `expires.hex(HMAC(secret, "challenge|ip|expires"))`.
//!   Embedded in the challenge page, valid for a few minutes, and only
//!   accepted by the report endpoint.
//! - pass token: `expires.hex(HMAC(secret, "pass|ip|expires"))`.
//!   Issued only after a browser report passes, and stored as the `bl_pass` cookie.

use std::net::IpAddr;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::PASS_COOKIE;

type HmacSha256 = Hmac<Sha256>;

/// How long a challenge page stays valid before the browser must report.
pub const CHALLENGE_TTL_SECS: u64 = 300;

pub fn keyed_digest(secret: &[u8], data: &str) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(secret).expect("HMAC accepts keys of any length");
    m.update(data.as_bytes());
    m.finalize().into_bytes().into()
}

fn token_mac(secret: &[u8], kind: &str, ip: IpAddr, expires: u64) -> HmacSha256 {
    let mut m = HmacSha256::new_from_slice(secret).expect("HMAC accepts keys of any length");
    m.update(format!("{kind}|{ip}|{expires}").as_bytes());
    m
}

fn issue_kind(secret: &[u8], kind: &str, ip: IpAddr, now: u64, ttl: u64) -> String {
    let expires = now + ttl;
    let sig = hex::encode(token_mac(secret, kind, ip, expires).finalize().into_bytes());
    format!("{expires}.{sig}")
}

fn verify_kind(secret: &[u8], kind: &str, ip: IpAddr, token: &str, now: u64) -> bool {
    let Some((exp, sig)) = token.split_once('.') else {
        return false;
    };
    let Ok(expires) = exp.parse::<u64>() else {
        return false;
    };
    if now >= expires {
        return false;
    }
    let Ok(sig_bytes) = hex::decode(sig) else {
        return false;
    };
    // verify_slice compares in constant time.
    token_mac(secret, kind, ip, expires).verify_slice(&sig_bytes).is_ok()
}

pub fn issue_pass(secret: &[u8], ip: IpAddr, now: u64, ttl: u64) -> String {
    issue_kind(secret, "pass", ip, now, ttl)
}

pub fn verify_pass(secret: &[u8], ip: IpAddr, token: &str, now: u64) -> bool {
    verify_kind(secret, "pass", ip, token, now)
}

pub fn issue_challenge(secret: &[u8], ip: IpAddr, now: u64) -> String {
    issue_kind(secret, "challenge", ip, now, CHALLENGE_TTL_SECS)
}

pub fn verify_challenge(secret: &[u8], ip: IpAddr, token: &str, now: u64) -> bool {
    verify_kind(secret, "challenge", ip, token, now)
}

/// Finds one cookie's value in a `Cookie` header.
pub fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').map(str::trim).find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == name).then_some(v)
    })
}

/// Only same-site relative paths are allowed as redirect targets.
pub fn safe_next(raw: Option<&str>) -> String {
    match raw {
        Some(next)
            if next.starts_with('/')
                && !next.starts_with("//")
                && !next.contains(|c: char| c == '\\' || c == '<' || c == '>' || c.is_control()) =>
        {
            next.to_string()
        }
        _ => "/".to_string(),
    }
}

/// The challenge page. The script collects browser signals, sends them with
/// the challenge token to the report endpoint, and only sets the pass cookie
/// if the server accepts the report.
pub fn page(challenge_token: &str, pass_ttl: u64, next: &str, report_path: &str) -> String {
    let token_js = serde_json::to_string(challenge_token).expect("string serializes");
    let next_js = serde_json::to_string(next).expect("string serializes");
    let report_js = serde_json::to_string(report_path).expect("string serializes");
    format!(
        "<!doctype html>\n<html><head><meta charset=\"utf-8\">\n\
         <meta name=\"robots\" content=\"noindex,nofollow\">\n\
         <title>Checking your browser</title></head>\n\
         <body>\n<noscript>JavaScript is required to continue.</noscript>\n\
         <p id=\"msg\">Checking your browser…</p>\n\
         <script>\n\
         (function () {{\n\
           var TOKEN = {token_js};\n\
           var TTL = {pass_ttl};\n\
           var NEXT = {next_js};\n\
           var REPORT = {report_js};\n\
           var sig = {{\n\
             w: navigator.webdriver ? 1 : 0,\n\
             h: /HeadlessChrome/.test(navigator.userAgent) ? 1 : 0,\n\
             z: (window.outerWidth === 0 && window.outerHeight === 0) ? 1 : 0\n\
           }};\n\
           var url = REPORT + \"?t=\" + encodeURIComponent(TOKEN) +\n\
             \"&w=\" + sig.w + \"&h=\" + sig.h + \"&z=\" + sig.z;\n\
           var msg = document.getElementById(\"msg\");\n\
           fetch(url, {{ credentials: \"same-origin\", cache: \"no-store\" }})\n\
             .then(function (r) {{ return r.json(); }})\n\
             .then(function (v) {{\n\
               if (v.ok && v.token) {{\n\
                 document.cookie = \"{PASS_COOKIE}=\" + v.token + \"; path=/; max-age=\" + TTL + \"; SameSite=Lax\";\n\
                 location.replace(NEXT);\n\
               }} else {{\n\
                 msg.textContent = \"This browser could not be verified.\";\n\
               }}\n\
             }})\n\
             .catch(function () {{ msg.textContent = \"Verification failed. Reload to try again.\"; }});\n\
         }})();\n\
         </script>\n</body></html>\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[test]
    fn issued_pass_verifies_for_same_ip_only() {
        let ip: IpAddr = "198.51.100.4".parse().unwrap();
        let other: IpAddr = "198.51.100.5".parse().unwrap();
        let t = issue_pass(SECRET, ip, 1000, 60);
        assert!(verify_pass(SECRET, ip, &t, 1000));
        assert!(!verify_pass(SECRET, other, &t, 1000));
    }

    #[test]
    fn expired_or_tampered_passes_fail() {
        let ip: IpAddr = "198.51.100.4".parse().unwrap();
        let t = issue_pass(SECRET, ip, 1000, 60);
        assert!(!verify_pass(SECRET, ip, &t, 1060));
        let tampered = t.replacen("1", "2", 1);
        assert!(!verify_pass(SECRET, ip, &tampered, 1000));
        assert!(!verify_pass(b"another-secret-of-length-32-bytes!", ip, &t, 1000));
    }

    #[test]
    fn challenge_and_pass_tokens_are_not_interchangeable() {
        let ip: IpAddr = "198.51.100.4".parse().unwrap();
        let challenge = issue_challenge(SECRET, ip, 1000);
        let pass = issue_pass(SECRET, ip, 1000, 60);
        assert!(verify_challenge(SECRET, ip, &challenge, 1000));
        assert!(!verify_pass(SECRET, ip, &challenge, 1000));
        assert!(!verify_challenge(SECRET, ip, &pass, 1000));
    }

    #[test]
    fn challenge_token_expires() {
        let ip: IpAddr = "198.51.100.4".parse().unwrap();
        let t = issue_challenge(SECRET, ip, 1000);
        assert!(verify_challenge(SECRET, ip, &t, 1000 + CHALLENGE_TTL_SECS - 1));
        assert!(!verify_challenge(SECRET, ip, &t, 1000 + CHALLENGE_TTL_SECS));
    }

    #[test]
    fn cookie_lookup() {
        let h = "a=1; bl_pass=1700000000.abcd; b=2";
        assert_eq!(cookie_value(h, PASS_COOKIE), Some("1700000000.abcd"));
        assert_eq!(cookie_value(h, "missing"), None);
    }

    #[test]
    fn next_must_be_same_site_path() {
        assert_eq!(safe_next(Some("/articles/x?y=1")), "/articles/x?y=1");
        assert_eq!(safe_next(Some("//evil.example")), "/");
        assert_eq!(safe_next(Some("https://evil.example")), "/");
        assert_eq!(safe_next(Some("/<script>")), "/");
        assert_eq!(safe_next(None), "/");
    }

    #[test]
    fn page_embeds_token_and_report_path_as_js_strings() {
        let html = page("1700000300.abcd", 3600, "/a\"b", "/.bl/report");
        assert!(html.contains("var TOKEN = \"1700000300.abcd\";"));
        assert!(html.contains("var REPORT = \"/.bl/report\";"));
        assert!(html.contains("var NEXT = \"/a\\\"b\";"));
        assert!(html.contains("navigator.webdriver"));
    }
}

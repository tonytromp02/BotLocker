//! The browser report: signals sent by the challenge page, checked on the server.
//!
//! The page sends a GET request to `/.bl/report` with its challenge token and
//! three flags, each `0` or `1`:
//! - `w`: `navigator.webdriver` is true (set by WebDriver-based automation, including Playwright)
//! - `h`: the user agent contains `HeadlessChrome`
//! - `z`: the window has zero outer size (typical of headless or hidden windows)
//!
//! Any flag set means the browser is automated. A missing or malformed flag or
//! token is a failure, which gives no pass. A report is only accepted for the
//! IP the challenge was issued to.
//!
//! These signals come from the browser, so a client that doesn't run the page
//! can send the request itself. Stealth tooling can also clear `navigator.webdriver`.
//! The report raises the cost of automation but does not prove a real browser.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::challenge::{issue_pass, verify_challenge};

#[derive(Debug, PartialEq)]
pub enum Verdict {
    /// The browser looks real. Carries a pass token to store as the cookie.
    Pass(String),
    /// At least one automation flag is set. Carries a description of each flag that fired.
    Automated(Vec<String>),
    /// Bad or missing token, or missing flags.
    Fail,
}

pub fn evaluate(secret: &[u8], ip: IpAddr, now: u64, query: &str, pass_ttl: u64) -> Verdict {
    let params: HashMap<&str, &str> = query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .collect();

    let Some(token) = params.get("t") else {
        return Verdict::Fail;
    };
    if !verify_challenge(secret, ip, token, now) {
        return Verdict::Fail;
    }

    match (bit(&params, "w"), bit(&params, "h"), bit(&params, "z")) {
        (Some(w), Some(h), Some(z)) => {
            if w || h || z {
                let mut flags = Vec::new();
                if w {
                    flags.push("navigator.webdriver is true".to_string());
                }
                if h {
                    flags.push("HeadlessChrome user agent".to_string());
                }
                if z {
                    flags.push("zero-size browser window".to_string());
                }
                Verdict::Automated(flags)
            } else {
                Verdict::Pass(issue_pass(secret, ip, now, pass_ttl))
            }
        }
        _ => Verdict::Fail,
    }
}

fn bit(params: &HashMap<&str, &str>, key: &str) -> Option<bool> {
    match *params.get(key)? {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::issue_challenge;

    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
    const NOW: u64 = 1_000;
    const PASS_TTL: u64 = 3600;

    fn ip() -> IpAddr {
        "198.51.100.4".parse().unwrap()
    }

    fn query(token: &str, w: &str, h: &str, z: &str) -> String {
        format!("t={token}&w={w}&h={h}&z={z}")
    }

    #[test]
    fn clean_browser_gets_a_pass() {
        let t = issue_challenge(SECRET, ip(), NOW);
        match evaluate(SECRET, ip(), NOW, &query(&t, "0", "0", "0"), PASS_TTL) {
            Verdict::Pass(token) => assert!(crate::challenge::verify_pass(SECRET, ip(), &token, NOW)),
            other => panic!("expected pass, got {other:?}"),
        }
    }

    #[test]
    fn any_automation_flag_is_automated() {
        let t = issue_challenge(SECRET, ip(), NOW);
        assert!(matches!(evaluate(SECRET, ip(), NOW, &query(&t, "1", "0", "0"), PASS_TTL), Verdict::Automated(_)));
        assert!(matches!(evaluate(SECRET, ip(), NOW, &query(&t, "0", "1", "0"), PASS_TTL), Verdict::Automated(_)));
        assert!(matches!(evaluate(SECRET, ip(), NOW, &query(&t, "0", "0", "1"), PASS_TTL), Verdict::Automated(_)));
    }

    #[test]
    fn missing_or_malformed_flags_fail() {
        let t = issue_challenge(SECRET, ip(), NOW);
        assert_eq!(evaluate(SECRET, ip(), NOW, &format!("t={t}&w=0&h=0"), PASS_TTL), Verdict::Fail);
        assert_eq!(evaluate(SECRET, ip(), NOW, &query(&t, "yes", "0", "0"), PASS_TTL), Verdict::Fail);
        assert_eq!(evaluate(SECRET, ip(), NOW, "", PASS_TTL), Verdict::Fail);
    }

    #[test]
    fn bad_tokens_fail() {
        let forged = "9999999999.deadbeef";
        assert_eq!(evaluate(SECRET, ip(), NOW, &query(forged, "0", "0", "0"), PASS_TTL), Verdict::Fail);

        // A challenge token is not accepted for another IP.
        let t = issue_challenge(SECRET, ip(), NOW);
        let other: IpAddr = "198.51.100.5".parse().unwrap();
        assert_eq!(evaluate(SECRET, other, NOW, &query(&t, "0", "0", "0"), PASS_TTL), Verdict::Fail);
    }

    #[test]
    fn expired_challenge_fails() {
        let t = issue_challenge(SECRET, ip(), NOW);
        let later = NOW + crate::challenge::CHALLENGE_TTL_SECS;
        assert_eq!(evaluate(SECRET, ip(), later, &query(&t, "0", "0", "0"), PASS_TTL), Verdict::Fail);
    }
}

//! Feeds decisions from nginx's access log into the dashboard.
//!
//! The nginx module logs one JSON object per request when `botlocker_json` is
//! enabled (see `nginx/docker/nginx.conf.template`). This module follows that
//! file and records each line in the store. Lines that don't parse are skipped.
//!
//! The log carries the action but not the score or evidence, so events from
//! this feed show a score of 0 and no evidence.

use std::io::SeekFrom;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use botlocker_core::Action;
use serde_json::Value;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};

use crate::dashboard::{Decision, Store};
use crate::unix_now;

/// On first open, read only this much of the existing file, so a long log
/// doesn't flood the dashboard.
const START_BYTES: u64 = 1024 * 1024;
const POLL: Duration = Duration::from_millis(500);

/// Follows `path` forever, recording each new line in `store`. Waits for the
/// file to appear and starts again from the beginning if it is truncated.
pub async fn follow(path: PathBuf, store: Arc<Store>) {
    // `None` until the file is opened for the first time.
    let mut pos: Option<u64> = None;

    loop {
        if let Ok(mut file) = File::open(&path).await {
            let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
            let start = match pos {
                None => len.saturating_sub(START_BYTES),
                Some(p) if p > len => 0, // truncated or replaced
                Some(p) => p,
            };
            pos = Some(start);

            if file.seek(SeekFrom::Start(start)).await.is_ok() {
                let mut reader = BufReader::new(file);
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            // A line without its newline is still being written.
                            // Leave `pos` where it is so the next pass reads it whole.
                            if !line.ends_with('\n') {
                                break;
                            }
                            pos = Some(pos.unwrap_or(0) + n as u64);
                            apply(&store, line.trim_end(), unix_now());
                        }
                    }
                }
            }
        }
        tokio::time::sleep(POLL).await;
    }
}

/// One line of the nginx JSON log, as far as the dashboard needs it.
#[derive(Debug, PartialEq)]
pub struct LogLine {
    pub ip: String,
    pub user_agent: String,
    pub method: String,
    pub path: String,
    pub action: Action,
    pub reason: String,
    pub evidence: Vec<String>,
}

/// Records one log line. Returns `false` if the line was skipped.
pub fn apply(store: &Store, line: &str, now: u64) -> bool {
    let Some(entry) = parse_line(line) else {
        return false;
    };
    store.push(
        now,
        Decision {
            ip: entry.ip,
            user_agent: entry.user_agent,
            method: entry.method,
            path: entry.path,
            action: entry.action,
            reason: entry.reason,
            // The log carries the evidence lines but not the numeric score.
            score: 0.0,
            evidence: entry.evidence,
        },
    );
    true
}

/// Parses one JSON line from the nginx access log.
pub fn parse_line(line: &str) -> Option<LogLine> {
    let v: Value = serde_json::from_str(line).ok()?;
    let action = match v.get("action")?.as_str()? {
        "proxied" => Action::Proxy,
        "challenged" => Action::Challenge,
        "trapped" => Action::Trap,
        _ => return None,
    };
    let ip: IpAddr = v.get("ip")?.as_str()?.parse().ok()?;
    // Evidence lines are joined with "\n" in the log.
    let evidence = str_field(&v, "evidence")
        .split('\n')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    Some(LogLine {
        ip: ip.to_string(),
        user_agent: str_field(&v, "ua"),
        method: str_field(&v, "method"),
        path: str_field(&v, "path"),
        action,
        // Lines written before the reason field existed have none.
        reason: match str_field(&v, "reason") {
            r if r.is_empty() => "unknown".to_string(),
            r => r,
        },
        evidence,
    })
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRAPPED: &str = r#"{"ts":"2026-10-31T10:00:00+00:00","ip":"203.0.113.9","method":"GET","path":"/maze/abc","status":200,"action":"trapped","reason":"honeypot","evidence":"requested a path under the maze prefix","ua":"python-requests/2.31"}"#;

    #[test]
    fn parses_a_trapped_line_with_its_reason() {
        let line = parse_line(TRAPPED).expect("valid line");
        assert_eq!(line.action, Action::Trap);
        assert_eq!(line.path, "/maze/abc");
        assert_eq!(line.ip, "203.0.113.9");
        assert_eq!(line.user_agent, "python-requests/2.31");
        assert_eq!(line.reason, "honeypot");
        assert_eq!(line.evidence, vec!["requested a path under the maze prefix".to_string()]);
    }

    #[test]
    fn splits_evidence_lines() {
        let l = r#"{"ip":"203.0.113.9","action":"trapped","reason":"scored","evidence":"score 7.5 (threshold 6.0, 3 signal families)\nclient.bot_ua: matches python-requests\nbehavior.rate: 130 requests"}"#;
        let line = parse_line(l).expect("valid line");
        assert_eq!(line.evidence.len(), 3);
        assert!(line.evidence[0].starts_with("score 7.5"));
    }

    #[test]
    fn skips_unknown_actions_bad_ips_and_garbage() {
        assert!(parse_line(r#"{"ip":"203.0.113.9","action":"mystery"}"#).is_none());
        assert!(parse_line(r#"{"ip":"not-an-ip","action":"proxied"}"#).is_none());
        assert!(parse_line("not json at all").is_none());
        assert!(parse_line("").is_none());
    }

    #[test]
    fn applied_lines_show_up_in_the_summary_and_the_captured_reason() {
        let store = Store::default();
        assert!(apply(&store, TRAPPED, 1_000));
        assert!(!apply(&store, "garbage", 1_000));
        let s = store.summary(1_000);
        assert_eq!(s["requests"], 1);
        assert_eq!(s["trapped"], 1);
        assert_eq!(s["captured"], 1);

        let clients = store.clients(1_000);
        assert_eq!(clients[0]["captured_because"], "honeypot");
        assert_eq!(clients[0]["trap_reasons"]["honeypot"], 1);
    }
}

//! Reloads the proxy when its config file changes.
//!
//! Polls the file's modification time. On a change, it parses the file and
//! rebuilds the engine, keeping the behaviour counters and flagged browsers. An
//! invalid file is logged and ignored, and the running config stays in place.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::settings::{apply_origin, read_config};
use crate::EngineSlot;

const POLL: Duration = Duration::from_secs(2);

fn mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Checks the file once. Returns `Ok(true)` if the engine was replaced.
///
/// `last` is the modification time last seen. It is updated before parsing, so
/// a broken file is reported once, not on every poll.
pub fn try_reload(
    path: &Path,
    origin_override: Option<&str>,
    slot: &EngineSlot,
    last: &mut Option<SystemTime>,
) -> Result<bool, String> {
    let Some(now) = mtime(path) else {
        return Ok(false);
    };
    if Some(now) == *last {
        return Ok(false);
    }
    *last = Some(now);

    let mut cfg = read_config(path)?;
    apply_origin(&mut cfg, origin_override)?;
    let next = slot.get().reconfigure(cfg).map_err(|e| e.to_string())?;
    slot.set(next);
    Ok(true)
}

/// Runs forever, reloading when the file changes. Start it after the proxy is up.
pub async fn watch(path: PathBuf, origin_override: Option<String>, slot: Arc<EngineSlot>) {
    // The caller has just loaded this file, so start from its current version.
    let mut last = mtime(&path);
    loop {
        tokio::time::sleep(POLL).await;
        match try_reload(&path, origin_override.as_deref(), &slot, &mut last) {
            Ok(true) => tracing::info!(config = %path.display(), "config reloaded"),
            Ok(false) => {}
            Err(e) => tracing::warn!(config = %path.display(), error = %e, "config change rejected; keeping the running config"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use botlocker_core::Engine;

    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn write(path: &Path, text: &str) {
        std::fs::write(path, text).unwrap();
        // Make sure the next write gets a different modification time.
        std::thread::sleep(Duration::from_millis(20));
    }

    #[test]
    fn applies_valid_changes_and_ignores_invalid_ones() {
        let dir = std::env::temp_dir().join(format!("bl-watch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("botlocker.toml");
        write(&path, "origin = \"https://origin.example\"\nmaze_prefix = \"/maze/\"\n");

        let cfg = read_config(&path).unwrap();
        let slot = EngineSlot::new(Engine::new(cfg, SECRET.to_vec()).unwrap());
        let mut last = mtime(&path);

        write(&path, "origin = \"https://origin.example\"\nmaze_prefix = \"/maze/\"\nchallenge_at = 4.5\n");
        assert_eq!(try_reload(&path, None, &slot, &mut last), Ok(true));
        assert_eq!(slot.get().config().challenge_at, 4.5);

        // Unchanged file: nothing to do.
        assert_eq!(try_reload(&path, None, &slot, &mut last), Ok(false));

        // Invalid file: rejected, running config kept.
        write(&path, "origin = \"https://origin.example\"\nmaze_prefix = \"/maze/\"\nchallenge_at = 9.0\ntrap_at = 1.0\n");
        assert!(try_reload(&path, None, &slot, &mut last).is_err());
        assert_eq!(slot.get().config().challenge_at, 4.5);
        // Reported once: the next poll sees the same broken version.
        assert_eq!(try_reload(&path, None, &slot, &mut last), Ok(false));
    }

    #[test]
    fn origin_flag_fills_in_for_a_file_without_one() {
        let dir = std::env::temp_dir().join(format!("bl-origin-flag-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("botlocker.toml");
        write(&path, "maze_prefix = \"/maze/\"\n");

        let mut cfg = read_config(&path).unwrap();
        crate::settings::apply_origin(&mut cfg, Some("https://flag.example/")).unwrap();
        assert_eq!(cfg.origin.as_deref(), Some("https://flag.example"));
        let slot = EngineSlot::new(Engine::new(cfg, SECRET.to_vec()).unwrap());
        let mut last = mtime(&path);

        // A reload of the same file keeps the flag's origin.
        write(&path, "maze_prefix = \"/maze/\"\nchallenge_at = 4.5\n");
        assert_eq!(try_reload(&path, Some("https://flag.example"), &slot, &mut last), Ok(true));
        assert_eq!(slot.get().config().origin.as_deref(), Some("https://flag.example"));
    }
}

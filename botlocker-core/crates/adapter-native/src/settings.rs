//! Settings: read and write the config file from the dashboard.
//!
//! A save is validated with the core config rules, written to a temp file, and
//! renamed over the config, so the proxy never sees a half-written file. The
//! running proxy picks the change up within a few seconds (see `config_watch`).

use std::fs;
use std::path::{Path, PathBuf};

use botlocker_core::Config;
use serde_json::{json, Value};

/// What the settings endpoints need: where the config lives.
/// Writes are protected by the API key on every `/api` route.
pub struct SettingsCtx {
    pub path: PathBuf,
}

/// Reads and validates the config file.
pub fn read_config(path: &Path) -> Result<Config, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Config::from_toml(&text).map_err(|e| e.to_string())
}

/// The standalone proxy needs an origin to forward to. Checked at startup and on
/// every reload, so a change that removes it is rejected and the running config stays.
pub fn require_origin(cfg: &Config) -> Result<(), String> {
    match &cfg.origin {
        Some(_) => Ok(()),
        None => Err("origin must be set for the standalone proxy (the nginx build uses ORIGIN_URL instead)".into()),
    }
}

/// Applies the `--origin` command-line value, which overrides the file, then checks the origin.
/// Run it on every config load, since a reload re-reads the file and would otherwise drop the override.
pub fn apply_origin(cfg: &mut Config, origin_override: Option<&str>) -> Result<(), String> {
    if let Some(origin) = origin_override {
        cfg.origin = Some(origin.trim_end_matches('/').to_string());
        cfg.validate().map_err(|e| format!("--origin: {e}"))?;
    }
    require_origin(cfg)
}

/// Validates a config from the dashboard. The same rules as the config file.
pub fn parse_update(body: Value) -> Result<Config, String> {
    let mut cfg: Config = serde_json::from_value(body).map_err(|e| e.to_string())?;
    cfg.bad_user_agents = cfg.bad_user_agents.iter().map(|s| s.to_ascii_lowercase()).collect();
    cfg.validate().map_err(|e| e.to_string())?;
    Ok(cfg)
}

/// Writes the config atomically: temp file in the same directory, then rename.
pub fn write_config(path: &Path, cfg: &Config) -> Result<(), String> {
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("bad config path {}", path.display()))?;
    let tmp = path.with_file_name(format!(".{}.tmp", file_name.to_string_lossy()));
    fs::write(&tmp, cfg.to_toml()).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("cannot replace {}: {e}", path.display()))
}

/// Name of the trigger file, next to the config. A dashboard save touches it so
/// the proxy checks the config at once instead of waiting for its next poll.
pub const RELOAD_TRIGGER: &str = ".reload-now";

/// Touches the reload trigger beside the config. The proxy reads its mtime, not its contents.
pub fn request_reload(config_path: &Path) -> Result<(), String> {
    let dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let trigger = dir.join(RELOAD_TRIGGER);
    fs::write(&trigger, b"").map_err(|e| format!("cannot touch {}: {e}", trigger.display()))
}

/// Top-level keys whose values differ, as `(key, old, new)`.
pub fn diff(old: &Value, new: &Value) -> Vec<(String, Value, Value)> {
    let (Some(old), Some(new)) = (old.as_object(), new.as_object()) else {
        return Vec::new();
    };
    let mut keys: Vec<&String> = old.keys().chain(new.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter_map(|k| {
            let before = old.get(k).cloned().unwrap_or(Value::Null);
            let after = new.get(k).cloned().unwrap_or(Value::Null);
            (before != after).then(|| (k.clone(), before, after))
        })
        .collect()
}

/// The config as JSON, for the settings form.
pub fn to_json(cfg: &Config) -> Value {
    json!(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "origin = \"https://origin.example\"\nmaze_prefix = \"/maze/\"\n";

    #[test]
    fn diff_lists_only_changed_keys() {
        let old = json!({"challenge_at": 3.0, "kill_switch": false});
        let new = json!({"challenge_at": 4.0, "kill_switch": false});
        let d = diff(&old, &new);
        assert_eq!(d, vec![("challenge_at".to_string(), json!(3.0), json!(4.0))]);
    }

    #[test]
    fn parse_update_validates_like_the_file() {
        let cfg = Config::from_toml(BASE).unwrap();
        let mut body = to_json(&cfg);
        body["trap_at"] = json!(2.0); // not above challenge_at
        assert!(parse_update(body).is_err());
    }

    #[test]
    fn write_then_read_round_trips() {
        let dir = std::env::temp_dir().join(format!("bl-settings-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("botlocker.toml");
        let mut cfg = Config::from_toml(BASE).unwrap();
        cfg.challenge_at = 4.5;
        write_config(&path, &cfg).unwrap();
        let back = read_config(&path).unwrap();
        assert_eq!(back.challenge_at, 4.5);
        assert_eq!(back.maze_prefix, "/maze/");
        assert!(!dir.join(".botlocker.toml.tmp").exists());
    }
}

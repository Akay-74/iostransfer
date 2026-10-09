//! Settings the double-click mode remembers between runs (`app.json` in the config dir).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use iost_receiver::identity::write_owner_only;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct AppState {
    /// Where received photos go.
    pub dest: Option<PathBuf>,
    /// Apple ID used to sign the iPhone app (the password lives in the OS keyring).
    pub apple_id: Option<String>,
    /// Firewall already set up (Linux ufw, which can't be checked without root).
    #[serde(default)]
    pub firewall_done: bool,
    /// iPhones this PC installed the app on, by UDID.
    #[serde(default)]
    pub phones: BTreeMap<String, Phone>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Phone {
    pub name: String,
    /// Unix time the app was last signed; free Apple IDs sign for 7 days.
    pub signed_at: u64,
    /// Last address the phone answered on over Wi‑Fi.
    pub ip: Option<String>,
}

impl AppState {
    pub fn load(config: &Path) -> AppState {
        std::fs::read(config.join("app.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    pub fn save(&self, config: &Path) -> Result<()> {
        write_atomic(&config.join("app.json"), &serde_json::to_vec_pretty(self)?)
    }
}

/// Owner-only write that replaces the file in one step.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    write_owner_only(&tmp, data).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// UDIDs are hex with an optional dash; anything else never becomes a file name.
pub fn safe_udid(udid: &str) -> Option<&str> {
    (!udid.is_empty() && udid.len() <= 64 && udid.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')).then_some(udid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udid_filter() {
        assert_eq!(safe_udid("00008110-001A2B3C4D5E801E"), Some("00008110-001A2B3C4D5E801E"));
        assert_eq!(safe_udid("../etc"), None);
        assert_eq!(safe_udid(""), None);
    }

    #[test]
    fn roundtrip() {
        let dir = std::env::temp_dir().join(format!("iost-state-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut s = AppState::load(&dir);
        assert!(s.dest.is_none());
        s.dest = Some("/x".into());
        s.phones.insert("u".into(), Phone { name: "n".into(), signed_at: 5, ip: None });
        s.save(&dir).unwrap();
        s.save(&dir).unwrap(); // replacing works
        let t = AppState::load(&dir);
        assert_eq!(t.dest, Some(PathBuf::from("/x")));
        assert_eq!(t.phones["u"].signed_at, 5);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

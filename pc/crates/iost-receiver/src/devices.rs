//! Paired devices, stored in the per-user config dir next to the TLS key, never in the
//! destination (THREAT_MODEL N16a: the raw secret is needed for HMAC).

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

pub struct DeviceDb {
    conn: Connection,
}

pub struct Device {
    pub device_id: String,
    pub name: String,
    pub secret: [u8; 32],
}

impl DeviceDb {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        Self::init(Connection::open(path)?)
    }

    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> rusqlite::Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS devices (
                 device_id TEXT PRIMARY KEY,
                 name      TEXT NOT NULL,
                 secret    BLOB NOT NULL,
                 paired_at INTEGER NOT NULL
             );",
        )?;
        Ok(DeviceDb { conn })
    }

    pub fn get(&self, device_id: &str) -> rusqlite::Result<Option<Device>> {
        let row: Option<(String, String, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT device_id, name, secret FROM devices WHERE device_id = ?1",
                params![device_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        Ok(row.and_then(|(device_id, name, secret)| {
            Some(Device { device_id, name, secret: secret.try_into().ok()? })
        }))
    }

    /// Insert or replace (re-pairing replaces the secret, PROTOCOL §4.1).
    pub fn put(&self, device_id: &str, name: &str, secret: &[u8; 32], now_ms: i64) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO devices(device_id, name, secret, paired_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(device_id) DO UPDATE SET name = ?2, secret = ?3, paired_at = ?4",
            params![device_id, name, secret.as_slice(), now_ms],
        )?;
        Ok(())
    }

    pub fn list(&self) -> rusqlite::Result<Vec<(String, String, i64)>> {
        let mut st = self.conn.prepare("SELECT device_id, name, paired_at FROM devices ORDER BY paired_at")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        rows.collect()
    }

    /// `devices revoke` (THREAT_MODEL N15). Returns whether a device was removed.
    pub fn revoke(&self, device_id: &str) -> rusqlite::Result<bool> {
        Ok(self.conn.execute("DELETE FROM devices WHERE device_id = ?1", params![device_id])? > 0)
    }
}

//! The index next to the received files: `<dest>/.iostransfer/index.db` (ARCHITECTURE §4.4).
//! Holds no secrets: the destination may be an exFAT drive or a NAS share.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

pub struct Index {
    conn: Connection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResState {
    Partial,
    Verified,
    Done,
    Orphaned,
}

impl ResState {
    fn as_str(self) -> &'static str {
        match self {
            ResState::Partial => "partial",
            ResState::Verified => "verified",
            ResState::Done => "done",
            ResState::Orphaned => "orphaned",
        }
    }
    fn parse(s: &str) -> Self {
        match s {
            "verified" => ResState::Verified,
            "done" => ResState::Done,
            "orphaned" => ResState::Orphaned,
            _ => ResState::Partial,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AssetRow {
    pub base_rel: String,
    pub modified_ms: Option<i64>,
    pub meta_json: Option<String>,
    /// Which meta the durable `<base>.xmp` holds, if one was written.
    pub xmp_meta_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResRow {
    pub device_id: String,
    pub asset_id: String,
    pub key: String,
    pub ty: String,
    pub rel_path: String,
    pub size: u64,
    pub durable_offset: u64,
    pub sha256: Option<Vec<u8>>,
    pub state: ResState,
}

const RES_COLS: &str = "device_id, asset_id, res_key, type, rel_path, size, durable_offset, sha256, state";

fn res_row(r: &rusqlite::Row) -> rusqlite::Result<ResRow> {
    Ok(ResRow {
        device_id: r.get(0)?,
        asset_id: r.get(1)?,
        key: r.get(2)?,
        ty: r.get(3)?,
        rel_path: r.get(4)?,
        size: r.get::<_, i64>(5)? as u64,
        durable_offset: r.get::<_, i64>(6)? as u64,
        sha256: r.get(7)?,
        state: ResState::parse(&r.get::<_, String>(8)?),
    })
}

impl Index {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        Self::init(Connection::open(path)?)
    }

    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> rusqlite::Result<Self> {
        // EXCLUSIVE before WAL: the WAL index lives in heap memory instead of a -shm file, which
        // makes WAL safe on SMB/NFS destinations and allows exactly one receiver per destination.
        conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
        // Fail fast instead of rusqlite's default 5 s wait when another receiver holds the lock.
        conn.busy_timeout(std::time::Duration::ZERO)?;
        // WAL commits are only durable with synchronous=FULL (PROTOCOL §9.1).
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS assets (
                 device_id   TEXT NOT NULL,
                 asset_id    TEXT NOT NULL,
                 kind        TEXT NOT NULL,
                 base_rel    TEXT NOT NULL,
                 base_lc     TEXT NOT NULL,
                 modified_ms INTEGER,
                 meta_json   TEXT,
                 xmp_meta_hash TEXT,
                 PRIMARY KEY (device_id, asset_id)
             );
             CREATE INDEX IF NOT EXISTS assets_base_lc ON assets(base_lc);
             CREATE TABLE IF NOT EXISTS resources (
                 device_id      TEXT NOT NULL,
                 asset_id       TEXT NOT NULL,
                 res_key        TEXT NOT NULL,
                 type           TEXT NOT NULL,
                 rel_path       TEXT NOT NULL,
                 size           INTEGER NOT NULL,
                 durable_offset INTEGER NOT NULL,
                 sha256         BLOB,
                 state          TEXT NOT NULL CHECK (state IN ('partial','verified','done','orphaned')),
                 PRIMARY KEY (device_id, asset_id, res_key)
             );",
        )?;
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('store_id', ?1)",
            params![uuid::Uuid::new_v4().to_string()],
        )?;
        Ok(Index { conn })
    }

    pub fn store_id(&self) -> rusqlite::Result<String> {
        self.conn.query_row("SELECT value FROM meta WHERE key = 'store_id'", [], |r| r.get(0))
    }

    pub fn asset(&self, dev: &str, id: &str) -> rusqlite::Result<Option<AssetRow>> {
        self.conn
            .query_row(
                "SELECT base_rel, modified_ms, meta_json, xmp_meta_hash FROM assets WHERE device_id = ?1 AND asset_id = ?2",
                params![dev, id],
                |r| Ok(AssetRow { base_rel: r.get(0)?, modified_ms: r.get(1)?, meta_json: r.get(2)?, xmp_meta_hash: r.get(3)? }),
            )
            .optional()
    }

    /// Allocate `dir/base`, `dir/base_2`, … once per asset (N7). `taken_on_disk` reports whether
    /// a candidate collides with files already in the directory. Committed before any `.part` exists.
    pub fn allocate_base(
        &mut self,
        dev: &str,
        id: &str,
        kind: &str,
        dir: &str,
        base: &str,
        taken_on_disk: impl Fn(&str) -> bool,
    ) -> rusqlite::Result<String> {
        let tx = self.conn.transaction()?;
        let mut n = 1u32;
        let chosen = loop {
            let name = if n == 1 { base.to_string() } else { format!("{base}_{n}") };
            let rel = format!("{dir}/{name}");
            let lc = rel.to_lowercase();
            let in_db: bool =
                tx.query_row("SELECT EXISTS(SELECT 1 FROM assets WHERE base_lc = ?1)", params![lc], |r| r.get(0))?;
            if !in_db && !taken_on_disk(&name) {
                break rel;
            }
            n += 1;
        };
        tx.execute(
            "INSERT INTO assets(device_id, asset_id, kind, base_rel, base_lc) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![dev, id, kind, chosen, chosen.to_lowercase()],
        )?;
        tx.commit()?;
        Ok(chosen)
    }

    pub fn set_asset_acked(&self, dev: &str, id: &str, modified_ms: i64, meta_json: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE assets SET modified_ms = ?3, meta_json = ?4 WHERE device_id = ?1 AND asset_id = ?2",
            params![dev, id, modified_ms, meta_json],
        )?;
        Ok(())
    }

    pub fn set_meta(&self, dev: &str, id: &str, meta_json: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE assets SET meta_json = ?3 WHERE device_id = ?1 AND asset_id = ?2",
            params![dev, id, meta_json],
        )?;
        Ok(())
    }

    pub fn set_xmp_hash(&self, dev: &str, id: &str, hash: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE assets SET xmp_meta_hash = ?3 WHERE device_id = ?1 AND asset_id = ?2",
            params![dev, id, hash],
        )?;
        Ok(())
    }

    pub fn resources(&self, dev: &str, id: &str) -> rusqlite::Result<Vec<ResRow>> {
        let mut st = self.conn.prepare_cached(&format!(
            "SELECT {RES_COLS} FROM resources WHERE device_id = ?1 AND asset_id = ?2 ORDER BY res_key"
        ))?;
        let rows = st.query_map(params![dev, id], res_row)?;
        rows.collect()
    }

    pub fn resource(&self, dev: &str, id: &str, key: &str) -> rusqlite::Result<Option<ResRow>> {
        self.conn
            .query_row(
                &format!("SELECT {RES_COLS} FROM resources WHERE device_id = ?1 AND asset_id = ?2 AND res_key = ?3"),
                params![dev, id, key],
                res_row,
            )
            .optional()
    }

    /// Rows that startup recovery must look at.
    pub fn unfinished(&self) -> rusqlite::Result<Vec<ResRow>> {
        let mut st =
            self.conn.prepare(&format!("SELECT {RES_COLS} FROM resources WHERE state IN ('partial','verified')"))?;
        let rows = st.query_map([], res_row)?;
        rows.collect()
    }

    /// Insert or reset a row to `partial` at RES_BEGIN. `rel_path` is kept if the row exists.
    pub fn begin_resource(&self, row: &ResRow) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO resources(device_id, asset_id, res_key, type, rel_path, size, durable_offset, sha256, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, 'partial')
             ON CONFLICT(device_id, asset_id, res_key) DO UPDATE SET
                 type = ?4, size = ?6, durable_offset = ?7, sha256 = NULL, state = 'partial'",
            params![row.device_id, row.asset_id, row.key, row.ty, row.rel_path, row.size as i64, row.durable_offset as i64],
        )?;
        Ok(())
    }

    pub fn set_durable(&self, dev: &str, id: &str, key: &str, offset: u64) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE resources SET durable_offset = ?4 WHERE device_id = ?1 AND asset_id = ?2 AND res_key = ?3",
            params![dev, id, key, offset as i64],
        )?;
        Ok(())
    }

    pub fn set_verified(&self, dev: &str, id: &str, key: &str, size: u64, sha: &[u8]) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE resources SET state = 'verified', durable_offset = ?4, size = ?4, sha256 = ?5
             WHERE device_id = ?1 AND asset_id = ?2 AND res_key = ?3",
            params![dev, id, key, size as i64, sha],
        )?;
        Ok(())
    }

    pub fn set_state(&self, dev: &str, id: &str, key: &str, state: ResState) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE resources SET state = ?4 WHERE device_id = ?1 AND asset_id = ?2 AND res_key = ?3",
            params![dev, id, key, state.as_str()],
        )?;
        Ok(())
    }

    /// Back to `partial` at offset 0 (NACK, damaged or missing final). `rel_path` is kept.
    pub fn reset_resource(&self, dev: &str, id: &str, key: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE resources SET state = 'partial', durable_offset = 0, sha256 = NULL
             WHERE device_id = ?1 AND asset_id = ?2 AND res_key = ?3",
            params![dev, id, key],
        )?;
        Ok(())
    }

    pub fn delete_resource(&self, dev: &str, id: &str, key: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "DELETE FROM resources WHERE device_id = ?1 AND asset_id = ?2 AND res_key = ?3",
            params![dev, id, key],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_receiver_per_destination_and_no_shm_file() {
        let dir = std::env::temp_dir().join(format!("iost-index-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("index.db");
        let first = Index::open(&path).unwrap();
        let id = first.store_id().unwrap();
        let second = Index::open(&path);
        assert!(second.is_err(), "a second receiver on the same dest must fail fast");
        assert!(!dir.join("index.db-shm").exists(), "EXCLUSIVE keeps the WAL index in memory");
        drop(first);
        assert_eq!(Index::open(&path).unwrap().store_id().unwrap(), id, "store_id is stable");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn base_allocation_is_case_insensitive_and_skips_disk_files() {
        let mut ix = Index::open_in_memory().unwrap();
        let a = ix.allocate_base("d", "A", "photo", "D/Photos/2024/03", "x_IMG_0001", |_| false).unwrap();
        assert_eq!(a, "D/Photos/2024/03/x_IMG_0001");
        let b = ix.allocate_base("d", "B", "photo", "D/Photos/2024/03", "x_img_0001", |_| false).unwrap();
        assert_eq!(b, "D/Photos/2024/03/x_img_0001_2");
        let c = ix.allocate_base("d", "C", "photo", "D/Photos/2024/03", "y", |n| n == "y").unwrap();
        assert_eq!(c, "D/Photos/2024/03/y_2");
    }
}

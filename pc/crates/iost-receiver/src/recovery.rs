//! Startup recovery (PROTOCOL §10 P1–P4, WRITER_TESTS §3). Runs before the listener accepts.
//! Idempotent: running it again on its own result changes nothing (invariant I-E).

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use tracing::{info, warn};

use crate::crash;
use crate::fsio::{self, resolve};
use crate::index::{Index, ResRow, ResState};
use crate::naming::part_name;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub truncated: u32,
    pub finished: u32,
    pub reset: u32,
    pub stray_parts_removed: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
}

pub fn paths(dest: &Path, row: &ResRow) -> io::Result<(PathBuf, PathBuf)> {
    let fin = resolve(dest, &row.rel_path)?;
    let name = fin.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
    Ok((fin.with_file_name(part_name(&name)), fin))
}

fn len_of(p: &Path) -> Option<u64> {
    fs::symlink_metadata(p).ok().filter(|m| m.is_file()).map(|m| m.len())
}

pub fn recover(index: &Index, dest: &Path) -> Result<Report, RecoveryError> {
    let mut rep = Report::default();
    let mut live_parts = HashSet::new();
    for row in index.unfinished()? {
        let (part, fin) = paths(dest, &row)?;
        let (dev, id, key) = (&row.device_id, &row.asset_id, &row.key);
        match row.state {
            ResState::Partial => {
                live_parts.insert(part.clone());
                match len_of(&part) {
                    // Bytes past the last checkpoint may be garbage after a power loss (P1, P2).
                    Some(len) if len > row.durable_offset => {
                        let f = fsio::open_part(&part)?;
                        f.set_len(row.durable_offset)?;
                        f.sync_all()?;
                        rep.truncated += 1;
                    }
                    Some(len) if len == row.durable_offset => {}
                    _ => {
                        // Shorter than the checkpoint, or gone: the prefix can't be trusted.
                        fsio::remove_if_exists(&part)?;
                        if row.durable_offset != 0 {
                            index.reset_resource(dev, id, key)?;
                            rep.reset += 1;
                        }
                    }
                }
            }
            ResState::Verified => {
                if len_of(&part) == Some(row.size) {
                    // P3: hash-verified and fsynced; finish the rename.
                    fsio::rename_replace(&part, &fin)?;
                    crash::at("R1", key);
                    fsio::fsync_dir(fin.parent().unwrap_or(dest))?;
                    index.set_state(dev, id, key, ResState::Done)?;
                    rep.finished += 1;
                } else if len_of(&part).is_none() && len_of(&fin) == Some(row.size) {
                    // P4 (or R1): already renamed.
                    fsio::fsync_dir(fin.parent().unwrap_or(dest))?;
                    index.set_state(dev, id, key, ResState::Done)?;
                    rep.finished += 1;
                } else {
                    // P4b: the final is damaged or missing. Never delete it; the next transfer
                    // atomically replaces it.
                    fsio::remove_if_exists(&part)?;
                    index.reset_resource(dev, id, key)?;
                    rep.reset += 1;
                }
            }
            ResState::Done | ResState::Orphaned => {}
        }
    }
    sweep_stray_parts(dest, &live_parts, &mut rep)?;
    if rep != Report::default() {
        info!(?rep, "startup recovery");
    }
    Ok(rep)
}

/// Delete `.<name>.part` files that no partial row owns (WRITER_TESTS OR). Never follows
/// symlinks, skips `.iostransfer`, and touches nothing but dot-prefixed `.part` files.
fn sweep_stray_parts(dest: &Path, live: &HashSet<PathBuf>, rep: &mut Report) -> io::Result<()> {
    let mut stack = vec![dest.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                warn!("recovery: can't read {}: {e}", dir.display());
                continue;
            }
        };
        for entry in entries {
            let entry = entry?;
            let ft = entry.file_type()?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if ft.is_dir() {
                if !(dir == dest && name == ".iostransfer") {
                    stack.push(path);
                }
            } else if ft.is_file() && name.starts_with('.') && name.ends_with(".xmp.tmp") {
                // X1: a sidecar that never got renamed; the asset's xmp_meta_hash wasn't updated either.
                fs::remove_file(&path)?;
                rep.stray_parts_removed += 1;
            } else if ft.is_file() && name.starts_with('.') && name.ends_with(".part") && !live.contains(&path) {
                fs::remove_file(&path)?;
                rep.stray_parts_removed += 1;
            }
        }
    }
    Ok(())
}

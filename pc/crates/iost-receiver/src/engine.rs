//! The ready phase of one session (PROTOCOL §6, §9): NEED computation and the durable write path.
//!
//! Runs on its own blocking thread, fed through a bounded queue: when the disk is slow the queue
//! fills, the session stops reading the socket, and TCP backpressure slows the phone down.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use iost_proto::msg::{
    is_original_family, Ack, Asset, AssetEnd, BadAsset, Bye, FailedKey, Job, Manifest, Need, NeedMore, Pause, ResAbort,
    ResBegin, ResEnd, ResNack, ResOffset, Resume, Verified, Verify, Want, MAX_VERIFY_ASSETS,
};
use iost_proto::{DataChunk, Frame, FrameType};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::handshake::Ctx;
use crate::index::{ResRow, ResState};
use crate::xmp::{self, Meta};
use crate::{crash, fsio, lock, naming};

/// PROTOCOL §6.1.
const MAX_PAGE_ASSETS: usize = 500;
const WRITE_BUFFER: usize = 1 << 20;

/// Input from the session task.
pub enum In {
    Frame(Frame),
    /// Periodic wake-up (free-space re-check while PAUSEd for disk_low).
    Tick,
}

/// What the engine asks the session task to do.
pub enum Out {
    Frame(Frame),
    /// Close the connection after the frames already queued.
    Close,
}

#[derive(Debug, thiserror::Error)]
pub enum Fatal {
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
}

fn protocol<T>(msg: impl Into<String>) -> Result<T, Fatal> {
    Err(Fatal::Protocol(msg.into()))
}

struct Writer {
    id: String,
    key: String,
    size: u64,
    written: u64,
    durable: u64,
    file: BufWriter<File>,
    hasher: Sha256,
    part: PathBuf,
    fin: PathBuf,
}

enum Slot {
    Active(Box<Writer>),
    /// After a NACK: further DATA for this slot is dropped until the next RES_BEGIN.
    Discarding,
}

struct Wanted {
    asset: Asset,
    /// Keys the phone may send, with the offset NEED/NEED_MORE gave.
    keys: HashMap<String, u64>,
    /// Edit-family keys answered as provisional `have` (NEED_MORE candidates).
    provisional: Vec<String>,
    /// The adjustment_data hash we held before this job (to detect a real edit).
    prev_adjustment_sha: Option<Vec<u8>>,
    /// Keys requested by NEED_MORE and not yet done: no ACK until they are.
    more_pending: HashSet<String>,
    acked: bool,
}

struct JobState {
    job: Job,
    /// Move jobs (and `--xmp`) keep an XMP sidecar per asset.
    xmp: bool,
    next_page: u32,
    seen: HashSet<String>,
    wanted: HashMap<String, Wanted>,
}

pub struct Engine {
    ctx: Arc<Ctx>,
    dev: String,
    dev_name: String,
    out: mpsc::UnboundedSender<Out>,
    job: Option<JobState>,
    slots: HashMap<u16, Slot>,
    attempts: HashMap<(String, String), u32>,
    /// Bytes we couldn't accept for lack of space; Some while PAUSEd{disk_low}.
    disk_paused: Option<u64>,
    slow_writer_done: bool,
}

struct NeedResult {
    want: Vec<ResOffset>,
    provisional: Vec<String>,
    prev_adjustment_sha: Option<Vec<u8>>,
}

fn parse<T: DeserializeOwned>(f: &Frame) -> Result<T, Fatal> {
    serde_json::from_slice(&f.payload).map_err(|e| Fatal::Protocol(format!("{:?}: {e}", f.ty)))
}

fn len_of(p: &Path) -> Option<u64> {
    fs::symlink_metadata(p).ok().filter(|m| m.is_file()).map(|m| m.len())
}

fn meta_json(a: &Asset) -> String {
    Meta::of(a).to_json()
}

/// Lower-case names in `dir`, for case-insensitive collision checks (NTFS, exFAT).
fn names_in(dir: &Path) -> HashSet<String> {
    fs::read_dir(dir)
        .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().to_lowercase()).collect())
        .unwrap_or_default()
}

impl Engine {
    pub fn new(ctx: Arc<Ctx>, dev: String, dev_name: String, out: mpsc::UnboundedSender<Out>) -> Self {
        Engine {
            ctx,
            dev,
            dev_name,
            out,
            job: None,
            slots: HashMap::new(),
            attempts: HashMap::new(),
            disk_paused: None,
            slow_writer_done: false,
        }
    }

    /// Process frames until the queue closes or a fatal error, then make every open `.part`
    /// durable at its exact length.
    pub fn run(mut self, mut rx: mpsc::Receiver<In>) {
        while let Some(input) = rx.blocking_recv() {
            let result = match input {
                In::Frame(f) => self.handle(f),
                In::Tick => {
                    self.tick();
                    Ok(())
                }
            };
            if let Err(e) = result {
                let code = if matches!(e, Fatal::Protocol(_)) { "protocol_error" } else { "shutting_down" };
                warn!(device = %self.dev_name, "{e}");
                self.send(FrameType::Bye, &Bye { msg: Some(e.to_string()), ..Bye::code(code) });
                let _ = self.out.send(Out::Close);
                break;
            }
        }
        self.shutdown();
    }

    fn shutdown(&mut self) {
        for (_, slot) in self.slots.drain() {
            if let Slot::Active(mut w) = slot {
                let r = w.file.flush().and_then(|_| w.file.get_ref().sync_all());
                match r {
                    Ok(()) => {
                        if let Err(e) = lock(&self.ctx.index).set_durable(&self.dev, &w.id, &w.key, w.written) {
                            warn!("committing offset at session end: {e}");
                        }
                    }
                    Err(e) => warn!("syncing {} at session end: {e}", w.part.display()),
                }
            }
        }
        info!(device = %self.dev_name, "session closed");
    }

    fn send<T: serde::Serialize>(&self, ty: FrameType, msg: &T) {
        let _ = self.out.send(Out::Frame(Frame::json(ty, msg)));
    }

    fn handle(&mut self, f: Frame) -> Result<(), Fatal> {
        match f.ty {
            FrameType::Manifest => self.manifest(parse(&f)?),
            FrameType::ResBegin => self.res_begin(parse(&f)?),
            FrameType::Data => {
                let chunk = f.as_data().map_err(|e| Fatal::Protocol(e.to_string()))?;
                self.data(chunk)
            }
            FrameType::ResEnd => self.res_end(parse(&f)?),
            FrameType::ResAbort => self.res_abort(parse(&f)?),
            FrameType::AssetEnd => self.asset_end(parse(&f)?),
            FrameType::Verify => self.verify(parse(&f)?),
            other => protocol(format!("{other:?} is not allowed in the ready phase")),
        }
    }

    // ---- MANIFEST → NEED (§6.1) ----

    fn manifest(&mut self, m: Manifest) -> Result<(), Fatal> {
        if m.assets.len() > MAX_PAGE_ASSETS {
            return protocol("more than 500 assets in a page");
        }
        if self.job.as_ref().is_none_or(|j| j.job.job_id != m.job.job_id) {
            if m.page != 0 {
                return protocol("a new job must start at page 0");
            }
            let xmp = m.job.is_move() || self.ctx.limits.xmp_always;
            self.job = Some(JobState { job: m.job.clone(), xmp, next_page: 0, seen: HashSet::new(), wanted: HashMap::new() });
        }
        let job = self.job.as_mut().unwrap();
        if m.page != job.next_page {
            return protocol(format!("expected page {}, got {}", job.next_page, m.page));
        }
        job.next_page += 1;
        for a in &m.assets {
            if !job.seen.insert(a.id.clone()) && !job.job.is_move() {
                return protocol(format!("asset {} appears in two pages", a.id));
            }
            let keys: HashSet<&str> = a.res.iter().map(|r| r.key.as_str()).collect();
            if a.id.is_empty() || keys.len() != a.res.len() || a.res.is_empty() {
                return protocol(format!("asset {:?} has no or duplicate resource keys", a.id));
            }
        }

        let mut need = Need { job_id: m.job.job_id.clone(), page: m.page, want: vec![], have: vec![] };
        let mut wanted = vec![];
        let xmp = self.job.as_ref().is_some_and(|j| j.xmp);
        for a in m.assets {
            let r = self.compute_need(&a, xmp)?;
            if r.want.is_empty() {
                need.have.push(a.id.clone());
            } else {
                need.want.push(Want { id: a.id.clone(), res: r.want.clone() });
                wanted.push((a, r));
            }
        }
        let job = self.job.as_mut().unwrap();
        for (a, r) in wanted {
            let w = Wanted {
                keys: r.want.into_iter().map(|o| (o.key, o.offset)).collect(),
                provisional: r.provisional,
                prev_adjustment_sha: r.prev_adjustment_sha,
                more_pending: HashSet::new(),
                acked: false,
                asset: a,
            };
            job.wanted.insert(w.asset.id.clone(), w);
        }
        self.send(FrameType::Need, &need);
        Ok(())
    }

    fn compute_need(&self, a: &Asset, xmp: bool) -> Result<NeedResult, Fatal> {
        let ix = lock(&self.ctx.index);
        let arow = ix.asset(&self.dev, &a.id)?;
        let rows: HashMap<String, ResRow> =
            ix.resources(&self.dev, &a.id)?.into_iter().map(|r| (r.key.clone(), r)).collect();
        let same_modified = arow.as_ref().and_then(|r| r.modified_ms) == Some(a.modified_ms);
        let mut out = NeedResult { want: vec![], provisional: vec![], prev_adjustment_sha: None };
        let want = |out: &mut NeedResult, key: &str, offset: u64| out.want.push(ResOffset { key: key.into(), offset });

        for r in &a.res {
            match rows.get(&r.key) {
                Some(row) if row.state == ResState::Done => {
                    let intact = fsio::resolve(&self.ctx.dest, &row.rel_path).ok().and_then(|p| len_of(&p)) == Some(row.size);
                    if !intact {
                        // N15: the user deleted or damaged the final file.
                        ix.reset_resource(&self.dev, &a.id, &r.key)?;
                        want(&mut out, &r.key, 0);
                    } else if is_original_family(&r.ty) || same_modified {
                    } else if r.ty == "adjustment_data" {
                        out.prev_adjustment_sha = row.sha256.clone();
                        want(&mut out, &r.key, 0);
                    } else if r.size != Some(row.size) {
                        want(&mut out, &r.key, 0);
                    } else {
                        out.provisional.push(r.key.clone());
                    }
                }
                Some(row) if row.state == ResState::Partial => want(&mut out, &r.key, row.durable_offset),
                Some(_) => {
                    ix.reset_resource(&self.dev, &a.id, &r.key)?;
                    want(&mut out, &r.key, 0);
                }
                None => want(&mut out, &r.key, 0),
            }
        }

        // N8: resources the phone no longer has. Finals are kept; partials are dropped.
        let current: HashSet<&str> = a.res.iter().map(|r| r.key.as_str()).collect();
        for row in rows.values().filter(|r| !current.contains(r.key.as_str())) {
            match row.state {
                ResState::Partial | ResState::Verified => {
                    if let Ok((part, _)) = crate::recovery::paths(&self.ctx.dest, row) {
                        fsio::remove_if_exists(&part)?;
                    }
                    ix.delete_resource(&self.dev, &a.id, &row.key)?;
                }
                ResState::Done => ix.set_state(&self.dev, &a.id, &row.key, ResState::Orphaned)?,
                ResState::Orphaned => {}
            }
        }

        if let (true, Some(arow)) = (out.want.is_empty(), &arow) {
            // `have`: store the current meta, and make the sidecar durable before NEED (§6.3 meta refresh).
            ix.set_asset_acked(&self.dev, &a.id, a.modified_ms, &meta_json(a))?;
            let meta = Meta::of(a);
            if (xmp || arow.xmp_meta_hash.is_some()) && arow.xmp_meta_hash.as_deref() != Some(&meta.xmp_hash()) {
                xmp::write(&self.ctx.dest, &arow.base_rel, &meta)?;
                ix.set_xmp_hash(&self.dev, &a.id, &meta.xmp_hash())?;
            }
        }
        Ok(out)
    }

    // ---- Resource transfer (§6.2) ----

    fn res_begin(&mut self, b: ResBegin) -> Result<(), Fatal> {
        if u32::from(b.slot) >= self.ctx.limits.max_slots {
            return protocol(format!("slot {} out of range", b.slot));
        }
        if matches!(self.slots.get(&b.slot), Some(Slot::Active(_))) {
            return protocol(format!("RES_BEGIN on busy slot {}", b.slot));
        }
        let Some(job) = self.job.as_ref() else { return protocol("RES_BEGIN before MANIFEST") };
        let Some(w) = job.wanted.get(&b.id).filter(|w| !w.acked) else {
            return protocol(format!("RES_BEGIN for asset {} not in NEED.want", b.id));
        };
        let Some(&expected) = w.keys.get(&b.key) else {
            return protocol(format!("RES_BEGIN for key {} not requested", b.key));
        };
        let asset = w.asset.clone();
        let desc = asset.res.iter().find(|r| r.key == b.key).cloned().expect("wanted keys come from the manifest");

        if b.offset > b.size || (b.offset != 0 && b.offset != expected) {
            return self.nack(Some(b.slot), &b.id, &b.key, "bad_offset", true);
        }
        if (self.ctx.free_bytes)() < self.ctx.limits.reserve_bytes.saturating_add(b.size - b.offset) {
            // Checked before any .part exists (N9). The sender waits for RESUME before retrying.
            self.nack(Some(b.slot), &b.id, &b.key, "disk_full", false)?;
            if self.disk_paused.is_none() {
                self.send(FrameType::Pause, &Pause { why: "disk_low".into() });
            }
            self.disk_paused = Some(b.size - b.offset);
            return Ok(());
        }

        let dest = self.ctx.dest.clone();
        let mut ix = lock(&self.ctx.index);
        let base_rel = match ix.asset(&self.dev, &b.id)? {
            Some(a) => a.base_rel,
            None => {
                let (dir, base) = naming::base_candidate(&self.dev_name, &asset);
                let dir_abs = fsio::ensure_dir(&dest, &dir)?;
                let existing = names_in(&dir_abs);
                let taken = |cand: &str| {
                    asset.res.iter().any(|r| {
                        let f = naming::resource_file(cand, r, &asset.res).to_lowercase();
                        existing.contains(&f) || existing.contains(&naming::part_name(&f))
                    })
                };
                ix.allocate_base(&self.dev, &b.id, &asset.kind, &dir, &base, taken)?
            }
        };
        let (dir_rel, base) = base_rel.rsplit_once('/').expect("base_rel always has a directory");
        let rel_path = match ix.resource(&self.dev, &b.id, &b.key)? {
            Some(row) => row.rel_path,
            None => format!("{dir_rel}/{}", naming::resource_file(base, &desc, &asset.res)),
        };
        let fin = fsio::resolve(&dest, &rel_path)?;
        let file_name = fin.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
        let part = fin.with_file_name(naming::part_name(&file_name));
        let dir_abs = fsio::ensure_dir(&dest, rel_path.rsplit_once('/').map_or("", |(d, _)| d))?;

        let row = ResRow {
            device_id: self.dev.clone(),
            asset_id: b.id.clone(),
            key: b.key.clone(),
            ty: desc.ty.clone(),
            rel_path,
            size: b.size,
            durable_offset: b.offset,
            sha256: None,
            state: ResState::Partial,
        };
        let mut hasher = Sha256::new();
        let file = if b.offset == 0 {
            fsio::remove_if_exists(&part)?;
            ix.begin_resource(&row)?;
            let f = fsio::create_part(&part)?;
            fsio::fsync_dir(&dir_abs)?;
            f
        } else {
            let opened = fsio::open_part(&part).and_then(|mut f| {
                if f.metadata()?.len() < b.offset {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "part shorter than offset"));
                }
                f.set_len(b.offset)?;
                // Re-hash the durable prefix: RES_END's hash covers the whole file (W5).
                let mut buf = vec![0u8; WRITE_BUFFER];
                let mut left = b.offset;
                f.seek(SeekFrom::Start(0))?;
                while left > 0 {
                    let n = f.read(&mut buf[..left.min(WRITE_BUFFER as u64) as usize])?;
                    if n == 0 {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "part shrank"));
                    }
                    hasher.update(&buf[..n]);
                    left -= n as u64;
                }
                f.seek(SeekFrom::End(0))?;
                Ok(f)
            });
            match opened {
                Ok(f) => {
                    ix.begin_resource(&row)?;
                    f
                }
                Err(e) => {
                    drop(ix);
                    warn!("resume of {} failed: {e}", part.display());
                    return self.nack(Some(b.slot), &b.id, &b.key, "bad_offset", true);
                }
            }
        };
        drop(ix);
        let w = Writer {
            id: b.id,
            key: b.key,
            size: b.size,
            written: b.offset,
            durable: b.offset,
            file: BufWriter::with_capacity(WRITE_BUFFER, file),
            hasher,
            part,
            fin,
        };
        self.slots.insert(b.slot, Slot::Active(Box::new(w)));
        Ok(())
    }

    fn data(&mut self, c: DataChunk) -> Result<(), Fatal> {
        let checkpoint = self.ctx.limits.checkpoint_bytes;
        let w = match self.slots.get_mut(&c.slot) {
            None => return protocol(format!("DATA on free slot {}", c.slot)),
            Some(Slot::Discarding) => return Ok(()),
            Some(Slot::Active(w)) => w,
        };
        let len = c.bytes.len() as u64;
        if c.offset != w.written || w.written + len > w.size {
            let (id, key) = (w.id.clone(), w.key.clone());
            return self.nack(Some(c.slot), &id, &key, "bad_offset", true);
        }
        if let Err(e) = w.file.write_all(&c.bytes) {
            let (id, key) = (w.id.clone(), w.key.clone());
            warn!("writing {}: {e}", w.part.display());
            let why = if e.kind() == io::ErrorKind::StorageFull { "disk_full" } else { "io" };
            return self.nack(Some(c.slot), &id, &key, why, true);
        }
        w.hasher.update(&c.bytes);
        let before = w.written;
        w.written += len;
        crash::at_bytes(before, w.written, &w.key);
        if w.written >= w.durable + checkpoint {
            w.file.flush()?;
            if let (Some(d), false) = (self.ctx.limits.test_slow_writer, self.slow_writer_done) {
                self.slow_writer_done = true;
                std::thread::sleep(d);
            }
            w.file.get_ref().sync_all()?;
            lock(&self.ctx.index).set_durable(&self.dev, &w.id, &w.key, w.written)?;
            w.durable = w.written;
        }
        Ok(())
    }

    fn res_end(&mut self, e: ResEnd) -> Result<(), Fatal> {
        let mut w = match self.slots.remove(&e.slot) {
            None => return protocol(format!("RES_END on free slot {}", e.slot)),
            Some(Slot::Discarding) => return Ok(()),
            Some(Slot::Active(w)) => w,
        };
        if e.size != w.size || w.written != w.size {
            return self.nack(None, &w.id.clone(), &w.key.clone(), "size_mismatch", true);
        }
        let sha: [u8; 32] = w.hasher.clone().finalize().into();
        let claimed = hex::decode(&e.sha256).ok().filter(|_| e.sha256.len() == 64);
        if claimed.as_deref() != Some(sha.as_slice()) {
            return self.nack(None, &w.id.clone(), &w.key.clone(), "hash_mismatch", true);
        }

        crash::at("P2", &w.key);
        w.file.flush()?;
        w.file.get_ref().sync_all()?;
        let (id, key) = (w.id.clone(), w.key.clone());
        let ix = lock(&self.ctx.index);
        ix.set_verified(&self.dev, &id, &key, w.size, &sha)?;
        crash::at("P3", &key);
        drop(w.file);
        fsio::rename_replace(&w.part, &w.fin)?;
        crash::at("P4", &key);
        fsio::fsync_dir(w.fin.parent().unwrap_or(&self.ctx.dest))?;
        ix.set_state(&self.dev, &id, &key, ResState::Done)?;
        drop(ix);

        let Some(wanted) = self.job.as_mut().and_then(|j| j.wanted.get_mut(&id)) else { return Ok(()) };
        wanted.more_pending.remove(&key);
        let ty = wanted.asset.res.iter().find(|r| r.key == key).map(|r| r.ty.as_str());
        if ty == Some("adjustment_data")
            && wanted.prev_adjustment_sha.as_deref().is_some_and(|p| p != sha)
            && !wanted.provisional.is_empty()
        {
            // The edit really changed: request the renders answered as provisional `have` (§6.1).
            let keys = std::mem::take(&mut wanted.provisional);
            for k in &keys {
                wanted.keys.insert(k.clone(), 0);
                wanted.more_pending.insert(k.clone());
            }
            let res = keys.into_iter().map(|key| ResOffset { key, offset: 0 }).collect();
            self.send(FrameType::NeedMore, &NeedMore { id, res });
        }
        Ok(())
    }

    fn res_abort(&mut self, a: ResAbort) -> Result<(), Fatal> {
        let mut w = match self.slots.remove(&a.slot) {
            None => return protocol(format!("RES_ABORT on free slot {}", a.slot)),
            Some(Slot::Discarding) => return Ok(()),
            Some(Slot::Active(w)) => w,
        };
        let ix = lock(&self.ctx.index);
        if matches!(a.why.as_str(), "not_local" | "asset_gone") {
            drop(w.file);
            fsio::remove_if_exists(&w.part)?;
            ix.delete_resource(&self.dev, &w.id, &w.key)?;
        } else {
            // Resumable: keep exactly what we have (N4).
            w.file.flush()?;
            w.file.get_ref().sync_all()?;
            ix.set_durable(&self.dev, &w.id, &w.key, w.written)?;
            if let Some(wanted) = self.job.as_mut().and_then(|j| j.wanted.get_mut(&w.id)) {
                wanted.keys.insert(w.key.clone(), w.written);
            }
        }
        Ok(())
    }

    /// RES_NACK: drop the `.part` (when `reset`) and expect a retry from 0.
    fn nack(&mut self, slot: Option<u16>, id: &str, key: &str, why: &str, reset: bool) -> Result<(), Fatal> {
        if let Some(s) = slot
            && let Some(Slot::Active(w)) = self.slots.insert(s, Slot::Discarding) {
                drop(w.file);
                if reset {
                    fsio::remove_if_exists(&w.part)?;
                }
            }
        if reset {
            let ix = lock(&self.ctx.index);
            if let Some(row) = ix.resource(&self.dev, id, key)? {
                if let Ok((part, _)) = crate::recovery::paths(&self.ctx.dest, &row) {
                    fsio::remove_if_exists(&part)?;
                }
                ix.reset_resource(&self.dev, id, key)?;
            }
            if let Some(w) = self.job.as_mut().and_then(|j| j.wanted.get_mut(id)) {
                w.keys.insert(key.to_string(), 0);
            }
        }
        let attempt = self.attempts.entry((id.to_string(), key.to_string())).or_default();
        *attempt += 1;
        let nack = ResNack { id: id.into(), key: key.into(), why: why.into(), attempt: *attempt };
        self.send(FrameType::ResNack, &nack);
        Ok(())
    }

    // ---- ASSET_END → ACK (§6.3) ----

    fn asset_end(&mut self, e: AssetEnd) -> Result<(), Fatal> {
        let Some(w) = self.job.as_mut().and_then(|j| j.wanted.get_mut(&e.id)) else {
            return protocol(format!("ASSET_END for asset {} not in NEED.want", e.id));
        };
        if w.acked {
            return protocol(format!("second ASSET_END for {} after its ACK", e.id));
        }
        if e.complete && !w.more_pending.is_empty() {
            // NEED_MORE is outstanding: the sender will send another ASSET_END (§6.1).
            return Ok(());
        }
        let in_flight: HashSet<&str> = self
            .slots
            .values()
            .filter_map(|s| match s {
                Slot::Active(sw) if sw.id == e.id => Some(sw.key.as_str()),
                _ => None,
            })
            .collect();
        let ix = lock(&self.ctx.index);
        let mut failed = vec![];
        for key in &e.res_keys {
            let done = !in_flight.contains(key.as_str())
                && ix.resource(&self.dev, &e.id, key)?.is_some_and(|row| {
                    row.state == ResState::Done
                        && fsio::resolve(&self.ctx.dest, &row.rel_path).ok().and_then(|p| len_of(&p)) == Some(row.size)
                });
            if !done {
                let why = if e.complete { "missing".to_string() } else { e.why.clone().unwrap_or_else(|| "incomplete".into()) };
                failed.push(FailedKey { key: key.clone(), why });
            }
        }
        let xmp_needed = self.job.as_ref().is_some_and(|j| j.xmp);
        let Some(w) = self.job.as_mut().and_then(|j| j.wanted.get_mut(&e.id)) else { unreachable!() };
        let ack = if e.complete && failed.is_empty() {
            ix.set_asset_acked(&self.dev, &e.id, w.asset.modified_ms, &meta_json(&w.asset))?;
            if xmp_needed {
                let meta = Meta::of(&w.asset);
                let base = ix.asset(&self.dev, &e.id)?.map(|a| a.base_rel).expect("done resources imply an asset row");
                xmp::write(&self.ctx.dest, &base, &meta)?;
                ix.set_xmp_hash(&self.dev, &e.id, &meta.xmp_hash())?;
            }
            crash::at("P5", "");
            Ack { id: e.id.clone(), status: "durable".into(), failed: None }
        } else {
            Ack { id: e.id.clone(), status: "failed".into(), failed: Some(failed) }
        };
        drop(ix);
        w.acked = true;
        self.send(FrameType::Ack, &ack);
        Ok(())
    }
}

impl Engine {
    /// Free-space re-check while PAUSEd for disk_low.
    fn tick(&mut self) {
        if let Some(needed) = self.disk_paused
            && (self.ctx.free_bytes)() >= self.ctx.limits.reserve_bytes.saturating_add(needed) {
                self.disk_paused = None;
                self.send(FrameType::Resume, &Resume {});
            }
    }

    // ---- VERIFY → VERIFIED (§6.4, move only) ----

    fn verify(&mut self, v: Verify) -> Result<(), Fatal> {
        if v.assets.len() > MAX_VERIFY_ASSETS {
            return protocol("more than 1000 assets in VERIFY");
        }
        if !self.job.as_ref().is_some_and(|j| j.job.is_move()) {
            return protocol("VERIFY outside a move job");
        }
        let ix = lock(&self.ctx.index);
        let (mut ok, mut bad) = (vec![], vec![]);
        for a in v.assets {
            let Some(arow) = ix.asset(&self.dev, &a.id)? else {
                bad.push(BadAsset { id: a.id, why: "unknown_asset".into(), key: None });
                continue;
            };
            // Meta refresh first: VERIFY never says ok while the current meta isn't durable (Δ18).
            let stored = arow.meta_json.as_deref().and_then(Meta::from_json);
            let tz_min = stored.as_ref().map_or(0, |m| m.tz_min);
            let meta = Meta { created_ms: a.meta.created_ms, tz_min, fav: a.meta.fav, loc: a.meta.loc.clone() };
            if stored.as_ref().map(Meta::key) != Some(meta.key()) {
                ix.set_meta(&self.dev, &a.id, &meta.to_json())?;
            }
            if arow.xmp_meta_hash.as_deref() != Some(&meta.xmp_hash()) {
                xmp::write(&self.ctx.dest, &arow.base_rel, &meta)?;
                ix.set_xmp_hash(&self.dev, &a.id, &meta.xmp_hash())?;
            }
            match self.check_resources(&ix, &a.id, &a.res)? {
                None => ok.push(a.id),
                Some((why, key)) => bad.push(BadAsset { id: a.id, why: why.into(), key: Some(key) }),
            }
        }
        drop(ix);
        self.send(FrameType::Verified, &Verified { seq: v.seq, ok, bad });
        Ok(())
    }

    /// First failing resource of an asset, if any.
    fn check_resources(
        &self,
        ix: &crate::index::Index,
        id: &str,
        res: &[iost_proto::msg::VerifyRes],
    ) -> Result<Option<(&'static str, String)>, Fatal> {
        for r in res {
            let row = match ix.resource(&self.dev, id, &r.key)? {
                Some(row) if row.state == ResState::Done => row,
                _ => return Ok(Some(("missing_resource", r.key.clone()))),
            };
            let path = fsio::resolve(&self.ctx.dest, &row.rel_path)?;
            let Some(on_disk) = len_of(&path) else { return Ok(Some(("file_missing", r.key.clone()))) };
            if on_disk != row.size || r.size != row.size {
                return Ok(Some(("size_mismatch", r.key.clone())));
            }
            let stored = row.sha256.clone().unwrap_or_default();
            if r.sha256.as_ref().is_some_and(|h| hex::decode(h).ok().as_deref() != Some(stored.as_slice())) {
                return Ok(Some(("hash_mismatch", r.key.clone())));
            }
            if self.ctx.limits.paranoid && hash_file(&path)? != stored {
                return Ok(Some(("hash_mismatch", r.key.clone())));
            }
        }
        Ok(None)
    }
}

fn hash_file(path: &Path) -> io::Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; WRITE_BUFFER];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(h.finalize().to_vec());
        }
        h.update(&buf[..n]);
    }
}

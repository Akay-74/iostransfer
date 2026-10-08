//! Writer-path oracle (docs/WRITER_TESTS.md) against the real `iostransfer` binary.
//! The receiver runs as a child process so crash points can `abort()` it for real.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use iost_proto::msg::*;
use iost_proto::{auth, DataChunk, Frame, FrameCodec, FrameType, PREFACE};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use tokio_util::codec::{Decoder, Encoder};

const C: u64 = 64 * 1024;
const K: u64 = 16 * 1024;
const RES: u64 = 1 << 20;
const DEV: &str = "0b7c1c1e-3f7a-4c8e-9a51-2a3b4c5d6e7f";
const SECRET: [u8; 32] = [0x42; 32];
const CREATED: i64 = 1_710_411_322_000;
const DIR: &str = "Test iPhone/Photos/2024/03";

// ---------------------------------------------------------------- fixtures

fn content(seed: u64, n: u64) -> Vec<u8> {
    (0..n).map(|i| ((seed * 7 + i * 31) % 251) as u8).collect()
}

fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

#[derive(Clone)]
struct Res {
    key: &'static str,
    ty: &'static str,
    uti: &'static str,
    name: &'static str,
    data: Vec<u8>,
}

#[derive(Clone)]
struct A {
    id: &'static str,
    kind: &'static str,
    modified: i64,
    res: Vec<Res>,
}

impl A {
    fn res(&self, key: &str) -> &Res {
        self.res.iter().find(|r| r.key == key).unwrap()
    }
    fn wire(&self) -> Asset {
        Asset {
            id: self.id.into(),
            kind: self.kind.into(),
            created_ms: CREATED,
            tz_min: 60,
            modified_ms: self.modified,
            w: 1,
            h: 1,
            dur_ms: None,
            fav: false,
            loc: None,
            burst_id: None,
            subtypes: vec![],
            res: self
                .res
                .iter()
                .map(|r| ResDesc { key: r.key.into(), ty: r.ty.into(), uti: r.uti.into(), name: r.name.into(), size: Some(r.data.len() as u64) })
                .collect(),
        }
    }
    fn keys(&self) -> Vec<String> {
        self.res.iter().map(|r| r.key.to_string()).collect()
    }
}

fn r(key: &'static str, ty: &'static str, uti: &'static str, name: &'static str, data: Vec<u8>) -> Res {
    Res { key, ty, uti, name, data }
}

const HEIC: &str = "public.heic";
const MOV: &str = "com.apple.quicktime-movie";
const AAE: &str = "com.apple.photos.adjustment";

fn asset_p() -> A {
    A { id: "P", kind: "photo", modified: 1, res: vec![r("photo#0", "photo", HEIC, "IMG_0001.HEIC", content(1, 4 * C + 100))] }
}
fn asset_l() -> A {
    A {
        id: "L",
        kind: "photo",
        modified: 1,
        res: vec![
            r("photo#0", "photo", HEIC, "IMG_0002.HEIC", content(2, 2 * C)),
            r("paired_video#0", "paired_video", MOV, "IMG_0002.MOV", content(3, 3 * C + 7)),
        ],
    }
}
fn asset_e(modified: i64, adj_seed: u64, render_seed: u64, render_len: u64) -> A {
    A {
        id: "E",
        kind: "photo",
        modified,
        res: vec![
            r("photo#0", "photo", HEIC, "IMG_0003.HEIC", content(4, C)),
            r("full_size_photo#0", "full_size_photo", HEIC, "FullSizeRender.HEIC", content(render_seed, render_len)),
            r("adjustment_data#0", "adjustment_data", AAE, "IMG_0003.AAE", content(adj_seed, 500)),
        ],
    }
}
fn asset_v() -> A {
    A { id: "V", kind: "video", modified: 1, res: vec![r("video#0", "video", MOV, "IMG_0004.MOV", content(7, 6 * C))] }
}
fn asset_b() -> A {
    A {
        id: "B",
        kind: "photo",
        modified: 1,
        res: vec![
            r("photo#0", "photo", HEIC, "img_0001.heic", content(8, 2 * C)),
            r("paired_video#0", "paired_video", MOV, "IMG_0001.MOV", content(9, C)),
        ],
    }
}

// ---------------------------------------------------------------- receiver process

struct Env {
    root: PathBuf,
}

impl Env {
    fn new(name: &str) -> Env {
        let root = std::env::temp_dir().join(format!("iost-writer-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("dest")).unwrap();
        Env { root }
    }
    fn dest(&self) -> PathBuf {
        self.root.join("dest")
    }
    fn file(&self, rel: &str) -> PathBuf {
        self.dest().join(rel)
    }
    fn part(&self, rel: &str) -> PathBuf {
        let p = self.file(rel);
        p.with_file_name(format!(".{}.part", p.file_name().unwrap().to_string_lossy()))
    }
    fn spawn(&self, crash: &[(&str, &str)]) -> Recv {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_iostransfer"));
        cmd.args(["--config"])
            .arg(self.root.join("cfg"))
            .args(["receive", "--insecure-dev", "--port", "0", "--dest"])
            .arg(self.dest())
            .args(["--dev-device", &format!("{DEV}:{}", hex::encode(SECRET))])
            .args(["--checkpoint-bytes", &C.to_string(), "--reserve-bytes", &RES.to_string()])
            .env("NO_COLOR", "1")
            .env_remove("IOST_CRASH_AT")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in crash {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().unwrap();
        let (tx, lines) = mpsc::channel();
        let out = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for l in BufReader::new(out).lines().map_while(Result::ok) {
                let _ = tx.send(l);
            }
        });
        let mut recv = Recv { child, lines, port: 0, log: vec![] };
        let line = recv.wait_line("Listening on", Duration::from_secs(10));
        recv.port = line.rsplit(':').next().unwrap().trim().parse().unwrap();
        recv
    }
    fn db(&self) -> Connection {
        let c = Connection::open(self.dest().join(".iostransfer/index.db")).unwrap();
        c.pragma_update(None, "locking_mode", "EXCLUSIVE").unwrap();
        c
    }
    /// (state, durable_offset, rel_path) of a resource row.
    fn row(&self, id: &str, key: &str) -> Option<(String, u64, String)> {
        self.db()
            .query_row(
                "SELECT state, durable_offset, rel_path FROM resources WHERE asset_id = ?1 AND res_key = ?2",
                [id, key],
                |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64, r.get(2)?)),
            )
            .ok()
    }
    fn base_rel(&self, id: &str) -> String {
        self.db().query_row("SELECT base_rel FROM assets WHERE asset_id = ?1", [id], |r| r.get(0)).unwrap()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

struct Recv {
    child: Child,
    lines: mpsc::Receiver<String>,
    port: u16,
    log: Vec<String>,
}

impl Recv {
    fn wait_line(&mut self, needle: &str, within: Duration) -> String {
        let end = Instant::now() + within;
        if let Some(l) = self.log.iter().find(|l| l.contains(needle)) {
            return l.clone();
        }
        loop {
            let left = end.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(l) => {
                    self.log.push(l.clone());
                    if l.contains(needle) {
                        return l;
                    }
                }
                Err(_) => panic!("receiver never printed {needle:?}; log: {:#?}", self.log),
            }
        }
    }
    /// Wait for an injected abort().
    fn expect_crash(mut self) {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(st) = self.child.try_wait().unwrap() {
                assert!(!st.success(), "receiver exited cleanly instead of crashing");
                #[cfg(unix)]
                assert_eq!(std::os::unix::process::ExitStatusExt::signal(&st), Some(6), "expected SIGABRT");
                return;
            }
            assert!(Instant::now() < end, "receiver did not crash");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    /// Wait until the session's writer has shut down (exact offsets committed), then kill.
    fn after_session_kill(mut self) {
        self.wait_line("session closed", Duration::from_secs(10));
        self.kill();
    }
    fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Recv {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------- phone simulator

struct Phone {
    s: TcpStream,
    buf: BytesMut,
    job: String,
    mode: &'static str,
    page: u32,
}

impl Phone {
    fn connect(recv: &Recv) -> Phone {
        Self::connect_mode(recv, "copy")
    }
    fn connect_mode(recv: &Recv, mode: &'static str) -> Phone {
        let s = TcpStream::connect(("127.0.0.1", recv.port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.set_nodelay(true).unwrap();
        let mut p = Phone { s, buf: BytesMut::new(), job: uuid::Uuid::new_v4().to_string(), mode, page: 0 };
        p.s.write_all(&PREFACE).unwrap();
        let mut pre = [0u8; 8];
        p.s.read_exact(&mut pre).unwrap();
        assert_eq!(pre, PREFACE);
        let s_nonce = [7u8; 32];
        p.send_json(
            FrameType::Hello,
            &Hello {
                proto: ProtoRange { min: 1, max: 1 },
                device_id: DEV.into(),
                device_name: "Test iPhone".into(),
                app_version: "test".into(),
                os: "sim".into(),
                auth: HelloAuth::Secret { s_nonce: hex::encode(s_nonce) },
            },
        );
        let ch: Challenge = p.expect(FrameType::Challenge);
        let r_nonce: [u8; 32] = hex::decode(&ch.r_nonce).unwrap().try_into().unwrap();
        assert_eq!(hex::encode(auth::r_proof(&SECRET, &s_nonce, &r_nonce)), ch.r_proof);
        p.send_json(FrameType::Auth, &Auth { s_proof: hex::encode(auth::s_proof(&SECRET, &s_nonce, &r_nonce)) });
        let _: Welcome = p.expect(FrameType::Welcome);
        p
    }
    fn send(&mut self, f: Frame) {
        let mut b = BytesMut::new();
        FrameCodec.encode(f, &mut b).unwrap();
        self.s.write_all(&b).unwrap();
    }
    fn send_json<T: serde::Serialize>(&mut self, ty: FrameType, m: &T) {
        self.send(Frame::json(ty, m));
    }
    /// Next frame that isn't a PING (answered) or PONG; None on close/timeout.
    fn next(&mut self, within: Duration) -> Option<Frame> {
        self.s.set_read_timeout(Some(within)).unwrap();
        loop {
            if let Some(f) = FrameCodec.decode(&mut self.buf).unwrap() {
                match f.ty {
                    FrameType::Ping => self.send(Frame { ty: FrameType::Pong, payload: f.payload }),
                    FrameType::Pong => {}
                    _ => return Some(f),
                }
                continue;
            }
            let mut tmp = [0u8; 65536];
            match self.s.read(&mut tmp) {
                Ok(0) | Err(_) => return None,
                Ok(n) => self.buf.extend_from_slice(&tmp[..n]),
            }
        }
    }
    fn expect<T: serde::de::DeserializeOwned>(&mut self, ty: FrameType) -> T {
        let f = self.next(Duration::from_secs(10)).unwrap_or_else(|| panic!("connection closed waiting for {ty:?}"));
        assert_eq!(f.ty, ty, "got {:?} {}", f.ty, String::from_utf8_lossy(&f.payload));
        serde_json::from_slice(&f.payload).unwrap()
    }
    /// Round-trip a PING: every frame sent before it has been read by the receiver.
    fn sync(&mut self) {
        self.send_json(FrameType::Ping, &serde_json::json!({"n": 99}));
        self.s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        loop {
            if let Some(f) = FrameCodec.decode(&mut self.buf).unwrap() {
                match f.ty {
                    FrameType::Pong => return,
                    FrameType::Ping => self.send(Frame { ty: FrameType::Pong, payload: f.payload }),
                    other => panic!("unexpected {other:?} {}", String::from_utf8_lossy(&f.payload)),
                }
                continue;
            }
            let mut tmp = [0u8; 65536];
            let n = self.s.read(&mut tmp).unwrap();
            assert!(n > 0, "closed during sync");
            self.buf.extend_from_slice(&tmp[..n]);
        }
    }
    fn manifest(&mut self, assets: &[&A]) -> Need {
        let m = Manifest {
            job: Job { job_id: self.job.clone(), label: "test".into(), section: "photos".into(), mode: self.mode.into() },
            page: self.page,
            last: false,
            assets: assets.iter().map(|a| a.wire()).collect(),
        };
        self.page += 1;
        self.send_json(FrameType::Manifest, &m);
        self.expect(FrameType::Need)
    }
    fn begin(&mut self, slot: u16, a: &A, key: &str, offset: u64) {
        let size = a.res(key).data.len() as u64;
        self.send_json(FrameType::ResBegin, &ResBegin { slot, id: a.id.into(), key: key.into(), offset, size });
    }
    fn data(&mut self, slot: u16, bytes: &[u8], from: u64, upto: u64) {
        let mut off = from;
        while off < upto {
            let end = (off + K).min(upto);
            self.send(Frame::data(&DataChunk { slot, offset: off, bytes: bytes[off as usize..end as usize].to_vec().into() }));
            off = end;
        }
    }
    fn end(&mut self, slot: u16, a: &A, key: &str) {
        let d = &a.res(key).data;
        self.send_json(FrameType::ResEnd, &ResEnd { slot, size: d.len() as u64, sha256: sha(d) });
    }
    /// RES_BEGIN + DATA [from, size) + RES_END.
    fn send_res(&mut self, slot: u16, a: &A, key: &str, from: u64) {
        let d = a.res(key).data.clone();
        self.begin(slot, a, key, from);
        self.data(slot, &d, from, d.len() as u64);
        self.end(slot, a, key);
    }
    /// RES_BEGIN + DATA [from, upto), no RES_END.
    fn send_upto(&mut self, slot: u16, a: &A, key: &str, from: u64, upto: u64) {
        let d = a.res(key).data.clone();
        self.begin(slot, a, key, from);
        self.data(slot, &d, from, upto);
    }
    fn asset_end(&mut self, a: &A, keys: Vec<String>, complete: bool, why: Option<&str>) {
        self.send_json(FrameType::AssetEnd, &AssetEnd { id: a.id.into(), res_keys: keys, complete, why: why.map(Into::into) });
    }
    fn ack(&mut self) -> Ack {
        self.expect(FrameType::Ack)
    }
    fn nack(&mut self) -> ResNack {
        self.expect(FrameType::ResNack)
    }
    fn expect_protocol_error(&mut self) {
        let b: Bye = self.expect(FrameType::Bye);
        assert_eq!(b.code, "protocol_error", "{b:?}");
    }
    /// Full transfer of every wanted key of `a`, then ASSET_END, expecting ACK durable.
    fn transfer(&mut self, a: &A, need: &Need) {
        let want = need.want.iter().find(|w| w.id == a.id).expect("asset wanted");
        for o in &want.res {
            self.send_res(0, a, &o.key, o.offset);
        }
        self.asset_end(a, a.keys(), true, None);
        let ack = self.ack();
        assert_eq!((ack.id.as_str(), ack.status.as_str()), (a.id, "durable"), "{ack:?}");
    }
}

fn want_of(need: &Need, id: &str) -> Vec<(String, u64)> {
    need.want.iter().find(|w| w.id == id).map(|w| w.res.iter().map(|o| (o.key.clone(), o.offset)).collect()).unwrap_or_default()
}

fn wants(pairs: &[(&str, u64)]) -> Vec<(String, u64)> {
    pairs.iter().map(|(k, o)| (k.to_string(), *o)).collect()
}

fn read(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn len(p: &Path) -> Option<u64> {
    std::fs::metadata(p).ok().map(|m| m.len())
}

const P_REL: &str = "Test iPhone/Photos/2024/03/20240314_111522_IMG_0001.HEIC";

/// Invariants I-B and I-C on a stopped receiver: no stray `.part`, every done row hashes right.
fn check_invariants(env: &Env) {
    let db = env.db();
    let mut st = db.prepare("SELECT rel_path, size, sha256, state FROM resources").unwrap();
    let rows: Vec<(String, i64, Option<Vec<u8>>, String)> =
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap().map(Result::unwrap).collect();
    for (rel, size, digest, state) in &rows {
        if state == "done" {
            let bytes = read(&env.file(rel));
            assert_eq!(bytes.len() as i64, *size, "{rel}");
            assert_eq!(Sha256::digest(&bytes).as_slice(), digest.as_deref().unwrap(), "I-C {rel}");
        }
        if state != "partial" && state != "verified" {
            assert!(!env.part(rel).exists(), "I-B: stray .part for {rel}");
        }
    }
}

// ---------------------------------------------------------------- §2 baseline

#[test]
fn w1_single_photo() {
    let env = Env::new("w1");
    let recv = env.spawn(&[]);
    let mut ph = Phone::connect(&recv);
    let p = asset_p();
    let need = ph.manifest(&[&p]);
    assert_eq!(want_of(&need, "P"), wants(&[("photo#0", 0)]));
    ph.transfer(&p, &need);
    assert_eq!(read(&env.file(P_REL)), p.res("photo#0").data);
    assert!(!env.part(P_REL).exists());
    drop(ph);
    recv.after_session_kill();
    assert_eq!(env.row("P", "photo#0"), Some(("done".into(), 4 * C + 100, P_REL.into())));
    check_invariants(&env);
}

#[test]
fn w2_live_photo_ack_only_after_asset_end() {
    let env = Env::new("w2");
    let recv = env.spawn(&[]);
    let mut ph = Phone::connect(&recv);
    let l = asset_l();
    let need = ph.manifest(&[&l]);
    assert_eq!(want_of(&need, "L"), wants(&[("photo#0", 0), ("paired_video#0", 0)]));
    ph.send_res(0, &l, "photo#0", 0);
    ph.send_res(0, &l, "paired_video#0", 0);
    ph.sync();
    assert!(ph.next(Duration::from_millis(300)).is_none(), "no ACK before ASSET_END");
    ph.asset_end(&l, l.keys(), true, None);
    assert_eq!(ph.ack().status, "durable");
    let base = format!("{DIR}/20240314_111522_IMG_0002");
    assert_eq!(read(&env.file(&format!("{base}.HEIC"))), l.res("photo#0").data);
    assert_eq!(read(&env.file(&format!("{base}.MOV"))), l.res("paired_video#0").data);
}

#[test]
fn w3_interleaved_slots() {
    let env = Env::new("w3");
    let recv = env.spawn(&[]);
    let mut ph = Phone::connect(&recv);
    let (p, v) = (asset_p(), asset_v());
    ph.manifest(&[&p, &v]);
    let (pd, vd) = (p.res("photo#0").data.clone(), v.res("video#0").data.clone());
    ph.begin(0, &p, "photo#0", 0);
    ph.begin(1, &v, "video#0", 0);
    let (mut po, mut vo) = (0u64, 0u64);
    while po < pd.len() as u64 || vo < vd.len() as u64 {
        if po < pd.len() as u64 {
            let e = (po + K).min(pd.len() as u64);
            ph.data(0, &pd, po, e);
            po = e;
        }
        if vo < vd.len() as u64 {
            let e = (vo + K).min(vd.len() as u64);
            ph.data(1, &vd, vo, e);
            vo = e;
        }
    }
    ph.end(1, &v, "video#0");
    ph.end(0, &p, "photo#0");
    ph.asset_end(&v, v.keys(), true, None);
    ph.asset_end(&p, p.keys(), true, None);
    assert_eq!(ph.ack().id, "V");
    assert_eq!(ph.ack().id, "P");
    assert_eq!(read(&env.file("Test iPhone/Videos/2024/03/20240314_111522_IMG_0004.MOV")), vd);
    assert_eq!(read(&env.file(P_REL)), pd);
}

#[test]
fn w4_resent_have_asset_is_not_rewritten() {
    let env = Env::new("w4");
    let recv = env.spawn(&[]);
    let p = asset_p();
    let mut ph = Phone::connect(&recv);
    let need = ph.manifest(&[&p]);
    ph.transfer(&p, &need);
    drop(ph);
    let before = std::fs::metadata(env.file(P_REL)).unwrap();
    let mut ph = Phone::connect(&recv);
    let need = ph.manifest(&[&p]);
    assert!(need.want.is_empty() && need.have == vec!["P".to_string()], "{need:?}");
    let after = std::fs::metadata(env.file(P_REL)).unwrap();
    assert_eq!(before.modified().unwrap(), after.modified().unwrap());
    #[cfg(unix)]
    assert_eq!(std::os::unix::fs::MetadataExt::ino(&before), std::os::unix::fs::MetadataExt::ino(&after));
    ph.begin(0, &p, "photo#0", 0);
    ph.expect_protocol_error();
}

// ---------------------------------------------------------------- §3 crash cases

#[test]
fn p1a_crash_mid_data_after_two_checkpoints() {
    let env = Env::new("p1a");
    let p = asset_p();
    {
        let recv = env.spawn(&[("IOST_CRASH_AT", &format!("P1:{}", 2 * C + 5000))]);
        let mut ph = Phone::connect(&recv);
        ph.manifest(&[&p]);
        ph.send_upto(0, &p, "photo#0", 0, 2 * C + 5000 + K);
        recv.expect_crash();
    }
    let l = len(&env.part(P_REL)).unwrap();
    assert!((2 * C..=2 * C + 5000 + K).contains(&l), "part len {l}");
    assert_eq!(env.row("P", "photo#0").unwrap().1, 2 * C);
    // abort() keeps the page cache; a power loss may also leave garbage past the checkpoint.
    let mut f = std::fs::OpenOptions::new().append(true).open(env.part(P_REL)).unwrap();
    f.write_all(&[0xEE; 3000]).unwrap();
    drop(f);
    let recv = env.spawn(&[]);
    assert_eq!(len(&env.part(P_REL)), Some(2 * C), "recovery truncates to the checkpoint");
    let mut ph = Phone::connect(&recv);
    let need = ph.manifest(&[&p]);
    assert_eq!(want_of(&need, "P"), wants(&[("photo#0", 2 * C)]));
    ph.transfer(&p, &need);
    assert_eq!(sha(&read(&env.file(P_REL))), sha(&p.res("photo#0").data));
    drop(ph);
    recv.after_session_kill();
    check_invariants(&env);
}

#[test]
fn p1b_crash_before_first_checkpoint() {
    let env = Env::new("p1b");
    let p = asset_p();
    {
        let recv = env.spawn(&[("IOST_CRASH_AT", &format!("P1:{}", C - 1))]);
        let mut ph = Phone::connect(&recv);
        ph.manifest(&[&p]);
        ph.send_upto(0, &p, "photo#0", 0, 2 * C);
        recv.expect_crash();
    }
    assert_eq!(env.row("P", "photo#0").unwrap().1, 0);
    let recv = env.spawn(&[]);
    assert_eq!(len(&env.part(P_REL)), Some(0));
    let mut ph = Phone::connect(&recv);
    assert_eq!(want_of(&ph.manifest(&[&p]), "P"), wants(&[("photo#0", 0)]));
}

#[test]
fn p1c_live_photo_second_resource_mid_flight() {
    let env = Env::new("p1c");
    let l = asset_l();
    {
        let recv = env.spawn(&[("IOST_CRASH_AT", &format!("P1:{}", C + K)), ("IOST_CRASH_KEY", "paired_video#0")]);
        let mut ph = Phone::connect(&recv);
        ph.manifest(&[&l]);
        ph.send_res(0, &l, "photo#0", 0);
        ph.send_upto(0, &l, "paired_video#0", 0, C + K);
        recv.expect_crash();
    }
    assert_eq!(env.row("L", "photo#0").unwrap().0, "done");
    assert_eq!(env.row("L", "paired_video#0").unwrap().1, C);
    let recv = env.spawn(&[]);
    let mut ph = Phone::connect(&recv);
    let need = ph.manifest(&[&l]);
    assert_eq!(want_of(&need, "L"), wants(&[("paired_video#0", C)]));
    ph.transfer(&l, &need);
}

#[test]
fn p2_hash_ok_crash_before_final_fsync() {
    let env = Env::new("p2");
    let p = asset_p();
    {
        let recv = env.spawn(&[("IOST_CRASH_AT", "P2")]);
        let mut ph = Phone::connect(&recv);
        ph.manifest(&[&p]);
        ph.send_res(0, &p, "photo#0", 0);
        recv.expect_crash();
    }
    assert_eq!(env.row("P", "photo#0").unwrap(), ("partial".into(), 4 * C, P_REL.into()));
    let recv = env.spawn(&[]);
    assert_eq!(len(&env.part(P_REL)), Some(4 * C));
    let mut ph = Phone::connect(&recv);
    let need = ph.manifest(&[&p]);
    assert_eq!(want_of(&need, "P"), wants(&[("photo#0", 4 * C)]));
    ph.transfer(&p, &need);
}

#[test]
fn w5_resume_where_offset_equals_size() {
    let env = Env::new("w5");
    let l = asset_l();
    {
        let recv = env.spawn(&[("IOST_CRASH_AT", "P2"), ("IOST_CRASH_KEY", "photo#0")]);
        let mut ph = Phone::connect(&recv);
        ph.manifest(&[&l]);
        ph.send_res(0, &l, "photo#0", 0);
        recv.expect_crash();
    }
    let recv = env.spawn(&[]);
    let mut ph = Phone::connect(&recv);
    let need = ph.manifest(&[&l]);
    assert_eq!(want_of(&need, "L"), wants(&[("photo#0", 2 * C), ("paired_video#0", 0)]));
    ph.begin(0, &l, "photo#0", 2 * C);
    ph.end(0, &l, "photo#0");
    ph.send_res(0, &l, "paired_video#0", 0);
    ph.asset_end(&l, l.keys(), true, None);
    assert_eq!(ph.ack().status, "durable");
    drop(ph);
    recv.after_session_kill();
    assert_eq!(env.row("L", "photo#0").unwrap().0, "done");
    check_invariants(&env);
}

#[test]
fn p3_verified_crash_before_rename() {
    let env = Env::new("p3");
    let p = asset_p();
    {
        let recv = env.spawn(&[("IOST_CRASH_AT", "P3")]);
        let mut ph = Phone::connect(&recv);
        ph.manifest(&[&p]);
        ph.send_res(0, &p, "photo#0", 0);
        recv.expect_crash();
    }
    assert_eq!(len(&env.part(P_REL)), Some(4 * C + 100));
    assert!(!env.file(P_REL).exists());
    assert_eq!(env.row("P", "photo#0").unwrap().0, "verified");
    let recv = env.spawn(&[]);
    assert!(!env.part(P_REL).exists());
    assert_eq!(read(&env.file(P_REL)), p.res("photo#0").data);
    let mut ph = Phone::connect(&recv);
    let need = ph.manifest(&[&p]);
    assert_eq!(need.have, vec!["P".to_string()]);
}

#[test]
fn p3_r1_crash_again_during_recovery() {
    let env = Env::new("p3r1");
    let p = asset_p();
    {
        let recv = env.spawn(&[("IOST_CRASH_AT", "P3")]);
        let mut ph = Phone::connect(&recv);
        ph.manifest(&[&p]);
        ph.send_res(0, &p, "photo#0", 0);
        recv.expect_crash();
    }
    // Recovery itself crashes after the rename: the child dies before it ever listens.
    let st = Command::new(env!("CARGO_BIN_EXE_iostransfer"))
        .arg("--config")
        .arg(env.root.join("cfg"))
        .args(["receive", "--insecure-dev", "--port", "0", "--dest"])
        .arg(env.dest())
        .env("IOST_CRASH_AT", "R1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!st.success());
    assert_eq!(env.row("P", "photo#0").unwrap().0, "verified");
    assert!(env.file(P_REL).exists() && !env.part(P_REL).exists());
    let recv = env.spawn(&[]);
    let mut ph = Phone::connect(&recv);
    assert_eq!(ph.manifest(&[&p]).have, vec!["P".to_string()]);
    drop(ph);
    recv.after_session_kill();
    check_invariants(&env);
}

#[test]
fn p4_renamed_crash_before_done_commit() {
    let env = Env::new("p4");
    let p = asset_p();
    {
        let recv = env.spawn(&[("IOST_CRASH_AT", "P4")]);
        let mut ph = Phone::connect(&recv);
        ph.manifest(&[&p]);
        ph.send_res(0, &p, "photo#0", 0);
        recv.expect_crash();
    }
    assert!(env.file(P_REL).exists() && !env.part(P_REL).exists());
    assert_eq!(env.row("P", "photo#0").unwrap().0, "verified");
    let recv = env.spawn(&[]);
    let mut ph = Phone::connect(&recv);
    assert_eq!(ph.manifest(&[&p]).have, vec!["P".to_string()]);
}

#[test]
fn p4b_damaged_final_is_replaced_not_deleted() {
    let env = Env::new("p4b");
    let p = asset_p();
    {
        let recv = env.spawn(&[("IOST_CRASH_AT", "P4")]);
        let mut ph = Phone::connect(&recv);
        ph.manifest(&[&p]);
        ph.send_res(0, &p, "photo#0", 0);
        recv.expect_crash();
    }
    std::fs::OpenOptions::new().write(true).open(env.file(P_REL)).unwrap().set_len(10).unwrap();
    let recv = env.spawn(&[]);
    assert_eq!(len(&env.file(P_REL)), Some(10), "recovery never deletes a final");
    let mut ph = Phone::connect(&recv);
    let need = ph.manifest(&[&p]);
    assert_eq!(want_of(&need, "P"), wants(&[("photo#0", 0)]));
    ph.transfer(&p, &need);
    assert_eq!(read(&env.file(P_REL)), p.res("photo#0").data);
}

#[test]
fn p5_done_crash_before_ack() {
    let env = Env::new("p5");
    let l = asset_l();
    {
        let recv = env.spawn(&[("IOST_CRASH_AT", "P5")]);
        let mut ph = Phone::connect(&recv);
        let need = ph.manifest(&[&l]);
        for (k, _) in want_of(&need, "L") {
            ph.send_res(0, &l, &k, 0);
        }
        ph.asset_end(&l, l.keys(), true, None);
        recv.expect_crash();
    }
    assert_eq!(env.row("L", "photo#0").unwrap().0, "done");
    assert_eq!(env.row("L", "paired_video#0").unwrap().0, "done");
    let recv = env.spawn(&[]);
    let mut ph = Phone::connect(&recv);
    assert_eq!(ph.manifest(&[&l]).have, vec!["L".to_string()]);
}

#[test]
fn or_stray_part_is_removed_other_files_untouched() {
    let env = Env::new("or");
    let dir = env.dest().join(DIR);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(".stray.part"), b"x").unwrap();
    std::fs::write(dir.join("keep.part"), b"user").unwrap();
    std::fs::write(dir.join(".hidden"), b"user").unwrap();
    let _recv = env.spawn(&[]);
    assert!(!dir.join(".stray.part").exists());
    assert!(dir.join("keep.part").exists() && dir.join(".hidden").exists());
}

// ---------------------------------------------------------------- §4 error paths

#[test]
fn n1_hash_mismatch_nack_then_retry() {
    let env = Env::new("n1");
    let recv = env.spawn(&[]);
    let p = asset_p();
    let mut ph = Phone::connect(&recv);
    ph.manifest(&[&p]);
    let d = p.res("photo#0").data.clone();
    for attempt in 1..=2 {
        ph.begin(0, &p, "photo#0", 0);
        ph.data(0, &d, 0, d.len() as u64);
        ph.send_json(FrameType::ResEnd, &ResEnd { slot: 0, size: d.len() as u64, sha256: "0".repeat(64) });
        let n = ph.nack();
        assert_eq!((n.why.as_str(), n.attempt), ("hash_mismatch", attempt));
        ph.sync();
        assert!(!env.part(P_REL).exists());
    }
    ph.send_res(0, &p, "photo#0", 0);
    ph.asset_end(&p, p.keys(), true, None);
    assert_eq!(ph.ack().status, "durable");
    drop(ph);
    recv.after_session_kill();
    assert_eq!(env.row("P", "photo#0").unwrap().2, P_REL, "rel_path stable across NACKs");
}

#[test]
fn n2_size_mismatches() {
    let env = Env::new("n2");
    let recv = env.spawn(&[]);
    let p = asset_p();
    let d = p.res("photo#0").data.clone();
    let mut ph = Phone::connect(&recv);
    ph.manifest(&[&p]);
    // (a) RES_END size differs from RES_BEGIN.
    ph.send_upto(0, &p, "photo#0", 0, d.len() as u64);
    ph.send_json(FrameType::ResEnd, &ResEnd { slot: 0, size: 5, sha256: sha(&d) });
    assert_eq!(ph.nack().why, "size_mismatch");
    // (b) RES_END after too few bytes.
    ph.send_upto(0, &p, "photo#0", 0, C);
    ph.end(0, &p, "photo#0");
    assert_eq!(ph.nack().why, "size_mismatch");
    // (c) DATA past the size: bad_offset, later DATA dropped, connection stays up.
    ph.send_upto(0, &p, "photo#0", 0, d.len() as u64);
    ph.send(Frame::data(&DataChunk { slot: 0, offset: d.len() as u64, bytes: vec![1u8; 10].into() }));
    assert_eq!(ph.nack().why, "bad_offset");
    ph.send(Frame::data(&DataChunk { slot: 0, offset: 0, bytes: vec![1u8; 10].into() }));
    ph.end(0, &p, "photo#0");
    ph.sync();
    assert!(!env.part(P_REL).exists());
    ph.send_res(0, &p, "photo#0", 0);
    ph.asset_end(&p, p.keys(), true, None);
    assert_eq!(ph.ack().status, "durable");
}

#[test]
fn n3_offset_errors() {
    let env = Env::new("n3");
    let p = asset_p();
    let d = p.res("photo#0").data.clone();
    {
        let recv = env.spawn(&[]);
        let mut ph = Phone::connect(&recv);
        ph.manifest(&[&p]);
        // (a) skip a chunk.
        ph.begin(0, &p, "photo#0", 0);
        ph.data(0, &d, 0, K);
        ph.data(0, &d, 2 * K, 3 * K);
        assert_eq!(ph.nack().why, "bad_offset");
        ph.end(0, &p, "photo#0");
        // Get to a durable 2C partial, then disconnect.
        ph.send_upto(0, &p, "photo#0", 0, 2 * C);
        ph.sync();
        drop(ph);
        recv.after_session_kill();
    }
    let recv = env.spawn(&[]);
    let mut ph = Phone::connect(&recv);
    let need = ph.manifest(&[&p]);
    assert_eq!(want_of(&need, "P"), wants(&[("photo#0", 2 * C)]));
    // (b) a wrong resume offset.
    ph.begin(0, &p, "photo#0", C);
    assert_eq!(ph.nack().why, "bad_offset");
    // (c) offset 0 is always accepted.
    ph.send_res(0, &p, "photo#0", 0);
    ph.asset_end(&p, p.keys(), true, None);
    assert_eq!(ph.ack().status, "durable");
    assert_eq!(read(&env.file(P_REL)), d);
}

#[test]
fn n4_res_abort_kinds() {
    for (why, resumable) in [("not_local", false), ("asset_gone", false), ("cancelled", true), ("read_error", true)] {
        let env = Env::new(&format!("n4-{why}"));
        let p = asset_p();
        {
            let recv = env.spawn(&[]);
            let mut ph = Phone::connect(&recv);
            ph.manifest(&[&p]);
            ph.send_upto(0, &p, "photo#0", 0, 2 * C + K);
            ph.send_json(FrameType::ResAbort, &ResAbort { slot: 0, why: why.into() });
            ph.asset_end(&p, p.keys(), false, Some(why));
            let ack = ph.ack();
            assert_eq!(ack.status, "failed", "{why}");
            drop(ph);
            recv.after_session_kill();
        }
        if resumable {
            assert_eq!(len(&env.part(P_REL)), Some(2 * C + K), "{why}");
            assert_eq!(env.row("P", "photo#0").unwrap().1, 2 * C + K, "{why}");
            let recv = env.spawn(&[]);
            let mut ph = Phone::connect(&recv);
            assert_eq!(want_of(&ph.manifest(&[&p]), "P"), wants(&[("photo#0", 2 * C + K)]), "{why}");
        } else {
            assert!(!env.part(P_REL).exists(), "{why}");
            assert!(env.row("P", "photo#0").is_none(), "{why}");
            assert!(!env.base_rel("P").is_empty(), "base_rel kept");
        }
    }
}

#[test]
fn n5_edit_changed_need_more_and_atomic_replace() {
    let env = Env::new("n5");
    let recv = env.spawn(&[]);
    let e1 = asset_e(1, 6, 5, C + 1);
    let mut ph = Phone::connect(&recv);
    let need = ph.manifest(&[&e1]);
    ph.transfer(&e1, &need);
    drop(ph);
    let base = format!("{DIR}/20240314_111522_IMG_0003");
    let edited = env.file(&format!("{base}_edited.HEIC"));
    let original_meta = std::fs::metadata(env.file(&format!("{base}.HEIC"))).unwrap();

    let e2 = asset_e(2, 16, 15, C + 1);
    let mut ph = Phone::connect(&recv);
    let need = ph.manifest(&[&e2]);
    assert_eq!(want_of(&need, "E"), wants(&[("adjustment_data#0", 0)]));
    ph.send_res(0, &e2, "adjustment_data#0", 0);
    let more: NeedMore = ph.expect(FrameType::NeedMore);
    assert_eq!(more.res, vec![ResOffset { key: "full_size_photo#0".into(), offset: 0 }]);
    ph.asset_end(&e2, e2.keys(), true, None);
    ph.sync();
    assert!(ph.next(Duration::from_millis(200)).is_none(), "no ACK while NEED_MORE is outstanding");
    let new_render = e2.res("full_size_photo#0").data.clone();
    ph.send_upto(0, &e2, "full_size_photo#0", 0, K);
    ph.sync();
    assert_eq!(read(&edited), e1.res("full_size_photo#0").data, "old render intact mid-transfer");
    ph.data(0, &new_render, K, new_render.len() as u64);
    ph.end(0, &e2, "full_size_photo#0");
    ph.asset_end(&e2, e2.keys(), true, None);
    assert_eq!(ph.ack().status, "durable");
    assert_eq!(read(&edited), new_render);
    assert_eq!(read(&env.file(&format!("{base}.AAE"))), e2.res("adjustment_data#0").data);
    let now_meta = std::fs::metadata(env.file(&format!("{base}.HEIC"))).unwrap();
    assert_eq!(original_meta.modified().unwrap(), now_meta.modified().unwrap(), "original untouched");
}

#[test]
fn n5b_n5c_n6_edit_variants() {
    let env = Env::new("n5b");
    let recv = env.spawn(&[]);
    let e1 = asset_e(1, 6, 5, C + 1);
    let mut ph = Phone::connect(&recv);
    let need = ph.manifest(&[&e1]);
    ph.transfer(&e1, &need);
    drop(ph);
    // N6: same modified → have.
    let mut ph = Phone::connect(&recv);
    assert_eq!(ph.manifest(&[&e1]).have, vec!["E".to_string()]);
    drop(ph);
    // N5b: modified changed, AAE unchanged → only the AAE, no NEED_MORE.
    let e2 = asset_e(2, 6, 5, C + 1);
    let mut ph = Phone::connect(&recv);
    let need = ph.manifest(&[&e2]);
    assert_eq!(want_of(&need, "E"), wants(&[("adjustment_data#0", 0)]));
    ph.send_res(0, &e2, "adjustment_data#0", 0);
    ph.asset_end(&e2, e2.keys(), true, None);
    assert_eq!(ph.ack().status, "durable");
    drop(ph);
    // N5c: render size changed → both wanted directly.
    let e3 = asset_e(3, 6, 25, C + 2);
    let mut ph = Phone::connect(&recv);
    let need = ph.manifest(&[&e3]);
    assert_eq!(want_of(&need, "E"), wants(&[("full_size_photo#0", 0), ("adjustment_data#0", 0)]));
}

#[test]
fn n7_name_collisions() {
    // (a) + (d): sequential, suffix shared by both of B's resources, stable afterwards.
    let env = Env::new("n7a");
    let recv = env.spawn(&[]);
    let (p, b) = (asset_p(), asset_b());
    let mut ph = Phone::connect(&recv);
    let need = ph.manifest(&[&p]);
    ph.transfer(&p, &need);
    let need = ph.manifest(&[&b]);
    ph.transfer(&b, &need);
    assert_eq!(read(&env.file(&format!("{DIR}/20240314_111522_img_0001_2.HEIC"))), b.res("photo#0").data);
    assert_eq!(read(&env.file(&format!("{DIR}/20240314_111522_img_0001_2.MOV"))), b.res("paired_video#0").data);
    drop(ph);
    let mut ph = Phone::connect(&recv);
    assert_eq!(ph.manifest(&[&b]).have, vec!["B".to_string()]);
    drop(ph);
    drop(recv);

    // (b) concurrent: the first RES_BEGIN wins.
    let env = Env::new("n7b");
    let recv = env.spawn(&[]);
    let mut ph = Phone::connect(&recv);
    ph.manifest(&[&p, &b]);
    ph.begin(0, &b, "photo#0", 0);
    ph.begin(1, &p, "photo#0", 0);
    ph.sync();
    drop(ph);
    recv.after_session_kill();
    assert_eq!(env.base_rel("B"), format!("{DIR}/20240314_111522_img_0001"));
    assert_eq!(env.base_rel("P"), format!("{DIR}/20240314_111522_IMG_0001_2"));

    // (c) a user's file is never overwritten.
    let env = Env::new("n7c");
    std::fs::create_dir_all(env.dest().join(DIR)).unwrap();
    std::fs::write(env.file(P_REL), b"user data").unwrap();
    let recv = env.spawn(&[]);
    let mut ph = Phone::connect(&recv);
    let need = ph.manifest(&[&p]);
    ph.transfer(&p, &need);
    assert_eq!(read(&env.file(P_REL)), b"user data");
    assert_eq!(read(&env.file(&format!("{DIR}/20240314_111522_IMG_0001_2.HEIC"))), p.res("photo#0").data);
}

#[test]
fn n8_orphaning_keeps_files() {
    let env = Env::new("n8");
    let recv = env.spawn(&[]);
    let e1 = asset_e(1, 6, 5, C + 1);
    let mut ph = Phone::connect(&recv);
    let need = ph.manifest(&[&e1]);
    ph.transfer(&e1, &need);
    drop(ph);
    let mut reverted = e1.clone();
    reverted.modified = 3;
    reverted.res.truncate(1);
    let mut ph = Phone::connect(&recv);
    assert_eq!(ph.manifest(&[&reverted]).have, vec!["E".to_string()]);
    drop(ph);
    recv.after_session_kill();
    assert_eq!(env.row("E", "full_size_photo#0").unwrap().0, "orphaned");
    assert_eq!(env.row("E", "adjustment_data#0").unwrap().0, "orphaned");
    assert!(env.file(&format!("{DIR}/20240314_111522_IMG_0003_edited.HEIC")).exists());
    assert!(env.file(&format!("{DIR}/20240314_111522_IMG_0003.AAE")).exists());
}

#[test]
fn n10_supersede_commits_exact_offset_before_next_need() {
    let env = Env::new("n10");
    let recv = env.spawn(&[]);
    let p = asset_p();
    let mut s1 = Phone::connect(&recv);
    s1.manifest(&[&p]);
    s1.send_upto(0, &p, "photo#0", 0, 2 * C + 3 * K);
    s1.sync();
    let mut s2 = Phone::connect(&recv);
    let bye: Bye = s1.expect(FrameType::Bye);
    assert_eq!(bye.code, "superseded");
    let need = s2.manifest(&[&p]);
    assert_eq!(want_of(&need, "P"), wants(&[("photo#0", 2 * C + 3 * K)]), "exact, not checkpoint-rounded");
    // Late DATA on the dead session is never written.
    let _ = s1.s.write_all(&[0u8; 64]);
    s2.transfer(&p, &need);
    assert_eq!(sha(&read(&env.file(P_REL))), sha(&p.res("photo#0").data));
}

#[test]
fn n11_disconnect_mid_resource() {
    let env = Env::new("n11");
    let p = asset_p();
    {
        let recv = env.spawn(&[]);
        let mut ph = Phone::connect(&recv);
        ph.manifest(&[&p]);
        ph.send_upto(0, &p, "photo#0", 0, 2 * C + 3 * K);
        ph.sync();
        drop(ph);
        recv.after_session_kill();
    }
    assert_eq!(env.row("P", "photo#0").unwrap().1, 2 * C + 3 * K);
    let recv = env.spawn(&[]);
    let mut ph = Phone::connect(&recv);
    let need = ph.manifest(&[&p]);
    assert_eq!(want_of(&need, "P"), wants(&[("photo#0", 2 * C + 3 * K)]));
    ph.transfer(&p, &need);
}

#[test]
fn n13_protocol_violations() {
    let env = Env::new("n13");
    let recv = env.spawn(&[]);
    let (p, l) = (asset_p(), asset_l());
    type Case = Box<dyn Fn(&mut Phone)>;
    let cases: Vec<(&str, Case)> = vec![
        ("a key not wanted", Box::new(|ph: &mut Phone| {
            ph.manifest(&[&asset_p()]);
            ph.send_json(FrameType::ResBegin, &ResBegin { slot: 0, id: "P".into(), key: "paired_video#0".into(), offset: 0, size: 1 });
        })),
        ("b busy slot", Box::new(|ph: &mut Phone| {
            let l = asset_l();
            ph.manifest(&[&l]);
            ph.begin(0, &l, "photo#0", 0);
            ph.begin(0, &l, "paired_video#0", 0);
        })),
        ("c DATA on free slot", Box::new(|ph: &mut Phone| {
            ph.manifest(&[&asset_p()]);
            ph.send(Frame::data(&DataChunk { slot: 3, offset: 0, bytes: vec![0u8; 4].into() }));
        })),
        ("d slot out of range", Box::new(|ph: &mut Phone| {
            let p = asset_p();
            ph.manifest(&[&p]);
            ph.begin(8, &p, "photo#0", 0);
        })),
        ("e page out of order", Box::new(|ph: &mut Phone| {
            ph.manifest(&[&asset_p()]);
            ph.page = 5;
            let m = Manifest {
                job: Job { job_id: ph.job.clone(), label: "t".into(), section: "photos".into(), mode: "copy".into() },
                page: 5,
                last: false,
                assets: vec![asset_l().wire()],
            };
            ph.send_json(FrameType::Manifest, &m);
        })),
        ("f same asset in two pages", Box::new(|ph: &mut Phone| {
            ph.manifest(&[&asset_p()]);
            let m = Manifest {
                job: Job { job_id: ph.job.clone(), label: "t".into(), section: "photos".into(), mode: "copy".into() },
                page: 1,
                last: false,
                assets: vec![asset_p().wire()],
            };
            ph.send_json(FrameType::Manifest, &m);
        })),
    ];
    let _ = (&p, &l);
    for (name, case) in cases {
        let mut ph = Phone::connect(&recv);
        case(&mut ph);
        let f = ph.next(Duration::from_secs(5)).unwrap_or_else(|| panic!("{name}: closed without BYE"));
        assert_eq!(f.ty, FrameType::Bye, "{name}: {}", String::from_utf8_lossy(&f.payload));
        assert!(String::from_utf8_lossy(&f.payload).contains("protocol_error"), "{name}");
    }
}

#[test]
fn n14_asset_end_with_unfinished_keys() {
    let env = Env::new("n14");
    let recv = env.spawn(&[]);
    let p = asset_p();
    let mut ph = Phone::connect(&recv);
    ph.manifest(&[&p]);
    ph.asset_end(&p, vec!["photo#0".into(), "paired_video#0".into()], true, None);
    let ack = ph.ack();
    assert_eq!(ack.status, "failed");
    let failed: Vec<(String, String)> = ack.failed.unwrap().into_iter().map(|f| (f.key, f.why)).collect();
    assert_eq!(failed, vec![("photo#0".into(), "missing".into()), ("paired_video#0".into(), "missing".into())]);
}

#[test]
fn n15_final_deleted_by_user_is_resent_to_same_path() {
    let env = Env::new("n15");
    let recv = env.spawn(&[]);
    let p = asset_p();
    let mut ph = Phone::connect(&recv);
    let need = ph.manifest(&[&p]);
    ph.transfer(&p, &need);
    drop(ph);
    std::fs::remove_file(env.file(P_REL)).unwrap();
    let mut ph = Phone::connect(&recv);
    let need = ph.manifest(&[&p]);
    assert_eq!(want_of(&need, "P"), wants(&[("photo#0", 0)]));
    ph.transfer(&p, &need);
    assert_eq!(read(&env.file(P_REL)), p.res("photo#0").data);
}

#[test]
fn n17_one_receiver_per_destination() {
    let env = Env::new("n17");
    let _recv = env.spawn(&[]);
    let t = Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_iostransfer"))
        .arg("--config")
        .arg(env.root.join("cfg"))
        .args(["receive", "--insecure-dev", "--port", "0", "--dest"])
        .arg(env.dest())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(t.elapsed() < Duration::from_secs(1), "took {:?}", t.elapsed());
    assert!(String::from_utf8_lossy(&out.stderr).contains("another iostransfer is already using"));
    assert!(!env.dest().join(".iostransfer/index.db-shm").exists());
}

/// N7(e): a base reserved by an asset whose files are gone (aborted not_local) still blocks
/// another asset: the DB check alone must catch the case-insensitive collision.
#[test]
fn n7e_reserved_base_without_files_still_collides() {
    let env = Env::new("n7e");
    let recv = env.spawn(&[]);
    let (p, b) = (asset_p(), asset_b());
    let mut ph = Phone::connect(&recv);
    ph.manifest(&[&b, &p]);
    ph.send_upto(0, &b, "photo#0", 0, K);
    ph.send_json(FrameType::ResAbort, &ResAbort { slot: 0, why: "not_local".into() });
    ph.asset_end(&b, b.keys(), false, Some("not_local"));
    assert_eq!(ph.ack().status, "failed");
    assert!(std::fs::read_dir(env.dest().join(DIR)).unwrap().next().is_none(), "no files left for B");
    ph.send_res(0, &p, "photo#0", 0);
    ph.asset_end(&p, p.keys(), true, None);
    assert_eq!(ph.ack().status, "durable");
    drop(ph);
    recv.after_session_kill();
    assert_eq!(env.base_rel("B"), format!("{DIR}/20240314_111522_img_0001"));
    assert_eq!(env.base_rel("P"), format!("{DIR}/20240314_111522_IMG_0001_2"));
}

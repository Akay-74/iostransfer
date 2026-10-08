//! Preface, version negotiation, pairing and HMAC auth (PROTOCOL §1.2, §3, §4).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::future::BoxFuture;
use futures_util::{SinkExt, StreamExt};
use iost_proto::msg::{self, Bye, Challenge, Hello, HelloAuth, Paired, ProtoRange, Welcome};
use iost_proto::{auth, Frame, FrameCodec, FrameType, PREFACE};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{timeout, timeout_at, Instant};
use tokio_util::codec::Framed;

use crate::{lock, DeviceDb, Index};

pub const SUPPORTED: ProtoRange = ProtoRange { min: 1, max: 1 };
const PREFACE_TIMEOUT: Duration = Duration::from_secs(10);
/// HELLO → WELCOME, including CHALLENGE/AUTH (PROTOCOL §7.3).
const AUTH_TIMEOUT: Duration = Duration::from_secs(15);
/// Pairing allows time for the y/N prompt on the PC (THREAT_MODEL N11).
const PAIR_TIMEOUT: Duration = Duration::from_secs(60);
/// Outgoing BYE on a failing connection: never wait longer than this (PROTOCOL §6.5).
const BYE_TIMEOUT: Duration = Duration::from_secs(2);
/// More PINGs than this before WELCOME is a flood.
const MAX_HANDSHAKE_PINGS: u32 = 16;
pub const TOKEN_TTL: Duration = Duration::from_secs(600);
const MAX_DEVICE_NAME: usize = 100;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_slots: u32,
    pub max_unacked_assets: u32,
    pub max_unacked_bytes: u64,
    /// fsync `.part` + commit `durable_offset` every this many bytes (PROTOCOL §9.1).
    pub checkpoint_bytes: u64,
    /// Free space that must remain after a resource is written (§6.3 disk_full).
    pub reserve_bytes: u64,
    /// No inbound frame for this long means the phone is gone (PROTOCOL §6.5).
    pub peer_silence: Duration,
    /// Send a PING after this long without outbound frames (PROTOCOL §6.5).
    pub ping_after: Duration,
    /// Writer blocked this long → PAUSE{disk_slow} (PROTOCOL Δ15).
    pub disk_slow_after: Duration,
    /// Free-space re-check interval while PAUSEd for disk_low.
    pub free_poll: Duration,
    /// Write XMP sidecars in copy jobs too (`--xmp`); move jobs always write them.
    pub xmp_always: bool,
    /// VERIFY re-hashes every file instead of trusting the stored hash (`--paranoid`).
    pub paranoid: bool,
    /// Test hook: stall this long at the first checkpoint fsync (WRITER_TESTS N12).
    pub test_slow_writer: Option<Duration>,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_slots: 8,
            max_unacked_assets: 64,
            max_unacked_bytes: 2 << 30,
            checkpoint_bytes: 64 << 20,
            reserve_bytes: 1 << 30,
            peer_silence: Duration::from_secs(30),
            ping_after: Duration::from_secs(10),
            disk_slow_after: Duration::from_secs(20),
            free_poll: Duration::from_secs(5),
            xmp_always: false,
            paranoid: false,
            test_slow_writer: None,
        }
    }
}

/// Per-device session bookkeeping for supersede (PROTOCOL §4.2, §9.3).
#[derive(Default)]
pub struct DeviceSessions {
    /// Held by the live session until its writer has shut down.
    pub lock: Arc<tokio::sync::Mutex<()>>,
    /// Signals the live session that a newer one replaced it.
    pub cancel: Option<tokio::sync::watch::Sender<bool>>,
}

/// Shown to the user before a pairing is accepted.
#[derive(Debug, Clone)]
pub struct PairRequest {
    pub device_id: String,
    pub device_name: String,
    pub peer: String,
}

pub type ConfirmPair = Arc<dyn Fn(PairRequest) -> BoxFuture<'static, bool> + Send + Sync>;

pub struct Ctx {
    pub devices: Mutex<DeviceDb>,
    pub index: Mutex<Index>,
    /// Destination root for received files.
    pub dest: std::path::PathBuf,
    pub sessions: Mutex<HashMap<String, DeviceSessions>>,
    pub pc_id: String,
    pub pc_name: String,
    pub limits: Limits,
    /// One-time pairing tokens (lowercase hex) → expiry.
    pub tokens: Mutex<HashMap<String, Instant>>,
    pub free_bytes: Arc<dyn Fn() -> u64 + Send + Sync>,
    pub confirm_pair: ConfirmPair,
}

impl Ctx {
    /// Create a pairing token valid for [`TOKEN_TTL`].
    pub fn new_token(&self) -> String {
        let token = hex::encode(random::<16>());
        lock(&self.tokens).insert(token.clone(), Instant::now() + TOKEN_TTL);
        token
    }

    /// Atomically take a token, so two connections can never both pair with it.
    fn take_token(&self, token: &str) -> Option<Instant> {
        let mut tokens = lock(&self.tokens);
        tokens.retain(|_, exp| *exp > Instant::now());
        tokens.remove(token)
    }

    /// Give a token back after a failed attempt, so the phone can retry with the same QR (PROTOCOL §4.1).
    fn return_token(&self, token: String, expiry: Instant) {
        if expiry > Instant::now() {
            lock(&self.tokens).insert(token, expiry);
        }
    }
}

pub struct Established<S> {
    pub framed: Framed<S, FrameCodec>,
    pub proto: u32,
    pub device_id: String,
    pub device_name: String,
    pub session_id: String,
    /// True when this session was a pairing (the device was just added).
    pub newly_paired: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("peer sent a wrong preface")]
    BadPreface,
    #[error("handshake timed out")]
    Timeout,
    #[error("connection closed")]
    Closed,
    #[error("rejected peer with BYE {0}")]
    Rejected(String),
    #[error("peer said BYE {0}")]
    PeerBye(String),
    #[error(transparent)]
    Frame(#[from] iost_proto::FrameError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("OS random source");
    b
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Run the receiver side of the handshake.
///
/// `peer` identifies the remote end for rate limiting (an IP address, or a fixed key for USB).
/// `tls` must be true only when the transport is pinned TLS: pairing over a plain transport is
/// refused (PROTOCOL §4.1).
pub async fn handshake<S>(mut io: S, ctx: &Ctx, peer: &str, tls: bool) -> Result<Established<S>, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let start = Instant::now();
    io.write_all(&PREFACE).await?;
    let mut preface = [0u8; 8];
    match timeout(PREFACE_TIMEOUT, io.read_exact(&mut preface)).await {
        Err(_) => return Err(HandshakeError::Timeout),
        Ok(Err(_)) => return Err(HandshakeError::Closed),
        Ok(Ok(_)) if preface != PREFACE => return Err(HandshakeError::BadPreface),
        Ok(Ok(_)) => {}
    }
    let mut hs = Hs { framed: Framed::new(io, FrameCodec), pings: 0 };

    let hello = match timeout_at(start + AUTH_TIMEOUT, hs.recv::<Hello>(FrameType::Hello)).await {
        Err(_) => return hs.fail_timeout().await,
        Ok(r) => r?,
    };
    let Some(proto) = msg::negotiate(SUPPORTED, hello.proto) else {
        let b = Bye { min: Some(SUPPORTED.min), max: Some(SUPPORTED.max), ..Bye::code("version_unsupported") };
        return hs.reject(b).await;
    };
    let Some(device_id) = valid_device_id(&hello.device_id) else {
        return hs.reject(Bye::code("protocol_error")).await;
    };
    let device_name = clean_device_name(&hello.device_name);
    let welcome = Welcome {
        proto,
        pc_id: ctx.pc_id.clone(),
        pc_name: ctx.pc_name.clone(),
        session_id: uuid::Uuid::new_v4().to_string(),
        store_id: lock(&ctx.index).store_id()?,
        device_secret: None,
        paired: None,
        max_slots: ctx.limits.max_slots,
        max_unacked_assets: ctx.limits.max_unacked_assets,
        max_unacked_bytes: ctx.limits.max_unacked_bytes,
        free_bytes: (ctx.free_bytes)(),
    };
    let session_id = welcome.session_id.clone();

    let newly_paired = matches!(hello.auth, HelloAuth::Pair { .. });
    let result = match hello.auth {
        HelloAuth::Pair { token } => {
            if !tls {
                return hs.reject(Bye::code("auth_failed")).await;
            }
            let Some(expiry) = is_token(&token).then(|| ctx.take_token(&token)).flatten() else {
                return hs.reject(Bye::code("token_invalid")).await;
            };
            let req = PairRequest { device_id: device_id.clone(), device_name: device_name.clone(), peer: peer.into() };
            let r = timeout_at(start + PAIR_TIMEOUT, hs.pair(ctx, req, welcome)).await;
            if !matches!(r, Ok(Ok(()))) {
                ctx.return_token(token, expiry);
            }
            r
        }
        HelloAuth::Secret { s_nonce } => {
            let Some(s_nonce) = hex32(&s_nonce) else {
                return hs.reject(Bye::code("protocol_error")).await;
            };
            // Unknown devices and bad proofs both count as failed auth for rate limiting (THREAT_MODEL N4).
            let device = lock(&ctx.devices).get(&device_id)?;
            let Some(device) = device else {
                return hs.reject(Bye::code("unknown_device")).await;
            };
            timeout_at(start + AUTH_TIMEOUT, hs.authenticate(&device.secret, s_nonce, welcome)).await
        }
    };
    match result {
        Err(_) => hs.fail_timeout().await,
        Ok(Err(e)) => Err(e),
        Ok(Ok(())) => Ok(Established { framed: hs.framed, proto, device_id, device_name, session_id, newly_paired }),
    }
}

/// `device_id` must be a UUID; returned in canonical lowercase form.
fn valid_device_id(s: &str) -> Option<String> {
    uuid::Uuid::parse_str(s).ok().map(|u| u.hyphenated().to_string())
}

/// Strip control characters and cap at [`MAX_DEVICE_NAME`] bytes on a char boundary.
/// (It still goes through the path sanitiser before it is ever used as a folder name.)
fn clean_device_name(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars().filter(|&c| !crate::text::is_deceptive(c)) {
        if out.len() + c.len_utf8() > MAX_DEVICE_NAME {
            break;
        }
        out.push(c);
    }
    let out = out.trim().to_string();
    if out.is_empty() { "iPhone".into() } else { out }
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_token(s: &str) -> bool {
    is_lower_hex(s, 32)
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if !is_lower_hex(s, 64) {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

struct Hs<S> {
    framed: Framed<S, FrameCodec>,
    pings: u32,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Hs<S> {
    async fn pair(&mut self, ctx: &Ctx, req: PairRequest, mut welcome: Welcome) -> Result<(), HandshakeError> {
        let (device_id, device_name) = (req.device_id.clone(), req.device_name.clone());
        if !(ctx.confirm_pair)(req).await {
            return self.reject(Bye::code("auth_failed")).await;
        }
        // Two-phase pairing (Δ3): the secret is committed only after PAIRED.
        let secret = random::<32>();
        welcome.device_secret = Some(hex::encode(secret));
        welcome.paired = Some(true);
        self.send(FrameType::Welcome, &welcome).await?;
        let _: Paired = self.recv(FrameType::Paired).await?;
        lock(&ctx.devices).put(&device_id, &device_name, &secret, now_ms())?;
        Ok(())
    }

    async fn authenticate(&mut self, secret: &[u8; 32], s_nonce: [u8; 32], welcome: Welcome) -> Result<(), HandshakeError> {
        let r_nonce = random::<32>();
        if r_nonce == s_nonce {
            // Reflection guard; astronomically unlikely unless the peer is replaying our nonce.
            return self.reject(Bye::code("auth_failed")).await;
        }
        let r_proof = auth::r_proof(secret, &s_nonce, &r_nonce);
        let challenge = Challenge { proto: welcome.proto, r_nonce: hex::encode(r_nonce), r_proof: hex::encode(r_proof) };
        self.send(FrameType::Challenge, &challenge).await?;
        let reply: msg::Auth = self.recv(FrameType::Auth).await?;
        let expected = auth::s_proof(secret, &s_nonce, &r_nonce);
        if !hex32(&reply.s_proof).is_some_and(|p| auth::proof_eq(&p, &expected)) {
            return self.reject(Bye::code("auth_failed")).await;
        }
        self.send(FrameType::Welcome, &welcome).await
    }

    async fn send<T: serde::Serialize>(&mut self, ty: FrameType, msg: &T) -> Result<(), HandshakeError> {
        self.framed.send(Frame::json(ty, msg)).await?;
        Ok(())
    }

    /// Best-effort BYE that can never hang the task.
    async fn bye(&mut self, b: Bye) {
        let _ = timeout(BYE_TIMEOUT, self.send(FrameType::Bye, &b)).await;
    }

    async fn reject<T>(&mut self, b: Bye) -> Result<T, HandshakeError> {
        let code = b.code.clone();
        self.bye(b).await;
        Err(HandshakeError::Rejected(code))
    }

    async fn fail_timeout<T>(&mut self) -> Result<T, HandshakeError> {
        self.bye(Bye::code("timeout")).await;
        Err(HandshakeError::Timeout)
    }

    /// Receive the next handshake frame, which must be `want` (PING is answered, BYE ends it).
    async fn recv<T: serde::de::DeserializeOwned>(&mut self, want: FrameType) -> Result<T, HandshakeError> {
        loop {
            let frame = self.framed.next().await.ok_or(HandshakeError::Closed)??;
            match frame.ty {
                FrameType::Ping => {
                    self.pings += 1;
                    if self.pings > MAX_HANDSHAKE_PINGS {
                        return self.reject(Bye::code("protocol_error")).await;
                    }
                    self.framed.send(Frame { ty: FrameType::Pong, payload: frame.payload }).await?;
                }
                FrameType::Pong => {}
                FrameType::Bye => {
                    let b: Option<Bye> = serde_json::from_slice(&frame.payload).ok();
                    return Err(HandshakeError::PeerBye(b.map(|b| b.code).unwrap_or_default()));
                }
                ty if ty == want => {
                    return match serde_json::from_slice(&frame.payload) {
                        Ok(v) => Ok(v),
                        Err(_) => self.reject(Bye::code("protocol_error")).await,
                    };
                }
                _ => return self.reject(Bye::code("protocol_error")).await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_name_is_cleaned_and_capped() {
        assert_eq!(clean_device_name("Ana's\u{0007} iPhone\n"), "Ana's iPhone");
        assert_eq!(clean_device_name("\u{0}\u{1}"), "iPhone");
        assert_eq!(clean_device_name("\u{202E}enohPi"), "enohPi");
        let long = "📷".repeat(40); // 160 bytes
        let c = clean_device_name(&long);
        assert!(c.len() <= MAX_DEVICE_NAME && c.chars().all(|ch| ch == '📷'));
    }

    #[test]
    fn hex_is_strict_lowercase() {
        assert!(hex32(&"ab".repeat(32)).is_some());
        assert!(hex32(&"AB".repeat(32)).is_none());
        assert!(hex32(&"ab".repeat(31)).is_none());
        assert!(is_token(&"0f".repeat(16)) && !is_token("nope"));
    }

    #[test]
    fn device_id_must_be_uuid() {
        assert!(valid_device_id("0B7C1C1E-3F7A-4C8E-9A51-2A3B4C5D6E7F").is_some_and(|s| s == "0b7c1c1e-3f7a-4c8e-9a51-2a3b4c5d6e7f"));
        assert!(valid_device_id("dev-1").is_none());
    }
}

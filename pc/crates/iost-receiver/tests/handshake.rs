//! Receiver handshake against a simulated phone over an in-memory pipe.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{FutureExt, SinkExt, StreamExt};
use iost_proto::msg::{Auth, Bye, Challenge, Hello, HelloAuth, Paired, ProtoRange, Welcome};
use iost_proto::{auth, Frame, FrameCodec, FrameType, PREFACE};
use iost_receiver::{handshake, Ctx, DeviceDb, HandshakeError, Index, Limits};
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_util::codec::Framed;

const DEV: &str = "0b7c1c1e-3f7a-4c8e-9a51-2a3b4c5d6e7f";
const V1: ProtoRange = ProtoRange { min: 1, max: 1 };

fn ctx_with(approve: Arc<AtomicBool>) -> Arc<Ctx> {
    Arc::new(Ctx {
        devices: Mutex::new(DeviceDb::open_in_memory().unwrap()),
        index: Mutex::new(Index::open_in_memory().unwrap()),
        dest: std::env::temp_dir(),
        sessions: Mutex::new(HashMap::new()),
        pc_id: "pc-1".into(),
        pc_name: "test-pc".into(),
        limits: Limits::default(),
        tokens: Mutex::new(HashMap::new()),
        free_bytes: Arc::new(|| 1 << 40),
        confirm_pair: Arc::new(move |_| {
            let ok = approve.load(Ordering::SeqCst);
            async move { ok }.boxed()
        }),
    })
}

fn ctx() -> Arc<Ctx> {
    ctx_with(Arc::new(AtomicBool::new(true)))
}

type Phone = Framed<DuplexStream, FrameCodec>;
type Task = tokio::task::JoinHandle<Result<String, HandshakeError>>;

async fn connect_buf(ctx: &Arc<Ctx>, tls: bool, buf: usize) -> (Phone, Task) {
    let (pc_side, mut phone) = duplex(buf);
    let c = ctx.clone();
    let task = tokio::spawn(async move { handshake(pc_side, &c, "test", tls).await.map(|e| e.device_id) });
    phone.write_all(&PREFACE).await.unwrap();
    let mut p = [0u8; 8];
    phone.read_exact(&mut p).await.unwrap();
    assert_eq!(p, PREFACE);
    (Framed::new(phone, FrameCodec), task)
}

async fn connect(ctx: &Arc<Ctx>, tls: bool) -> (Phone, Task) {
    connect_buf(ctx, tls, 1 << 20).await
}

fn hello_from(device_id: &str, auth: HelloAuth, proto: ProtoRange) -> Frame {
    Frame::json(
        FrameType::Hello,
        &Hello {
            proto,
            device_id: device_id.into(),
            device_name: "Test iPhone".into(),
            app_version: "0.1.0".into(),
            os: "iOS 19".into(),
            auth,
        },
    )
}

fn hello(auth: HelloAuth, proto: ProtoRange) -> Frame {
    hello_from(DEV, auth, proto)
}

async fn expect<T: serde::de::DeserializeOwned>(phone: &mut Phone, ty: FrameType) -> T {
    let f = phone.next().await.unwrap().unwrap();
    assert_eq!(f.ty, ty, "payload: {}", String::from_utf8_lossy(&f.payload));
    serde_json::from_slice(&f.payload).unwrap()
}

/// Pair and return the device secret the phone stored.
async fn pair(ctx: &Arc<Ctx>) -> [u8; 32] {
    let token = ctx.new_token();
    let (mut phone, task) = connect(ctx, true).await;
    phone.send(hello(HelloAuth::Pair { token }, V1)).await.unwrap();
    let w: Welcome = expect(&mut phone, FrameType::Welcome).await;
    assert_eq!(w.paired, Some(true));
    assert_eq!(w.store_id, ctx.index.lock().unwrap().store_id().unwrap());
    let secret: [u8; 32] = hex::decode(w.device_secret.unwrap()).unwrap().try_into().unwrap();
    phone.send(Frame::json(FrameType::Paired, &Paired {})).await.unwrap();
    assert_eq!(task.await.unwrap().unwrap(), DEV);
    assert!(ctx.tokens.lock().unwrap().is_empty(), "token must be consumed");
    secret
}

#[tokio::test]
async fn pair_then_authenticate() {
    let ctx = ctx();
    let secret = pair(&ctx).await;
    assert!(ctx.devices.lock().unwrap().get(DEV).unwrap().is_some());

    let (mut phone, task) = connect(&ctx, true).await;
    let s_nonce = [7u8; 32];
    phone.send(hello(HelloAuth::Secret { s_nonce: hex::encode(s_nonce) }, V1)).await.unwrap();
    let ch: Challenge = expect(&mut phone, FrameType::Challenge).await;
    let r_nonce: [u8; 32] = hex::decode(&ch.r_nonce).unwrap().try_into().unwrap();
    assert_eq!(hex::encode(auth::r_proof(&secret, &s_nonce, &r_nonce)), ch.r_proof, "phone authenticates PC");
    let s_proof = auth::s_proof(&secret, &s_nonce, &r_nonce);
    phone.send(Frame::json(FrameType::Auth, &Auth { s_proof: hex::encode(s_proof) })).await.unwrap();
    let w: Welcome = expect(&mut phone, FrameType::Welcome).await;
    assert_eq!(w.device_secret, None, "secret is never resent after pairing");
    assert_eq!(task.await.unwrap().unwrap(), DEV);
}

#[tokio::test]
async fn wrong_proof_is_rejected() {
    let ctx = ctx();
    pair(&ctx).await;
    let (mut phone, task) = connect(&ctx, true).await;
    phone.send(hello(HelloAuth::Secret { s_nonce: hex::encode([7u8; 32]) }, V1)).await.unwrap();
    let _: Challenge = expect(&mut phone, FrameType::Challenge).await;
    phone.send(Frame::json(FrameType::Auth, &Auth { s_proof: hex::encode([0u8; 32]) })).await.unwrap();
    let b: Bye = expect(&mut phone, FrameType::Bye).await;
    assert_eq!(b.code, "auth_failed");
    assert!(matches!(task.await.unwrap(), Err(HandshakeError::Rejected(c)) if c == "auth_failed"));
}

#[tokio::test]
async fn rejections() {
    let ctx = ctx();
    let token = ctx.new_token();
    let cases = [
        (true, DEV, HelloAuth::Secret { s_nonce: hex::encode([1u8; 32]) }, V1, "unknown_device"),
        (true, DEV, HelloAuth::Pair { token: "nope".into() }, V1, "token_invalid"),
        (true, DEV, HelloAuth::Pair { token: token.to_uppercase() }, V1, "token_invalid"),
        (false, DEV, HelloAuth::Pair { token: token.clone() }, V1, "auth_failed"),
        (true, DEV, HelloAuth::Pair { token: token.clone() }, ProtoRange { min: 2, max: 3 }, "version_unsupported"),
        (true, "not-a-uuid", HelloAuth::Pair { token: token.clone() }, V1, "protocol_error"),
        (true, DEV, HelloAuth::Secret { s_nonce: "AB".repeat(32) }, V1, "protocol_error"),
    ];
    for (tls, dev, a, proto, code) in cases {
        let (mut phone, task) = connect(&ctx, tls).await;
        phone.send(hello_from(dev, a, proto)).await.unwrap();
        let b: Bye = expect(&mut phone, FrameType::Bye).await;
        assert_eq!(b.code, code);
        assert!(task.await.unwrap().is_err());
    }
    assert!(ctx.tokens.lock().unwrap().contains_key(&token), "rejected attempts never burn a valid token");
}

#[tokio::test]
async fn token_race_only_one_pairs() {
    let ctx = ctx();
    let token = ctx.new_token();
    let (mut a, ta) = connect(&ctx, true).await;
    let (mut b, tb) = connect(&ctx, true).await;
    a.send(hello(HelloAuth::Pair { token: token.clone() }, V1)).await.unwrap();
    let _: Welcome = expect(&mut a, FrameType::Welcome).await; // `a` holds the token now
    b.send(hello(HelloAuth::Pair { token: token.clone() }, V1)).await.unwrap();
    let bye: Bye = expect(&mut b, FrameType::Bye).await;
    assert_eq!(bye.code, "token_invalid");
    assert!(tb.await.unwrap().is_err());
    a.send(Frame::json(FrameType::Paired, &Paired {})).await.unwrap();
    assert!(ta.await.unwrap().is_ok());
}

#[tokio::test]
async fn pairing_dropped_before_paired_commits_nothing_and_returns_token() {
    let ctx = ctx();
    let token = ctx.new_token();
    let (mut phone, task) = connect(&ctx, true).await;
    phone.send(hello(HelloAuth::Pair { token: token.clone() }, V1)).await.unwrap();
    let _: Welcome = expect(&mut phone, FrameType::Welcome).await;
    assert!(ctx.tokens.lock().unwrap().is_empty(), "token is held while pairing");
    drop(phone);
    assert!(task.await.unwrap().is_err());
    assert!(ctx.devices.lock().unwrap().get(DEV).unwrap().is_none());
    assert!(ctx.tokens.lock().unwrap().contains_key(&token), "token stays valid for a retry");
}

#[tokio::test]
async fn declined_pairing() {
    let approve = Arc::new(AtomicBool::new(false));
    let ctx = ctx_with(approve);
    let token = ctx.new_token();
    let (mut phone, task) = connect(&ctx, true).await;
    phone.send(hello(HelloAuth::Pair { token: token.clone() }, V1)).await.unwrap();
    let b: Bye = expect(&mut phone, FrameType::Bye).await;
    assert_eq!(b.code, "auth_failed");
    assert!(task.await.unwrap().is_err());
    assert!(ctx.devices.lock().unwrap().get(DEV).unwrap().is_none());
}

#[tokio::test]
async fn ping_flood_is_cut_off() {
    let ctx = ctx();
    let (mut phone, task) = connect(&ctx, true).await;
    for n in 0..40 {
        phone.send(Frame::json(FrameType::Ping, &serde_json::json!({ "n": n }))).await.unwrap();
    }
    let mut last = None;
    while let Some(Ok(f)) = phone.next().await {
        last = Some(f);
    }
    let last = last.unwrap();
    assert_eq!(last.ty, FrameType::Bye);
    assert!(matches!(task.await.unwrap(), Err(HandshakeError::Rejected(c)) if c == "protocol_error"));
}

/// A peer that floods without ever reading must not hang the handshake task
/// (the 15 s deadline fires, then the BYE gives up after 2 s).
#[tokio::test(start_paused = true)]
async fn non_reading_peer_cannot_hang_the_task() {
    let ctx = ctx();
    let (phone, task) = connect_buf(&ctx, true, 64).await;
    let (_reader, mut writer) = tokio::io::split(phone.into_inner());
    let ping = {
        let mut b = bytes::BytesMut::new();
        tokio_util::codec::Encoder::encode(&mut FrameCodec, Frame::json(FrameType::Ping, &serde_json::json!({"n":1})), &mut b).unwrap();
        b
    };
    for _ in 0..8 {
        let _ = tokio::time::timeout(Duration::from_millis(10), writer.write_all(&ping)).await;
    }
    let r = tokio::time::timeout(Duration::from_secs(30), task).await.expect("handshake task must finish");
    assert!(r.unwrap().is_err());
}

#[tokio::test]
async fn bad_preface_closes_without_bye() {
    let ctx = ctx();
    let (pc_side, mut phone) = duplex(4096);
    let c = ctx.clone();
    let task = tokio::spawn(async move { handshake(pc_side, &c, "test", true).await.map(|_| ()) });
    phone.write_all(b"GET / HT").await.unwrap();
    assert!(matches!(task.await.unwrap(), Err(HandshakeError::BadPreface)));
}

#[tokio::test(start_paused = true)]
async fn silent_peer_times_out() {
    let ctx = ctx();
    let (_phone, task) = connect(&ctx, true).await;
    assert!(matches!(task.await.unwrap(), Err(HandshakeError::Timeout)));
}

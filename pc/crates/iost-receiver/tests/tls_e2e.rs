//! End to end over real TCP + TLS: a client that pins the SPKI the way the iPhone does.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{FutureExt, SinkExt, StreamExt};
use iost_proto::msg::{Auth, Challenge, Hello, HelloAuth, Paired, ProtoRange, Welcome};
use iost_proto::{auth, Frame, FrameCodec, FrameType, PREFACE};
use iost_receiver::identity::{self, Identity, P256_SPKI_PREFIX};
use iost_receiver::server::{serve, OnSession};
use iost_receiver::{tls, Ctx, DeviceDb, Index, Limits};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_util::codec::Framed;

const DEV: &str = "0b7c1c1e-3f7a-4c8e-9a51-2a3b4c5d6e7f";

/// What the iPhone does: take the P-256 point out of the leaf, prepend the fixed prefix, hash, compare.
#[derive(Debug)]
struct PinVerifier {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(&self, leaf: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        let der = leaf.as_ref();
        let at = der.windows(26).position(|w| w == P256_SPKI_PREFIX).ok_or(rustls::Error::General("not P-256".into()))?;
        let spki = der.get(at..at + 91).ok_or(rustls::Error::General("short".into()))?;
        if <[u8; 32]>::from(Sha256::digest(spki)) == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("pin mismatch".into()))
        }
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 not allowed".into()))
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

fn connector(pin: [u8; 32], alpn: bool) -> TlsConnector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier { pin, provider }))
        .with_no_client_auth();
    if alpn {
        cfg.alpn_protocols = vec![tls::ALPN.to_vec()];
    }
    TlsConnector::from(Arc::new(cfg))
}

fn test_ctx(limits: Limits) -> Arc<Ctx> {
    Arc::new(Ctx {
        devices: Mutex::new(DeviceDb::open_in_memory().unwrap()),
        index: Mutex::new(Index::open_in_memory().unwrap()),
        dest: std::env::temp_dir(),
        sessions: Mutex::new(HashMap::new()),
        pc_id: "pc-1".into(),
        pc_name: "test-pc".into(),
        limits,
        tokens: Mutex::new(HashMap::new()),
        free_bytes: Arc::new(|| 1 << 40),
        confirm_pair: Arc::new(|_| async { true }.boxed()),
    })
}

async fn start() -> (std::net::SocketAddr, Arc<Ctx>, Identity) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let id = Identity::from_key(key).unwrap();
    let ctx = test_ctx(Limits::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let on_session: OnSession = Arc::new(|ctx, s| iost_receiver::session::run(ctx, s).boxed());
    tokio::spawn(serve(listener, ctx.clone(), Some(tls::acceptor(&id).unwrap()), on_session));
    (addr, ctx, id)
}

async fn dial(addr: std::net::SocketAddr, pin: [u8; 32], alpn: bool) -> std::io::Result<Framed<tokio_rustls::client::TlsStream<TcpStream>, FrameCodec>> {
    let tcp = TcpStream::connect(addr).await?;
    let ip = ServerName::IpAddress(addr.ip().into());
    let mut s = connector(pin, alpn).connect(ip, tcp).await?;
    s.write_all(&PREFACE).await?;
    let mut p = [0u8; 8];
    s.read_exact(&mut p).await?;
    assert_eq!(p, PREFACE);
    Ok(Framed::new(s, FrameCodec))
}

fn hello(auth: HelloAuth) -> Frame {
    let proto = ProtoRange { min: 1, max: 1 };
    Frame::json(FrameType::Hello, &Hello { proto, device_id: DEV.into(), device_name: "Phone".into(), app_version: "0".into(), os: "iOS".into(), auth })
}

async fn next<T: serde::de::DeserializeOwned>(f: &mut Framed<tokio_rustls::client::TlsStream<TcpStream>, FrameCodec>, ty: FrameType) -> T {
    let fr = f.next().await.unwrap().unwrap();
    assert_eq!(fr.ty, ty, "{}", String::from_utf8_lossy(&fr.payload));
    serde_json::from_slice(&fr.payload).unwrap()
}

#[tokio::test]
async fn pair_auth_and_ping_over_tls() {
    let (addr, ctx, id) = start().await;
    let mut f = dial(addr, id.pin(), true).await.unwrap();
    f.send(hello(HelloAuth::Pair { token: ctx.new_token() })).await.unwrap();
    let w: Welcome = next(&mut f, FrameType::Welcome).await;
    let secret: [u8; 32] = hex::decode(w.device_secret.unwrap()).unwrap().try_into().unwrap();
    f.send(Frame::json(FrameType::Paired, &Paired {})).await.unwrap();
    f.send(Frame::json(FrameType::Ping, &serde_json::json!({"n": 5}))).await.unwrap();
    let pong: serde_json::Value = next(&mut f, FrameType::Pong).await;
    assert_eq!(pong["n"], 5);

    let mut f = dial(addr, id.pin(), true).await.unwrap();
    let s_nonce = [9u8; 32];
    f.send(hello(HelloAuth::Secret { s_nonce: hex::encode(s_nonce) })).await.unwrap();
    let ch: Challenge = next(&mut f, FrameType::Challenge).await;
    let r_nonce: [u8; 32] = hex::decode(ch.r_nonce).unwrap().try_into().unwrap();
    let s_proof = auth::s_proof(&secret, &s_nonce, &r_nonce);
    f.send(Frame::json(FrameType::Auth, &Auth { s_proof: hex::encode(s_proof) })).await.unwrap();
    let _: Welcome = next(&mut f, FrameType::Welcome).await;
}

#[tokio::test]
async fn wrong_pin_fails_on_the_phone_side() {
    let (addr, _ctx, _id) = start().await;
    assert!(dial(addr, [0u8; 32], true).await.is_err());
}

#[tokio::test]
async fn missing_alpn_is_dropped() {
    let (addr, _ctx, id) = start().await;
    assert!(dial(addr, id.pin(), false).await.is_err());
}

#[tokio::test]
async fn ninth_unauthenticated_connection_is_dropped() {
    let (addr, _ctx, _id) = start().await;
    let mut idle = vec![];
    for _ in 0..8 {
        idle.push(TcpStream::connect(addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut ninth = TcpStream::connect(addr).await.unwrap();
    let mut b = [0u8; 1];
    let r = tokio::time::timeout(Duration::from_secs(2), ninth.read(&mut b)).await.expect("closed promptly");
    assert!(matches!(r, Ok(0) | Err(_)), "9th connection must be closed");
}

#[tokio::test]
async fn plaintext_refuses_non_loopback() {
    let (_, ctx, _) = start().await;
    let l = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let on: OnSession = Arc::new(|_, _| async {}.boxed());
    assert!(serve(l, ctx, None, on).await.is_err());
}

#[test]
fn spki_vector_and_pairing_code() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../testdata/protocol-vectors.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    for s in v["spki"].as_array().unwrap() {
        let point = hex::decode(s["point_hex"].as_str().unwrap()).unwrap();
        let der = [P256_SPKI_PREFIX.as_slice(), &point].concat();
        assert_eq!(hex::encode(&der), s["spki_der_hex"].as_str().unwrap());
        let pin: [u8; 32] = Sha256::digest(&der).into();
        assert_eq!(hex::encode(pin), s["pin_sha256_hex"].as_str().unwrap());
        assert_eq!(identity::pin_b64url(&pin), s["pin_b64url_nopad"].as_str().unwrap());
    }
    for c in v["pairing_code"].as_array().unwrap() {
        let pin: [u8; 32] = hex::decode(c["pin_sha256_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
        assert_eq!(identity::pairing_code(&pin), c["code"].as_str().unwrap(), "{c}");
    }
    let pin: [u8; 32] = hex::decode(v["spki"][0]["pin_sha256_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
    assert_eq!(identity::pairing_code(&pin), v["spki"][0]["pairing_code"].as_str().unwrap());
}

#[cfg(unix)]
#[test]
fn key_file_is_owner_only_and_open_perms_are_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("iost-key-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = Identity::load_or_create(&dir).unwrap();
    let key = dir.join("key.pem");
    assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
    let b = Identity::load_or_create(&dir).unwrap();
    assert_eq!(a.pin(), b.pin(), "same key on reload");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Identity::load_or_create(&dir).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Uses a short real timeout: tokio's paused clock doesn't auto-advance while the session's
/// writer thread (spawn_blocking) is alive.
#[tokio::test]
async fn silent_phone_is_disconnected() {
    use iost_receiver::session;
    let (pc_side, mut phone) = tokio::io::duplex(1 << 16);
    let ctx = test_ctx(Limits { peer_silence: Duration::from_millis(300), ..Limits::default() });
    let token = ctx.new_token();
    let c = ctx.clone();
    let task = tokio::spawn(async move {
        let s = iost_receiver::handshake(Box::new(pc_side) as Box<dyn iost_receiver::server::Io>, &c, "t", true).await.unwrap();
        session::run(c.clone(), s).await;
    });
    phone.write_all(&PREFACE).await.unwrap();
    let mut p = [0u8; 8];
    phone.read_exact(&mut p).await.unwrap();
    let mut f = Framed::new(phone, FrameCodec);
    f.send(hello(HelloAuth::Pair { token })).await.unwrap();
    let fr = f.next().await.unwrap().unwrap();
    assert_eq!(fr.ty, FrameType::Welcome);
    f.send(Frame::json(FrameType::Paired, &Paired {})).await.unwrap();
    // Phone goes silent: the session must end with BYE timeout.
    let bye = tokio::time::timeout(Duration::from_secs(5), f.next()).await.unwrap().unwrap().unwrap();
    assert_eq!(bye.ty, FrameType::Bye);
    assert!(String::from_utf8_lossy(&bye.payload).contains("timeout"));
    tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
}

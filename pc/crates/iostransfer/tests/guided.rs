//! The double-click (guided) mode as a child process: first run shows a pairing QR on the receive
//! port, a phone pairs over TLS after the user types y, Q quits; the second run skips pairing.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use iost_proto::msg::{Hello, HelloAuth, Paired, ProtoRange, Welcome};
use iost_proto::{Frame, FrameCodec, FrameType, PREFACE};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::codec::Framed;

const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

struct Guided {
    child: Child,
    stdin: ChildStdin,
    chunks: Receiver<String>,
    /// All output so far, and how far `wait` has consumed it.
    out: String,
    pos: usize,
}

impl Guided {
    fn start(config: &Path, dest: &Path, port: u16) -> Guided {
        let mut child = Command::new(env!("CARGO_BIN_EXE_iostransfer"))
            .args(["--config", config.to_str().unwrap(), "--dest", dest.to_str().unwrap(), "--port", &port.to_string()])
            .env("IOST_SKIP_SETUP", "1")
            .env("IOST_TEST_PAIR_URL", "1")
            .env("IOST_IN_TERMINAL", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let out = child.stdout.take().unwrap();
        let (tx, chunks) = channel();
        // Raw chunks, not lines: prompts end without a newline.
        std::thread::spawn(move || {
            let mut out = out;
            let mut buf = [0u8; 4096];
            while let Ok(n) = out.read(&mut buf) {
                if n == 0 || tx.send(String::from_utf8_lossy(&buf[..n]).into_owned()).is_err() {
                    break;
                }
            }
        });
        Guided { child, stdin, chunks, out: String::new(), pos: 0 }
    }

    /// Wait for output containing `needle` after what was already consumed; returns its line.
    fn wait(&mut self, needle: &str) -> String {
        let end = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(i) = self.out[self.pos..].find(needle) {
                let at = self.pos + i;
                // Let the rest of the line arrive (prompts never end theirs, hence the short wait).
                let settle = Instant::now() + Duration::from_millis(500);
                while !self.out[at..].contains('\n') && Instant::now() < settle {
                    if let Ok(c) = self.chunks.recv_timeout(Duration::from_millis(50)) {
                        self.out.push_str(&c);
                    }
                }
                let start = self.out[..at].rfind('\n').map_or(0, |j| j + 1);
                let stop = self.out[at..].find('\n').map_or(self.out.len(), |j| at + j);
                self.pos = at + needle.len();
                return self.out[start..stop].to_string();
            }
            assert!(Instant::now() < end, "no {needle:?} in output:\n{}", self.out);
            if let Ok(c) = self.chunks.recv_timeout(Duration::from_millis(200)) {
                self.out.push_str(&c);
            }
        }
    }

    fn type_line(&mut self, s: &str) {
        writeln!(self.stdin, "{s}").unwrap();
        self.stdin.flush().unwrap();
    }

    fn quit(mut self) -> String {
        self.type_line("q");
        self.wait("Stopped.");
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(st) = self.child.try_wait().unwrap() {
                assert!(st.success(), "exit status {st}");
                return std::mem::take(&mut self.out);
            }
            assert!(Instant::now() < end, "did not exit");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Guided {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn query<'a>(url: &'a str, key: &str) -> &'a str {
    let q = url.split_once('?').unwrap().1;
    q.split('&').find_map(|kv| kv.strip_prefix(key).and_then(|r| r.strip_prefix('='))).unwrap()
}

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

async fn dial(port: u16, pin: [u8; 32]) -> Framed<tokio_rustls::client::TlsStream<TcpStream>, FrameCodec> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier { pin, provider }))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"iost/1".to_vec()];
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut s = TlsConnector::from(Arc::new(cfg)).connect(ServerName::IpAddress(std::net::Ipv4Addr::LOCALHOST.into()), tcp).await.unwrap();
    s.write_all(&PREFACE).await.unwrap();
    let mut p = [0u8; 8];
    s.read_exact(&mut p).await.unwrap();
    assert_eq!(p, PREFACE);
    Framed::new(s, FrameCodec)
}

#[tokio::test(flavor = "multi_thread")]
async fn first_run_pairs_on_the_receive_port_then_second_run_just_receives() {
    let root = std::env::temp_dir().join(format!("iost-guided-{}", uuid::Uuid::new_v4()));
    let (config, dest) = (root.join("config"), root.join("Pictures/iPhone"));
    let port = free_port();

    let mut g = Guided::start(&config, &dest, port);
    let url = g.wait("PAIR-URL: ").split_once("PAIR-URL: ").unwrap().1.to_string();
    let code = g.wait("must show the code");
    assert_eq!(query(&url, "p"), port.to_string(), "pairing happens on the receive port");
    assert_eq!(query(&url, "rp"), port.to_string());
    let pin: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(query(&url, "spki")).unwrap().try_into().unwrap();

    let mut f = dial(port, pin).await;
    let hello = Hello {
        proto: ProtoRange { min: 1, max: 1 },
        device_id: "0b7c1c1e-3f7a-4c8e-9a51-2a3b4c5d6e7f".into(),
        device_name: "Test iPhone".into(),
        app_version: "0".into(),
        os: "iOS".into(),
        auth: HelloAuth::Pair { token: query(&url, "t").into() },
    };
    f.send(Frame::json(FrameType::Hello, &hello)).await.unwrap();
    let prompt = tokio::task::block_in_place(|| g.wait("Pair \"Test iPhone\""));
    let shown = code.split("code ").nth(1).unwrap().split('.').next().unwrap();
    assert!(prompt.contains(shown), "{prompt} vs {code}");
    g.type_line("y");
    let fr = f.next().await.unwrap().unwrap();
    assert_eq!(fr.ty, FrameType::Welcome, "{}", String::from_utf8_lossy(&fr.payload));
    let w: Welcome = serde_json::from_slice(&fr.payload).unwrap();
    assert!(w.device_secret.is_some());
    f.send(Frame::json(FrameType::Paired, &Paired {})).await.unwrap();
    tokio::task::block_in_place(|| g.wait("Paired with \"Test iPhone\""));
    drop(f);
    let out = tokio::task::block_in_place(|| g.quit());
    assert!(out.contains("step 2 of 2"));
    assert!(dest.is_dir(), "destination created");

    // Second run: remembered folder, no pairing QR.
    let mut g = Guided::start(&config, &dest, port);
    tokio::task::block_in_place(|| g.wait("Ready."));
    let out = tokio::task::block_in_place(|| g.quit());
    assert!(!out.contains("PAIR-URL"), "{out}");
    let _ = std::fs::remove_dir_all(&root);
}

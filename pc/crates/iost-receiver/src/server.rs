//! Accept loop: TLS (or loopback-only plaintext for `--insecure-dev`), pre-auth limits, handshake.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::handshake::{handshake, Ctx, Established, HandshakeError};
use crate::lock;
use crate::tls;

/// At most this many connections may be in TLS/handshake at once (THREAT_MODEL N4).
pub const MAX_PREAUTH: usize = 8;
const TLS_TIMEOUT: Duration = Duration::from_secs(10);
/// Failed authentications allowed per peer per window (THREAT_MODEL N4).
pub const MAX_FAILED_AUTH: usize = 5;
const AUTH_WINDOW: Duration = Duration::from_secs(60);

/// Failed-auth counter per peer address. Unknown devices and bad tokens count too.
#[derive(Default)]
struct AuthLimiter(Mutex<HashMap<String, VecDeque<Instant>>>);

impl AuthLimiter {
    fn blocked(&self, peer: &str) -> bool {
        let mut map = lock(&self.0);
        let Some(q) = map.get_mut(peer) else { return false };
        while q.front().is_some_and(|t| t.elapsed() > AUTH_WINDOW) {
            q.pop_front();
        }
        if q.is_empty() {
            map.remove(peer);
            return false;
        }
        q.len() >= MAX_FAILED_AUTH
    }

    fn record(&self, peer: &str) {
        lock(&self.0).entry(peer.to_string()).or_default().push_back(Instant::now());
    }
}

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub type Session = Established<Box<dyn Io>>;
pub type OnSession = Arc<dyn Fn(Arc<Ctx>, Session) -> BoxFuture<'static, ()> + Send + Sync>;

/// Serve forever. `acceptor = None` means plaintext, which is only allowed on loopback (N21).
pub async fn serve(listener: TcpListener, ctx: Arc<Ctx>, acceptor: Option<TlsAcceptor>, on_session: OnSession) -> std::io::Result<()> {
    if acceptor.is_none() && !listener.local_addr()?.ip().is_loopback() {
        return Err(std::io::Error::other("plaintext mode must bind to loopback only"));
    }
    let preauth = Arc::new(Semaphore::new(MAX_PREAUTH));
    let limiter = Arc::new(AuthLimiter::default());
    loop {
        let (tcp, addr) = match listener.accept().await {
            Ok(a) => a,
            Err(e) => {
                // ECONNABORTED, EMFILE, …: never fatal for the receiver.
                warn!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let peer = addr.ip().to_string();
        if limiter.blocked(&peer) {
            debug!(%addr, "too many failed authentications, dropping");
            continue;
        }
        let Ok(permit) = preauth.clone().try_acquire_owned() else {
            debug!(%addr, "too many unauthenticated connections, dropping");
            continue;
        };
        let _ = tcp.set_nodelay(true);
        let (ctx, acceptor, on_session, limiter) = (ctx.clone(), acceptor.clone(), on_session.clone(), limiter.clone());
        tokio::spawn(async move {
            let (io, is_tls): (Box<dyn Io>, bool) = match acceptor {
                None => (Box::new(tcp), false),
                Some(acc) => match timeout(TLS_TIMEOUT, acc.accept(tcp)).await {
                    Ok(Ok(s)) if tls::alpn_ok(s.get_ref().1) => (Box::new(s), true),
                    Ok(Ok(_)) => return debug!(%addr, "client did not offer ALPN iost/1"),
                    Ok(Err(e)) => return debug!(%addr, "TLS handshake failed: {e}"),
                    Err(_) => return debug!(%addr, "TLS handshake timed out"),
                },
            };
            let session = match handshake(io, &ctx, &peer, is_tls).await {
                Ok(s) => s,
                Err(e) => {
                    if let HandshakeError::Rejected(code) = &e
                        && matches!(code.as_str(), "auth_failed" | "unknown_device" | "token_invalid") {
                            limiter.record(&peer);
                        }
                    return warn!(%addr, "handshake failed: {e}");
                }
            };
            drop(permit);
            info!(%addr, device = %session.device_name, paired = session.newly_paired, "session established");
            on_session(ctx, session).await;
        });
    }
}

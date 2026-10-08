//! Accept loop: TLS (or loopback-only plaintext for `--insecure-dev`), pre-auth limits, handshake.

use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::handshake::{handshake, Ctx, Established};
use crate::tls;

/// At most this many connections may be in TLS/handshake at once (THREAT_MODEL N4).
pub const MAX_PREAUTH: usize = 8;
const TLS_TIMEOUT: Duration = Duration::from_secs(10);

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
        let Ok(permit) = preauth.clone().try_acquire_owned() else {
            debug!(%addr, "too many unauthenticated connections, dropping");
            continue;
        };
        let _ = tcp.set_nodelay(true);
        let (ctx, acceptor, on_session) = (ctx.clone(), acceptor.clone(), on_session.clone());
        tokio::spawn(async move {
            let peer = addr.ip().to_string();
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
                Err(e) => return warn!(%addr, "handshake failed: {e}"),
            };
            drop(permit);
            info!(%addr, device = %session.device_name, paired = session.newly_paired, "session established");
            on_session(ctx, session).await;
        });
    }
}

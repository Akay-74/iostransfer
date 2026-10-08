//! TLS 1.3 server profile (PROTOCOL §1.1): P-256 self-signed cert, ALPN `iost/1`, no client certs.

use std::sync::Arc;

use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::identity::Identity;

pub const ALPN: &[u8] = b"iost/1";

pub fn acceptor(id: &Identity) -> Result<TlsAcceptor, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![id.cert.clone()], id.key.clone_key())?;
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    // No resumption: every connection runs the full handshake, so the phone's pin check always runs.
    cfg.send_tls13_tickets = 0;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// rustls rejects a client whose ALPN list doesn't contain ours, but accepts a client that sends
/// no ALPN at all; the spec requires it, so check after the handshake.
pub fn alpn_ok(conn: &rustls::ServerConnection) -> bool {
    conn.alpn_protocol() == Some(ALPN)
}

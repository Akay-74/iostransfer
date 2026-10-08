//! IOStransfer PC receiver core.

pub mod crash;
pub mod devices;
pub mod engine;
pub mod fsio;
pub mod handshake;
pub mod identity;
pub mod index;
pub mod naming;
pub mod recovery;
pub mod server;
pub mod session;
pub mod text;
pub mod tls;
pub mod xmp;

pub use devices::DeviceDb;
pub use handshake::{handshake, Ctx, DeviceSessions, Established, HandshakeError, Limits, PairRequest};
pub use index::Index;

/// Lock a std mutex, ignoring poisoning: one panicked session must not wedge every later one.
pub fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

//! HMAC challenge/response (PROTOCOL §4.2).

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

fn proof(label: &[u8; 7], secret: &[u8; 32], s_nonce: &[u8; 32], r_nonce: &[u8; 32]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    m.update(label);
    m.update(s_nonce);
    m.update(r_nonce);
    m.finalize().into_bytes().into()
}

/// Receiver (PC) proof, sent in CHALLENGE.
pub fn r_proof(secret: &[u8; 32], s_nonce: &[u8; 32], r_nonce: &[u8; 32]) -> [u8; 32] {
    proof(b"IOST1-R", secret, s_nonce, r_nonce)
}

/// Sender (phone) proof, sent in AUTH.
pub fn s_proof(secret: &[u8; 32], s_nonce: &[u8; 32], r_nonce: &[u8; 32]) -> [u8; 32] {
    proof(b"IOST1-S", secret, s_nonce, r_nonce)
}

/// Constant-time comparison of a received proof.
pub fn proof_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

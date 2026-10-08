//! The PC's TLS identity: an ECDSA P-256 key kept in the config dir (PROTOCOL §1.1).
//! Only the key is stored; the self-signed certificate is rebuilt from it at startup, and the
//! phone pins the key (SPKI), not the certificate.

use std::fs;
use std::io::Write;
use std::path::Path;

use base64::Engine;
use rcgen::{CertificateParams, KeyPair, PublicKeyData, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

/// DER prefix of every P-256 SubjectPublicKeyInfo; the 65-byte uncompressed point follows.
pub const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub struct Identity {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
    pub spki: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("{path} is readable by other users; run `chmod 600 {path}` (THREAT_MODEL N16)")]
    TooOpen { path: String },
    #[error("key file is not a P-256 key")]
    WrongKeyType,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Rcgen(#[from] rcgen::Error),
}

impl Identity {
    /// Load `key.pem` from `dir`, creating it (owner-only) on first run.
    pub fn load_or_create(dir: &Path) -> Result<Self, IdentityError> {
        let path = dir.join("key.pem");
        let key = if path.exists() {
            check_owner_only(&path)?;
            KeyPair::from_pem(&fs::read_to_string(&path)?)?
        } else {
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
            write_owner_only(&path, key.serialize_pem().as_bytes())?;
            key
        };
        Self::from_key(key)
    }

    pub fn from_key(key: KeyPair) -> Result<Self, IdentityError> {
        let spki = key.subject_public_key_info();
        if spki.len() != 91 || spki[..26] != P256_SPKI_PREFIX {
            return Err(IdentityError::WrongKeyType);
        }
        let mut params = CertificateParams::new(vec!["iostransfer".to_string()])?;
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2099, 12, 31);
        let cert = params.self_signed(&key)?;
        Ok(Identity {
            cert: cert.der().clone(),
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            spki,
        })
    }

    pub fn pin(&self) -> [u8; 32] {
        Sha256::digest(&self.spki).into()
    }

    /// The `spki` QR parameter: base64url without padding, 43 chars (PROTOCOL Δ19).
    pub fn pin_b64url(&self) -> String {
        pin_b64url(&self.pin())
    }

    /// Pairing code shown on both screens (THREAT_MODEL N11).
    pub fn pairing_code(&self) -> String {
        pairing_code(&self.pin())
    }
}

pub fn pin_b64url(pin: &[u8; 32]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pin)
}

/// First 40 bits of the pin in Crockford base32, as `XXXX-XXXX`.
pub fn pairing_code(pin: &[u8; 32]) -> String {
    let bits = u64::from_be_bytes([0, 0, 0, pin[0], pin[1], pin[2], pin[3], pin[4]]);
    let chars: Vec<u8> = (0..8).rev().map(|i| CROCKFORD[((bits >> (i * 5)) & 31) as usize]).collect();
    format!("{}-{}", std::str::from_utf8(&chars[..4]).unwrap(), std::str::from_utf8(&chars[4..]).unwrap())
}

/// Create a new file readable only by the current user.
pub fn write_owner_only(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    // On Windows the config dir (%APPDATA%) is already owner-only by default ACL.
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

/// Refuse group/world-readable secrets (THREAT_MODEL N16).
pub fn check_owner_only(path: &Path) -> Result<(), IdentityError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            return Err(IdentityError::TooOpen { path: path.display().to_string() });
        }
    }
    let _ = path;
    Ok(())
}

pub mod callbacks;
pub mod device;
#[cfg(feature = "fs-storage")]
pub mod fs_storage;
#[cfg(feature = "keyring-storage")]
pub mod keyring_storage;
pub mod plist;
pub mod storage;

/// iostransfer patch: the public web roots (Mozilla's list, built in), independent of the OS store.
#[cfg(not(target_arch = "wasm32"))]
pub fn web_roots() -> Vec<reqwest::Certificate> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().filter_map(|c| reqwest::Certificate::from_der(c.as_ref()).ok()).collect()
}

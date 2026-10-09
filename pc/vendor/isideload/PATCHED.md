# isideload 0.4.4, patched for iostransfer

Copied from crates.io `isideload-0.4.4` (MIT, https://github.com/nab138/isideload) with one change:
HTTPS to Apple (GrandSlam) and the anisette server uses rustls with Mozilla's root list plus Apple's
root (`src/util/mod.rs::web_roots`), never the OS verifier. On some Windows PCs schannel rejects
gsa.apple.com (signed by the private "Apple Root CA"), so sign-in failed with "error sending request".
The `cfg(windows)` native-tls override in Cargo.toml is removed for the same reason.

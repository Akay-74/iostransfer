//! Release builds embed the unsigned iPhone app: set IOST_EMBED_IPA to its path. Without it the
//! guided mode downloads the app from the latest GitHub release.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(embedded_ipa)");
    println!("cargo::rerun-if-env-changed=IOST_EMBED_IPA");
    if let Some(src) = std::env::var_os("IOST_EMBED_IPA") {
        let src = std::path::PathBuf::from(src);
        println!("cargo::rerun-if-changed={}", src.display());
        let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR")).join("IOStransfer.ipa");
        std::fs::copy(&src, &out).unwrap_or_else(|e| panic!("IOST_EMBED_IPA={}: {e}", src.display()));
        println!("cargo::rustc-cfg=embedded_ipa");
    }
}

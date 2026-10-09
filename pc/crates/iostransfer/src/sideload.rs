//! Put the IOStransfer app on the iPhone and keep it signed, with a free Apple ID: install over
//! USB once, then re-sign before the 7-day expiry over USB or Wi‑Fi (no SideStore needed).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use idevice::IdeviceService;
use idevice::amfi::AmfiClient;
use idevice::installation_proxy::InstallationProxyClient;
use idevice::lockdown::LockdownClient;
use idevice::pairing_file::PairingFile;
use idevice::provider::{IdeviceProvider, TcpProvider};
use idevice::usbmuxd::{Connection, UsbmuxdAddr, UsbmuxdConnection, UsbmuxdDevice};
use isideload::anisette::remote_v3::RemoteV3AnisetteProvider;
use isideload::auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse};
use isideload::dev::certificates::DevelopmentCertificate;
use isideload::dev::developer_session::DeveloperSession;
use isideload::sideload::builder::MaxCertsBehavior;
use isideload::sideload::{SideloaderBuilder, TeamSelection};
use isideload::util::fs_storage::FsStorage;
use rootcause::Report;
use sha2::{Digest, Sha256};

use crate::console::Console;
use crate::state::{AppState, Phone, now, safe_udid, write_atomic};

/// Bundle ID in the .ipa; signing appends the team ID.
pub const BUNDLE_PREFIX: &str = "io.github.akay74.iostransfer";
/// Free Apple IDs sign for 7 days; renew with 3 days to spare.
pub const RENEW_AFTER: u64 = 4 * 24 * 3600;
const SIGN_DAYS: u64 = 7;
const KEYRING_SERVICE: &str = "iostransfer-apple-id";
const LABEL: &str = "iostransfer";
const RELEASE_URL: &str = "https://github.com/Akay-74/iostransfer/releases/latest/download";

#[cfg(embedded_ipa)]
static EMBEDDED_IPA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/IOStransfer.ipa"));

pub struct Installer {
    config: PathBuf,
    console: Arc<Console>,
    state: Arc<Mutex<AppState>>,
    /// One signing at a time (they share the Apple session and certificate).
    busy: tokio::sync::Mutex<()>,
    /// Phones whose last automatic renewal failed, to retry later rather than every minute.
    backoff: Mutex<HashMap<String, Instant>>,
    /// Prompt for the password at most once per run when the keyring has none.
    asked_password: Mutex<bool>,
}

impl Installer {
    pub fn new(config: &Path, console: Arc<Console>, state: Arc<Mutex<AppState>>) -> Arc<Self> {
        Arc::new(Self {
            config: config.to_path_buf(),
            console,
            state,
            busy: tokio::sync::Mutex::new(()),
            backoff: Mutex::new(HashMap::new()),
            asked_password: Mutex::new(false),
        })
    }

    fn save(&self) {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Err(e) = st.save(&self.config) {
            tracing::warn!("saving settings: {e:#}");
        }
    }

    /// iPhones plugged in by USB right now.
    pub async fn usb_phones() -> Vec<UsbmuxdDevice> {
        let Ok(mut mux) = UsbmuxdConnection::default().await else { return vec![] };
        mux.get_devices().await.unwrap_or_default().into_iter().filter(|d| matches!(d.connection_type, Connection::Usb)).collect()
    }

    /// Is IOStransfer installed on this phone?
    pub async fn is_installed(provider: &dyn IdeviceProvider) -> Result<bool> {
        let mut ip = InstallationProxyClient::connect(provider).await.map_err(|e| anyhow!("{e}"))?;
        let apps = ip.get_apps(Some("User"), None).await.map_err(|e| anyhow!("{e}"))?;
        Ok(apps.keys().any(|k| k.starts_with(BUNDLE_PREFIX)))
    }

    /// Full first-time install over USB: trust this PC, sign, install, enable Wi‑Fi renewal, and
    /// tell the user the two taps the iPhone needs.
    pub async fn install_usb(&self, dev: &UsbmuxdDevice) -> Result<()> {
        let _busy = self.busy.lock().await;
        let pairing = self.trust_pc(dev).await?;
        let provider = dev.to_provider(UsbmuxdAddr::default(), LABEL);
        let name = device_name(&provider).await.unwrap_or_else(|_| "iPhone".into());
        println!("Installing IOStransfer on \"{name}\"…");
        self.sign_and_install(&provider).await?;
        self.after_install(&provider, &dev.udid, &name, pairing).await;
        Ok(())
    }

    /// The iPhone asks "Trust This Computer?" the first time; returns the pairing record.
    async fn trust_pc(&self, dev: &UsbmuxdDevice) -> Result<PairingFile> {
        let mut mux = UsbmuxdConnection::default().await.map_err(|e| anyhow!("iPhone USB service: {e}"))?;
        if let Ok(p) = mux.get_pair_record(&dev.udid).await {
            let provider = dev.to_provider(UsbmuxdAddr::default(), LABEL);
            if let Ok(mut l) = LockdownClient::connect(&provider).await
                && l.start_session(&p).await.is_ok()
            {
                return Ok(p);
            }
        }
        let buid = mux.get_buid().await.map_err(|e| anyhow!("iPhone USB service: {e}"))?;
        let host_id = uuid::Uuid::new_v4().to_string().to_uppercase();
        let provider = dev.to_provider(UsbmuxdAddr::default(), LABEL);
        let mut said = "";
        let deadline = Instant::now() + Duration::from_secs(180);
        let record = loop {
            let mut l = LockdownClient::connect(&provider).await.map_err(|e| anyhow!("{e}"))?;
            match l.pair_once(host_id.clone(), buid.clone(), Some(&crate::pc_name())).await {
                Ok(p) => break p,
                Err(idevice::IdeviceError::PasswordProtected) => {
                    if said != "unlock" {
                        println!("Unlock the iPhone…");
                        said = "unlock";
                    }
                }
                Err(idevice::IdeviceError::PairingDialogResponsePending) => {
                    if said != "trust" {
                        println!("On the iPhone, tap \"Trust\" and enter its passcode.");
                        said = "trust";
                    }
                }
                Err(idevice::IdeviceError::UserDeniedPairing) => bail!("the iPhone said \"Don't Trust\"; unplug and plug it in again to retry"),
                Err(e) => bail!("pairing with the iPhone failed: {e}"),
            }
            if Instant::now() > deadline {
                bail!("timed out waiting for \"Trust\" on the iPhone");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        };
        let bytes = record.clone().serialize().map_err(|e| anyhow!("{e}"))?;
        mux.save_pair_record(&dev.udid, bytes).await.map_err(|e| anyhow!("saving the pairing: {e}"))?;
        Ok(record)
    }

    async fn after_install(&self, provider: &dyn IdeviceProvider, udid: &str, name: &str, pairing: PairingFile) {
        // Allow lockdown over Wi‑Fi, so later renewals need no cable.
        if let Ok(mut l) = LockdownClient::connect(provider).await
            && l.start_session(&pairing).await.is_ok()
            && let Err(e) = l.set_value("EnableWifiConnections", true.into(), Some("com.apple.mobile.wireless_lockdown")).await
        {
            tracing::debug!("enabling Wi‑Fi connections: {e}");
        }
        if let Some(udid) = safe_udid(udid)
            && let Ok(bytes) = pairing.serialize()
        {
            let dir = self.config.join("phones");
            let _ = std::fs::create_dir_all(&dir);
            if let Err(e) = write_atomic(&dir.join(format!("{udid}.plist")), &bytes) {
                tracing::warn!("saving the pairing for Wi‑Fi renewal: {e:#}");
            }
        }
        {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let p = st.phones.entry(udid.to_string()).or_default();
            p.name = name.to_string();
            p.signed_at = now();
        }
        self.save();

        let dev_mode = match AmfiClient::connect(provider).await {
            Ok(mut a) => match a.get_developer_mode_status().await {
                Ok(on) => {
                    if !on {
                        let _ = a.reveal_developer_mode_option_in_ui().await;
                    }
                    Some(on)
                }
                Err(_) => None,
            },
            Err(_) => None,
        };
        println!();
        println!("IOStransfer is on the iPhone. One-time steps on the iPhone:");
        let mut n = 1;
        if dev_mode != Some(true) {
            println!("  {n}. Settings → Privacy & Security → Developer Mode → On, then Restart and confirm \"Turn On\".");
            n += 1;
        }
        println!("  {n}. Settings → General → VPN & Device Management → your Apple ID → Trust.");
        println!("  {}. Open IOStransfer.", n + 1);
        println!("This PC renews the app automatically every few days while this window is open.");
    }

    /// Re-sign and reinstall phones whose signature is getting old. Called periodically; `peers`
    /// are addresses phones recently connected from.
    pub async fn renew_due(&self, peers: &[String]) {
        let due: Vec<(String, Phone)> = {
            let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            st.phones.iter().filter(|(_, p)| now().saturating_sub(p.signed_at) >= RENEW_AFTER).map(|(u, p)| (u.clone(), p.clone())).collect()
        };
        for (udid, phone) in due {
            if self.backoff.lock().unwrap_or_else(|e| e.into_inner()).get(&udid).is_some_and(|t| *t > Instant::now()) {
                continue;
            }
            let left = (phone.signed_at + SIGN_DAYS * 86400).saturating_sub(now()) / 3600;
            match self.renew(&udid, &phone, peers).await {
                Ok(true) => println!("Renewed IOStransfer on \"{}\" for another 7 days.", phone.name),
                Ok(false) => {
                    if left < 24 {
                        println!(
                            "IOStransfer on \"{}\" stops opening in about {left} h. Connect the iPhone to this PC (USB, or same Wi‑Fi with IOStransfer open) to renew.",
                            phone.name
                        );
                    }
                    self.retry_later(&udid, Duration::from_secs(15 * 60));
                }
                Err(e) => {
                    println!("Couldn't renew IOStransfer on \"{}\": {e:#}", phone.name);
                    self.retry_later(&udid, Duration::from_secs(30 * 60));
                }
            }
        }
    }

    fn retry_later(&self, udid: &str, after: Duration) {
        self.backoff.lock().unwrap_or_else(|e| e.into_inner()).insert(udid.to_string(), Instant::now() + after);
    }

    /// Ok(false): the phone isn't reachable right now.
    async fn renew(&self, udid: &str, phone: &Phone, peers: &[String]) -> Result<bool> {
        if let Some(dev) = Self::usb_phones().await.into_iter().find(|d| d.udid == udid) {
            let _busy = self.busy.lock().await;
            let provider = dev.to_provider(UsbmuxdAddr::default(), LABEL);
            self.sign_and_install(&provider).await?;
            self.mark_signed(udid, None);
            return Ok(true);
        }
        let Some(pairing) = self.saved_pairing(udid) else { return Ok(false) };
        let mut ips: Vec<String> = phone.ip.iter().cloned().collect();
        ips.extend(peers.iter().filter(|p| Some(*p) != phone.ip.as_ref()).cloned());
        for ip in ips {
            let Ok(addr) = ip.parse() else { continue };
            let provider = TcpProvider { addr, scope_id: None, pairing_file: pairing.clone(), label: LABEL.into() };
            // Only the right phone accepts this pairing record.
            let reachable = tokio::time::timeout(Duration::from_secs(5), async {
                let mut l = LockdownClient::connect(&provider).await.ok()?;
                l.start_session(&pairing).await.ok()
            })
            .await
            .ok()
            .flatten()
            .is_some();
            if !reachable {
                continue;
            }
            let _busy = self.busy.lock().await;
            self.sign_and_install(&provider).await?;
            self.mark_signed(udid, Some(ip));
            return Ok(true);
        }
        Ok(false)
    }

    fn mark_signed(&self, udid: &str, ip: Option<String>) {
        {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(p) = st.phones.get_mut(udid) {
                p.signed_at = now();
                if ip.is_some() {
                    p.ip = ip;
                }
            }
        }
        self.save();
    }

    fn saved_pairing(&self, udid: &str) -> Option<PairingFile> {
        let path = self.config.join("phones").join(format!("{}.plist", safe_udid(udid)?));
        PairingFile::read_from_file(path).ok()
    }

    // -----------------------------------------------------------------------------------------
    // Signing

    async fn sign_and_install(&self, provider: &(impl IdeviceProvider + ?Sized)) -> Result<()> {
        let ipa = self.ipa().await?;
        let (email, session) = self.login().await?;
        let storage_dir = self.config.join("signing");
        std::fs::create_dir_all(&storage_dir)?;
        let console = self.console.clone();
        let revoke = move |certs: Vec<DevelopmentCertificate>| {
            let console = console.clone();
            async move { Ok::<_, Report>(pick_certs_to_revoke(&console, &certs).await) }
        };
        let mut sideloader = SideloaderBuilder::new(session, email)
            .team_selection(TeamSelection::First)
            .max_certs_behavior(MaxCertsBehavior::Prompt(revoke))
            .storage(Box::new(FsStorage::new(storage_dir)))
            .machine_name(format!("iostransfer-{}", crate::pc_name()))
            .delete_app_after_install(true)
            .build();
        let last = Arc::new(Mutex::new(-1i32));
        let progress = move |f: f32| {
            let pct = (f * 100.0) as i32 / 10 * 10;
            let mut l = last.lock().unwrap_or_else(|e| e.into_inner());
            if pct > *l {
                *l = pct;
                println!("  signing… {pct}%");
            }
            std::future::ready(())
        };
        sideloader.install_app(&ProviderRef(provider), ipa, false, Some(progress), None).await.map_err(|e| anyhow!("{e}"))?;
        Ok(())
    }

    /// Log in to the Apple ID (remembered email; password from the OS keyring or asked).
    async fn login(&self) -> Result<(String, DeveloperSession)> {
        let saved = self.state.lock().unwrap_or_else(|e| e.into_inner()).apple_id.clone();
        let email = match saved {
            Some(e) => e,
            None => {
                println!("Signing the iPhone app needs a free Apple ID (a separate one just for this is fine).");
                let e = self.console.ask("Apple ID email: ").await.context("no input")?;
                let e = e.trim().to_string();
                if e.is_empty() {
                    bail!("no Apple ID given");
                }
                e
            }
        };
        let stored = keyring_get(&email).await;
        let (password, from_keyring) = match stored {
            Some(p) => (p, true),
            None => {
                {
                    let mut asked = self.asked_password.lock().unwrap_or_else(|e| e.into_inner());
                    if *asked {
                        bail!("no saved Apple ID password; type I and Enter to sign in again");
                    }
                    *asked = true;
                }
                let p = self.console.ask_secret(&format!("Password for {email} (not shown while typing): ")).await.context("no input")?;
                (p, false)
            }
        };
        let anisette_dir = self.config.join("anisette");
        std::fs::create_dir_all(&anisette_dir)?;
        let anisette = RemoteV3AnisetteProvider::default()
            .map_err(|e| anyhow!("{e}"))?
            .set_storage(Box::new(FsStorage::new(anisette_dir)));
        let console = self.console.clone();
        let two_factor = move |p: TwoFactorCallbackParams| {
            let console = console.clone();
            async move { Ok::<_, Report>(ask_two_factor(&console, p).await) }
        };
        let mut account = match AppleAccount::builder(&email).anisette_provider(anisette).login(&password, two_factor).await {
            Ok(a) => a,
            Err(e) => {
                if from_keyring {
                    // Probably a changed password: forget it, ask next time.
                    keyring_delete(&email).await;
                }
                bail!("Apple ID sign-in failed: {e}");
            }
        };
        let session = DeveloperSession::from_account(&mut account).await.map_err(|e| anyhow!("{e}"))?;
        if !from_keyring {
            if !keyring_set(&email, &password).await {
                println!("(Couldn't save the password in the system keyring; you'll be asked when the app needs renewing.)");
            }
        }
        self.state.lock().unwrap_or_else(|e| e.into_inner()).apple_id = Some(email.clone());
        self.save();
        Ok((email, session))
    }

    /// The unsigned app: built into this program for releases, else the latest release download.
    async fn ipa(&self) -> Result<PathBuf> {
        let path = self.config.join("IOStransfer.ipa");
        #[cfg(embedded_ipa)]
        {
            std::fs::write(&path, EMBEDDED_IPA)?;
            Ok(path)
        }
        #[cfg(not(embedded_ipa))]
        {
            println!("Downloading the iPhone app…");
            let ipa = fetch(&format!("{RELEASE_URL}/IOStransfer.ipa")).await?;
            let sums = String::from_utf8_lossy(&fetch(&format!("{RELEASE_URL}/SHA256SUMS")).await?).into_owned();
            let want = sums
                .lines()
                .find_map(|l| l.split_whitespace().collect::<Vec<_>>().get(..2).filter(|v| v[1].trim_start_matches('*') == "IOStransfer.ipa").map(|v| v[0].to_lowercase()))
                .context("SHA256SUMS has no IOStransfer.ipa")?;
            if hex::encode(Sha256::digest(&ipa)) != want {
                bail!("the downloaded app is corrupt (checksum mismatch)");
            }
            std::fs::write(&path, &ipa)?;
            Ok(path)
        }
    }
}

#[cfg(not(embedded_ipa))]
async fn fetch(url: &str) -> Result<Vec<u8>> {
    let r = reqwest::Client::new().get(url).send().await?.error_for_status()?;
    Ok(r.bytes().await?.to_vec())
}

/// SHA-256 of the app built into this binary, if any (shown by `--version`-style diagnostics).
#[allow(dead_code)]
pub fn embedded_ipa_sha256() -> Option<String> {
    #[cfg(embedded_ipa)]
    return Some(hex::encode(Sha256::digest(EMBEDDED_IPA)));
    #[cfg(not(embedded_ipa))]
    None
}

// The OS credential store (Windows Credential Manager, Secret Service on Linux). Its calls block, so
// they run off the async workers.

async fn keyring_get(email: &str) -> Option<String> {
    let email = email.to_string();
    tokio::task::spawn_blocking(move || keyring::Entry::new(KEYRING_SERVICE, &email).ok()?.get_password().ok()).await.ok().flatten()
}

async fn keyring_set(email: &str, password: &str) -> bool {
    let (email, password) = (email.to_string(), password.to_string());
    tokio::task::spawn_blocking(move || keyring::Entry::new(KEYRING_SERVICE, &email).and_then(|k| k.set_password(&password)).is_ok()).await.unwrap_or(false)
}

async fn keyring_delete(email: &str) {
    let email = email.to_string();
    let _ = tokio::task::spawn_blocking(move || keyring::Entry::new(KEYRING_SERVICE, &email).map(|k| k.delete_credential())).await;
}

async fn device_name(provider: &dyn IdeviceProvider) -> Result<String> {
    let mut l = LockdownClient::connect(provider).await.map_err(|e| anyhow!("{e}"))?;
    let v = l.get_value(Some("DeviceName"), None).await.map_err(|e| anyhow!("{e}"))?;
    Ok(v.as_string().unwrap_or("iPhone").to_string())
}

async fn ask_two_factor(console: &Console, p: TwoFactorCallbackParams) -> TwoFactorCallbackResponse {
    if let Some(err) = &p.last_error {
        println!("{err}");
    }
    let to = if p.sms {
        p.numbers.iter().find(|n| Some(n.id) == p.selected_number_id).map_or("your phone number".to_string(), |n| n.number_with_dial_code.clone())
    } else {
        "your Apple devices".to_string()
    };
    if p.unknown {
        println!("The last verification method didn't work.");
    } else {
        println!("Apple sent a verification code to {to}.");
    }
    let others: Vec<_> = p.numbers.iter().filter(|n| Some(n.id) != p.selected_number_id).collect();
    if !others.is_empty() {
        for n in &others {
            println!("  type p{} to get it by SMS at {}", n.id, n.number_with_dial_code);
        }
    }
    println!("  (d = send to devices, r = resend)");
    let Some(a) = console.ask("Verification code: ").await else { return TwoFactorCallbackResponse::Abort };
    let a = a.trim();
    if let Some(id) = a.strip_prefix('p').and_then(|s| s.parse().ok()) {
        TwoFactorCallbackResponse::SendSms(id)
    } else if a == "d" {
        TwoFactorCallbackResponse::SendToDevices
    } else if a == "r" {
        TwoFactorCallbackResponse::ResendCode
    } else if a.is_empty() {
        TwoFactorCallbackResponse::Abort
    } else {
        TwoFactorCallbackResponse::SubmitCode(a.to_string())
    }
}

/// Free Apple IDs may hold only a couple of signing certificates; let the user pick which to drop.
async fn pick_certs_to_revoke(console: &Console, certs: &[DevelopmentCertificate]) -> Option<Vec<String>> {
    println!("This Apple ID already has the maximum number of signing certificates:");
    for (i, c) in certs.iter().enumerate() {
        println!("  {}. {} ({})", i + 1, c.machine_name.as_deref().unwrap_or("unknown computer"), c.name.as_deref().unwrap_or("certificate"));
    }
    println!("Revoking one stops apps signed by it from opening until they are re-signed (e.g. by SideStore).");
    let a = console.ask("Number(s) to revoke, comma-separated (Enter = cancel): ").await?;
    let picked: Vec<String> = a
        .split(',')
        .filter_map(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n >= 1 && n <= certs.len())
        .filter_map(|n| certs[n - 1].serial_number.clone())
        .collect();
    (!picked.is_empty()).then_some(picked)
}

/// `install_app` wants a sized provider; this forwards to any provider by reference.
#[derive(Debug)]
struct ProviderRef<'a, P: ?Sized>(&'a P);

impl<P: IdeviceProvider + ?Sized> IdeviceProvider for ProviderRef<'_, P> {
    fn connect(&self, port: u16) -> std::pin::Pin<Box<dyn Future<Output = Result<idevice::Idevice, idevice::IdeviceError>> + Send>> {
        self.0.connect(port)
    }
    fn label(&self) -> &str {
        self.0.label()
    }
    fn get_pairing_file(&self) -> std::pin::Pin<Box<dyn Future<Output = Result<PairingFile, idevice::IdeviceError>> + Send>> {
        self.0.get_pairing_file()
    }
}

#[cfg(test)]
mod tests {
    /// Needs a desktop session with a keyring; run by hand: cargo test -- --ignored keyring
    #[tokio::test]
    #[ignore]
    async fn keyring_roundtrip() {
        let who = format!("test-{}@example.invalid", uuid::Uuid::new_v4());
        assert!(super::keyring_set(&who, "pw 1").await);
        assert_eq!(super::keyring_get(&who).await.as_deref(), Some("pw 1"));
        super::keyring_delete(&who).await;
        assert_eq!(super::keyring_get(&who).await, None);
    }

    /// Network: the latest release's app downloads and matches SHA256SUMS.
    #[cfg(not(embedded_ipa))]
    #[tokio::test]
    #[ignore]
    async fn release_ipa_download() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!("iost-ipa-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = std::sync::Arc::new(std::sync::Mutex::new(crate::state::AppState::default()));
        let inst = super::Installer::new(&dir, crate::console::Console::new(), state);
        let p = inst.ipa().await.unwrap();
        let bytes = std::fs::read(&p).unwrap();
        assert_eq!(&bytes[..2], b"PK");
        // The signer can read it and finds our bundle.
        let app = isideload::sideload::application::Application::new(p).unwrap();
        assert_eq!(app.main_bundle_id().unwrap(), super::BUNDLE_PREFIX);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

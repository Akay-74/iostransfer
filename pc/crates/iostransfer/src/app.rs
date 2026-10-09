//! Double-click mode: `iostransfer` with no arguments sets everything up and keeps receiving.
//! First run: firewall, install the iPhone app over USB, pair by QR. Later runs: just receive, and
//! renew the iPhone app before its 7-day signature runs out.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use futures_util::FutureExt;
use iost_receiver::handshake::{ConfirmPair, TOKEN_TTL};
use iost_receiver::identity::Identity;
use iost_receiver::server::{OnSession, serve};
use iost_receiver::text::escape_for_terminal;
use iost_receiver::{Limits, lock, session, tls};
use tokio::net::TcpListener;

use crate::console::Console;
use crate::sideload::Installer;
use crate::state::AppState;
use crate::{advertise, build_ctx, lan_ips, open_devices, percent_encode, print_qr, setup};

const PEER_MEMORY: Duration = Duration::from_secs(3600);

pub fn default_dest() -> PathBuf {
    let pictures = directories::UserDirs::new()
        .and_then(|u| u.picture_dir().map(Path::to_path_buf).or_else(|| Some(u.home_dir().join("Pictures"))))
        .unwrap_or_else(|| PathBuf::from("Pictures"));
    pictures.join("iPhone")
}

pub async fn run(config: &Path, dest_arg: Option<PathBuf>, port: u16) -> Result<()> {
    println!("IOStransfer {}: photos and videos from your iPhone to this PC", env!("CARGO_PKG_VERSION"));
    println!();
    let console = Console::new();
    let state = Arc::new(Mutex::new(AppState::load(config)));
    let dest = {
        let mut st = lock(&state);
        let dest = dest_arg.or(st.dest.clone()).unwrap_or_else(default_dest);
        st.dest = Some(dest.clone());
        st.save(config)?;
        dest
    };
    std::fs::create_dir_all(&dest).with_context(|| format!("creating {}", dest.display()))?;

    // Firewall: cheap to check on Windows and firewalld; ufw can only be set, so once.
    let skip_setup = std::env::var_os("IOST_SKIP_SETUP").is_some(); // tests
    if !skip_setup && (cfg!(windows) || !lock(&state).firewall_done) {
        let status = setup::firewall(&console, port).await;
        println!("{status}");
        if !status.contains("not ") && !status.contains("could not") {
            let mut st = lock(&state);
            st.firewall_done = true;
            st.save(config)?;
        }
    }

    // Receiver, which also accepts pairing on the same port.
    let id = Identity::load_or_create(config)?;
    let code = id.pairing_code();
    let confirm: ConfirmPair = {
        let (console, code) = (console.clone(), code.clone());
        Arc::new(move |req| {
            let (console, code) = (console.clone(), code.clone());
            async move {
                let q = format!(
                    "\nPair \"{}\" ({})? The iPhone must show code {code}.",
                    escape_for_terminal(&req.device_name),
                    req.peer
                );
                console.yes(&q, false).await
            }
            .boxed()
        })
    };
    let ctx = build_ctx(config, &dest, open_devices(config)?, Limits::default(), confirm, None)?;
    let listener = match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => l,
        Err(_) => bail!("port {port} is in use. Is IOStransfer already open in another window?"),
    };
    let ips = lan_ips();
    let _mdns = advertise(&ctx.pc_id, &ips, port).map_err(|e| tracing::warn!("Bonjour advertising failed: {e}")).ok();
    let peers: Arc<Mutex<Vec<(String, Instant)>>> = Arc::default();
    let active = Arc::new(AtomicUsize::new(0));
    let on_session: OnSession = {
        let (peers, active) = (peers.clone(), active.clone());
        Arc::new(move |ctx, s| {
            let (peers, active) = (peers.clone(), active.clone());
            async move {
                if s.newly_paired {
                    println!("Paired with \"{}\".", escape_for_terminal(&s.device_name));
                }
                {
                    let mut p = lock(&peers);
                    p.retain(|(ip, t)| *ip != s.peer && t.elapsed() < PEER_MEMORY);
                    p.push((s.peer.clone(), Instant::now()));
                }
                active.fetch_add(1, Ordering::SeqCst);
                session::run(ctx, s).await;
                active.fetch_sub(1, Ordering::SeqCst);
            }
            .boxed()
        })
    };
    let acceptor = tls::acceptor(&id)?;
    let mut server = tokio::spawn(serve(listener, ctx.clone(), Some(acceptor), on_session));
    println!("Photos and videos go to {}", dest.display());

    let installer = Installer::new(config, console.clone(), state.clone());
    let paired = lock(&ctx.devices).list()?.len();
    if paired == 0 {
        if !skip_setup {
            first_run(&console, &installer, &state).await;
        }
        println!();
        println!("First-time setup, step 2 of 2: pair the iPhone with this PC");
        pair(&ctx, &id, &ips, port, &code).await;
    }

    // Renew the iPhone app in the background, never during a transfer (installing restarts it).
    {
        let (installer, peers, active) = (installer.clone(), peers.clone(), active.clone());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                if active.load(Ordering::SeqCst) == 0 {
                    let recent: Vec<String> = lock(&peers).iter().filter(|(_, t)| t.elapsed() < PEER_MEMORY).map(|(ip, _)| ip.clone()).collect();
                    installer.renew_due(&recent).await;
                }
            }
        });
    }

    ready_text(&dest);
    loop {
        tokio::select! {
            line = console.command() => {
                let Some(line) = line else {
                    // No keyboard (stdin closed): keep receiving until stopped.
                    let _ = tokio::signal::ctrl_c().await;
                    break;
                };
                match line.trim().to_lowercase().as_str() {
                    "" => {}
                    "p" => pair(&ctx, &id, &ips, port, &code).await,
                    "i" => install_now(&console, &installer).await,
                    "o" => setup::open_path(&dest),
                    "d" => change_dest(&console, &state, config).await,
                    "q" => break,
                    _ => ready_text(&dest),
                }
            }
            _ = tokio::signal::ctrl_c() => break,
            r = &mut server => match r {
                Ok(Err(e)) => bail!("the receiver stopped: {e}"),
                _ => bail!("the receiver stopped unexpectedly"),
            },
        }
    }
    println!("Stopped.");
    Ok(())
}

fn ready_text(dest: &Path) {
    println!();
    println!("Ready. Keep this window open, then on the iPhone open IOStransfer, pick photos and tap Copy or Move.");
    println!("Type a letter and press Enter:  P pair another iPhone · I install/renew the iPhone app (USB) · O open {} · D change folder · Q quit", dest.display());
}

/// Step 1 of the first run: get the app onto the iPhone over USB.
async fn first_run(console: &Arc<Console>, installer: &Arc<Installer>, state: &Arc<Mutex<AppState>>) {
    println!();
    println!("First-time setup, step 1 of 2: the IOStransfer app on the iPhone");
    println!("(iCloud Photos must be off on the iPhone: Settings → your name → iCloud → Photos.)");
    if !lock(state).phones.is_empty() {
        println!("Already installed from this PC.");
        return;
    }
    if !setup::usb_service(console).await {
        println!("Without the iPhone USB service the app can't be installed from here.");
        println!("If IOStransfer is already on the iPhone (e.g. via SideStore), continue with pairing.");
        return;
    }
    println!("Connect the iPhone to this PC with a USB cable and unlock it.");
    println!("(Already have the app on the iPhone? Press Enter to skip.)");
    let Some(dev) = wait_for_usb_phone(console).await else { return };
    let provider = dev.to_provider(idevice::usbmuxd::UsbmuxdAddr::default(), "iostransfer");
    if Installer::is_installed(&provider).await.unwrap_or(false)
        && !console.yes("IOStransfer is already on this iPhone. Reinstall it from here so this PC can renew it automatically?", true).await
    {
        return;
    }
    if let Err(e) = installer.install_usb(&dev).await {
        println!("Installing the app failed: {e:#}");
        println!("You can retry any time: type I and press Enter.");
    }
    let _ = console.ask("\nPress Enter when IOStransfer opens on the iPhone… ").await;
}

/// Wait for a USB iPhone, or None if the user presses Enter.
async fn wait_for_usb_phone(console: &Console) -> Option<idevice::usbmuxd::UsbmuxdDevice> {
    let poll = async {
        loop {
            if let Some(d) = Installer::usb_phones().await.into_iter().next() {
                return d;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    };
    tokio::select! {
        d = poll => Some(d),
        _ = console.ask("") => None,
    }
}

async fn install_now(console: &Arc<Console>, installer: &Arc<Installer>) {
    if !setup::usb_service(console).await {
        println!("The iPhone USB service isn't available.");
        return;
    }
    let dev = match Installer::usb_phones().await.into_iter().next() {
        Some(d) => d,
        None => {
            println!("Connect the iPhone with a USB cable and unlock it (Enter = cancel).");
            match wait_for_usb_phone(console).await {
                Some(d) => d,
                None => return,
            }
        }
    };
    match installer.install_usb(&dev).await {
        Ok(()) => {}
        Err(e) => println!("Installing the app failed: {e:#}"),
    }
}

/// Step 2: show a pairing QR. Returns at once; "Paired with …" is printed when a phone pairs.
async fn pair(ctx: &Arc<iost_receiver::Ctx>, id: &Identity, ips: &[std::net::IpAddr], port: u16, code: &str) {
    if ips.is_empty() {
        println!("This PC has no local network address. Connect it to the same Wi‑Fi/LAN as the iPhone and restart IOStransfer.");
        return;
    }
    let before = lock(&ctx.devices).list().map(|l| l.len()).unwrap_or(0);
    let token = ctx.new_token();
    let hosts = ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
    let url = format!(
        "iost://pair?pcid={}&h={hosts}&p={port}&rp={port}&spki={}&t={token}&n={}",
        ctx.pc_id,
        id.pin_b64url(),
        percent_encode(&ctx.pc_name)
    );
    println!();
    println!("Pairing: in IOStransfer on the iPhone tap \"Scan the pairing QR code\" and point it at this code.");
    if let Err(e) = print_qr(&url) {
        println!("(Couldn't draw the QR code: {e})");
    }
    if std::env::var_os("IOST_TEST_PAIR_URL").is_some() {
        println!("PAIR-URL: {url}");
    }
    println!("Both screens must show the code {code}. The QR works for {} minutes.", TOKEN_TTL.as_secs() / 60);
    let ctx = ctx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(TOKEN_TTL).await;
        let tokens_left = lock(&ctx.tokens).contains_key(&token);
        if tokens_left && lock(&ctx.devices).list().map(|l| l.len()).unwrap_or(0) == before {
            println!("The pairing QR expired. Type P and press Enter for a new one.");
        }
    });
}

async fn change_dest(console: &Console, state: &Arc<Mutex<AppState>>, config: &Path) {
    let Some(a) = console.ask("New folder for photos and videos (Enter = keep): ").await else { return };
    let a = a.trim().trim_matches('"');
    if a.is_empty() {
        return;
    }
    let mut st = lock(state);
    st.dest = Some(PathBuf::from(a));
    match st.save(config) {
        Ok(()) => println!("Saved. Close and reopen IOStransfer to use {a}."),
        Err(e) => println!("Couldn't save: {e:#}"),
    }
}

//! `iostransfer`: the PC side of IOStransfer (ARCHITECTURE §4.5).

use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use futures_util::FutureExt;
use iost_receiver::handshake::{ConfirmPair, TOKEN_TTL};
use iost_receiver::identity::{check_owner_only, write_owner_only, Identity};
use iost_receiver::server::{serve, OnSession};
use iost_receiver::text::escape_for_terminal;
use iost_receiver::{lock, recovery, session, tls, Ctx, DeviceDb, Index, Limits};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Semaphore};

const DEFAULT_PORT: u16 = 47800;
const SERVICE_TYPE: &str = "_iostransfer._tcp.local.";
const SINK_MAX_CONNS: usize = 16;

#[derive(Parser)]
#[command(name = "iostransfer", version, about = "Receive photos and videos from an iPhone")]
struct Cli {
    /// Config directory (default: the OS per-user config dir)
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show a QR code and pair one iPhone (works while `receive` is running)
    Pair {
        /// Folder where received photos and videos go
        #[arg(long)]
        dest: PathBuf,
        /// Port for this pairing session (default: any free port; the QR carries it)
        #[arg(long, default_value_t = 0)]
        port: u16,
    },
    /// Receive from paired iPhones
    Receive {
        #[arg(long)]
        dest: PathBuf,
        #[arg(long, default_value_t = DEFAULT_PORT)]
        port: u16,
        /// Plaintext on 127.0.0.1 only, for interop tests. Never use with a real phone.
        #[arg(long)]
        insecure_dev: bool,
        /// Pre-provisioned test device `<uuid>:<64 hex secret>`, in memory only (interop tests)
        #[arg(long, requires = "insecure_dev", value_name = "UUID:SECRET")]
        dev_device: Vec<String>,
        /// Checkpoint interval in bytes (tests only; default 64 MiB)
        #[arg(long, hide = true)]
        checkpoint_bytes: Option<u64>,
        /// Free-space reserve in bytes (tests only; default 1 GiB)
        #[arg(long, hide = true)]
        reserve_bytes: Option<u64>,
        /// Also write an .xmp sidecar (date, location, favourite) in copy jobs; move jobs always do
        #[arg(long)]
        xmp: bool,
        /// VERIFY re-hashes every file before the phone may delete (slower, catches disk corruption)
        #[arg(long)]
        paranoid: bool,
        /// Test hook: stall the first checkpoint fsync this many ms
        #[arg(long, hide = true)]
        test_slow_writer_ms: Option<u64>,
        /// Test hook: read "free bytes" from this file instead of the disk
        #[arg(long, hide = true)]
        test_free_bytes_file: Option<PathBuf>,
        /// Test hook: free-space poll interval in ms while paused (default 5000)
        #[arg(long, hide = true)]
        free_poll_ms: Option<u64>,
        /// Test hook: peer-silence timeout in ms (default 30000)
        #[arg(long, hide = true)]
        peer_silence_ms: Option<u64>,
        /// Test hook: PAUSE{disk_slow} after the writer is blocked this many ms (default 20000)
        #[arg(long, hide = true)]
        disk_slow_ms: Option<u64>,
    },
    /// Manage paired iPhones
    Devices {
        #[command(subcommand)]
        cmd: DevicesCmd,
    },
    /// Discard sink for the iPhone throughput spikes (docs/SPIKES.md §0.3)
    SpikeSink {
        #[arg(long, default_value_t = 47899)]
        port: u16,
        /// Use the receiver's TLS profile (same cert, ALPN and pin)
        #[arg(long)]
        tls: bool,
        /// Also write per-connection CSV logs here
        #[arg(long)]
        log_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum DevicesCmd {
    /// List paired iPhones
    List,
    /// Remove a paired iPhone; it must pair again to connect
    Revoke { device_id: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let cli = Cli::parse();
    let config = match cli.config {
        Some(c) => c,
        None => directories::ProjectDirs::from("io.github", "iostransfer", "iostransfer")
            .context("no home directory")?
            .config_dir()
            .to_path_buf(),
    };
    create_private_dir(&config)?;
    match cli.cmd {
        Cmd::Pair { dest, port } => pair(&config, &dest, port).await,
        Cmd::Receive {
            dest,
            port,
            insecure_dev,
            dev_device,
            checkpoint_bytes,
            reserve_bytes,
            xmp,
            paranoid,
            test_slow_writer_ms,
            test_free_bytes_file,
            free_poll_ms,
            peer_silence_ms,
            disk_slow_ms,
        } => {
            let d = Limits::default();
            let ms = Duration::from_millis;
            let limits = Limits {
                checkpoint_bytes: checkpoint_bytes.unwrap_or(d.checkpoint_bytes).max(1),
                reserve_bytes: reserve_bytes.unwrap_or(d.reserve_bytes),
                xmp_always: xmp,
                paranoid,
                test_slow_writer: test_slow_writer_ms.map(ms),
                free_poll: free_poll_ms.map_or(d.free_poll, ms),
                peer_silence: peer_silence_ms.map_or(d.peer_silence, ms),
                disk_slow_after: disk_slow_ms.map_or(d.disk_slow_after, ms),
                ..d
            };
            receive(&config, &dest, port, insecure_dev, &dev_device, limits, test_free_bytes_file).await
        }
        Cmd::Devices { cmd } => devices(&config, cmd),
        Cmd::SpikeSink { port, tls, log_dir } => spike_sink(&config, port, tls, log_dir).await,
    }
}

fn create_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Config-dir files hold secrets: create owner-only, refuse to use them if too open (N16).
fn private_file(path: &Path) -> Result<()> {
    if path.exists() {
        check_owner_only(path)?;
    } else {
        write_owner_only(path, b"")?;
    }
    Ok(())
}

/// The destination may be exFAT/NTFS/SMB, where modes don't stick. It holds no secrets (N16a),
/// so owner-only is best effort there.
fn best_effort_private(path: &Path) {
    let exists = path.exists() || write_owner_only(path, b"").is_ok();
    #[cfg(unix)]
    if exists {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        if check_owner_only(path).is_err() {
            tracing::warn!("{} can't be made owner-only on this filesystem (fine: it holds no secrets)", path.display());
        }
    }
    #[cfg(not(unix))]
    let _ = exists;
}

fn open_devices(config: &Path) -> Result<DeviceDb> {
    let path = config.join("devices.db");
    private_file(&path)?;
    Ok(DeviceDb::open(&path)?)
}

fn open_index(dest: &Path) -> Result<Index> {
    let meta_dir = dest.join(".iostransfer");
    std::fs::create_dir_all(&meta_dir).with_context(|| format!("creating {}", meta_dir.display()))?;
    let path = meta_dir.join("index.db");
    best_effort_private(&path);
    Index::open(&path).map_err(|e| match e.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            anyhow::anyhow!("another iostransfer is already using {} (one receiver per destination)", dest.display())
        }
        _ => anyhow::Error::from(e).context(format!("opening {}", path.display())),
    })
}

fn pc_id(config: &Path) -> Result<String> {
    let path = config.join("pc_id");
    if let Ok(id) = std::fs::read_to_string(&path) {
        return Ok(id.trim().to_string());
    }
    let id = uuid::Uuid::new_v4().to_string();
    write_owner_only(&path, id.as_bytes())?;
    Ok(id)
}

fn pc_name() -> String {
    let name = gethostname::gethostname().to_string_lossy().into_owned();
    if name.is_empty() { "iostransfer-pc".into() } else { name }
}

fn build_ctx(
    config: &Path,
    dest: &Path,
    devices: DeviceDb,
    limits: Limits,
    confirm_pair: ConfirmPair,
    free_bytes_file: Option<PathBuf>,
) -> Result<Arc<Ctx>> {
    let index = open_index(dest)?;
    // Finish or roll back interrupted writes before accepting anything (PROTOCOL §10).
    recovery::recover(&index, dest).context("startup recovery")?;
    let free_dest = dest.to_path_buf();
    Ok(Arc::new(Ctx {
        devices: Mutex::new(devices),
        index: Mutex::new(index),
        dest: dest.to_path_buf(),
        sessions: Mutex::new(HashMap::new()),
        pc_id: pc_id(config)?,
        pc_name: pc_name(),
        limits,
        tokens: Mutex::new(HashMap::new()),
        free_bytes: match free_bytes_file {
            Some(f) => Arc::new(move || std::fs::read_to_string(&f).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)),
            None => Arc::new(move || fs4::available_space(&free_dest).unwrap_or(0)),
        },
        confirm_pair,
    }))
}

/// Addresses worth putting in the QR: private IPv4 on real adapters (no Docker, VM, VPN, link-local).
fn lan_ips() -> Vec<IpAddr> {
    const VIRTUAL: &[&str] =
        &["docker", "br-", "veth", "virbr", "vmnet", "vboxnet", "tun", "tap", "wg", "tailscale", "zt", "utun", "vethernet", "wsl", "hyper-v"];
    let mut ips: Vec<IpAddr> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| {
            let name = i.name.to_lowercase();
            !VIRTUAL.iter().any(|v| name.starts_with(v) || name.contains(v))
        })
        .map(|i| i.ip())
        .filter(|ip| matches!(ip, IpAddr::V4(v4) if v4.is_private()))
        .collect();
    ips.sort();
    ips.dedup();
    ips
}

fn advertise(pc_id: &str, ips: &[IpAddr], port: u16) -> Result<mdns_sd::ServiceDaemon> {
    let daemon = mdns_sd::ServiceDaemon::new()?;
    let host: String = pc_name().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
    let info = mdns_sd::ServiceInfo::new(
        SERVICE_TYPE,
        &format!("iostransfer-{}", &pc_id[..8]),
        &format!("{host}.local."),
        ips,
        port,
        &[("pcid", pc_id), ("v", "1")][..],
    )?;
    daemon.register(info)?;
    Ok(daemon)
}

fn print_qr(text: &str) -> Result<()> {
    let code = qrcode::QrCode::new(text.as_bytes())?;
    let img = code.render::<qrcode::render::unicode::Dense1x2>().quiet_zone(true).build();
    println!("{img}");
    Ok(())
}

/// One long-lived stdin reader: a blocking read can't be cancelled, so per-prompt readers would
/// leave stale threads that swallow the next answer.
fn stdin_lines() -> Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<String>>> {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        while std::io::stdin().read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
            if tx.send(std::mem::take(&mut line)).is_err() {
                break;
            }
        }
    });
    Arc::new(tokio::sync::Mutex::new(rx))
}

async fn pair(config: &Path, dest: &Path, port: u16) -> Result<()> {
    let id = Identity::load_or_create(config)?;
    let code = id.pairing_code();
    let lines = stdin_lines();
    let prompt_code = code.clone();
    let confirm: ConfirmPair = Arc::new(move |req| {
        let (code, lines) = (prompt_code.clone(), lines.clone());
        async move {
            let mut rx = lines.lock().await;
            while rx.try_recv().is_ok() {} // drop answers typed before this prompt
            print!(
                "\nPair \"{}\" ({})? The iPhone must show code {code}. [y/N] ",
                escape_for_terminal(&req.device_name),
                req.peer
            );
            let _ = std::io::stdout().flush();
            rx.recv().await.is_some_and(|l| l.trim().eq_ignore_ascii_case("y"))
        }
        .boxed()
    });
    let ctx = build_ctx(config, dest, open_devices(config)?, Limits::default(), confirm, None)?;
    let ips = lan_ips();
    if ips.is_empty() {
        bail!("no private IPv4 address found; connect this PC to the same Wi‑Fi/LAN as the iPhone");
    }
    // Any free port: `receive` may be holding the default one. The QR carries the port, so no
    // Bonjour advertisement is needed for pairing.
    let listener = TcpListener::bind(("0.0.0.0", port)).await.with_context(|| format!("port {port} is busy"))?;
    let port = listener.local_addr()?.port();
    let token = ctx.new_token();
    let hosts = ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
    let url = format!(
        "iost://pair?pcid={}&h={hosts}&p={port}&spki={}&t={token}&n={}",
        ctx.pc_id,
        id.pin_b64url(),
        percent_encode(&ctx.pc_name)
    );

    print_qr(&url)?;
    println!("Scan this with IOStransfer on the iPhone. Pairing code: {code}");
    println!("Listening on {hosts} port {port}. The QR expires in {} minutes.", TOKEN_TTL.as_secs() / 60);

    let (tx, mut rx) = mpsc::unbounded_channel();
    let on_session: OnSession = Arc::new(move |ctx, s| {
        if s.newly_paired {
            let _ = tx.send(s.device_name.clone());
        }
        session::run(ctx, s).boxed()
    });
    let acceptor = tls::acceptor(&id)?;
    tokio::select! {
        r = serve(listener, ctx, Some(acceptor), on_session) => r?,
        Some(name) = rx.recv() => {
            println!("Paired with \"{}\". Now run: iostransfer receive --dest {}", escape_for_terminal(&name), dest.display());
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        _ = tokio::time::sleep(TOKEN_TTL) => bail!("the pairing QR expired; run `iostransfer pair` again"),
    }
    Ok(())
}

/// Parse `--dev-device <uuid>:<64 lowercase hex>`.
fn dev_device(spec: &str) -> Result<(String, [u8; 32])> {
    let (id, secret) = spec.split_once(':').context("expected <uuid>:<64 hex>")?;
    let id = uuid::Uuid::parse_str(id).context("device id must be a UUID")?.hyphenated().to_string();
    let secret: [u8; 32] = hex::decode(secret).ok().and_then(|v| v.try_into().ok()).context("secret must be 64 hex chars")?;
    Ok((id, secret))
}

async fn receive(
    config: &Path,
    dest: &Path,
    port: u16,
    insecure_dev: bool,
    dev_devices: &[String],
    limits: Limits,
    free_bytes_file: Option<PathBuf>,
) -> Result<()> {
    let no_pairing: ConfirmPair = Arc::new(|_| async { false }.boxed());
    let on_session: OnSession = Arc::new(|ctx, s| session::run(ctx, s).boxed());
    std::fs::create_dir_all(dest).with_context(|| format!("creating {}", dest.display()))?;
    if insecure_dev {
        // Test devices live only in memory; devices.db is never touched in this mode.
        let devices = DeviceDb::open_in_memory()?;
        for spec in dev_devices {
            let (id, secret) = dev_device(spec)?;
            devices.put(&id, "dev-device", &secret, 0)?;
        }
        let ctx = build_ctx(config, dest, devices, limits, no_pairing, free_bytes_file)?;
        eprintln!("\x1b[31mWARNING: --insecure-dev: plaintext on 127.0.0.1 only. Never use with a real phone.\x1b[0m");
        let listener = TcpListener::bind(("127.0.0.1", port)).await?;
        println!("Listening on {}", listener.local_addr()?);
        return Ok(serve(listener, ctx, None, on_session).await?);
    }
    let id = Identity::load_or_create(config)?;
    let ctx = build_ctx(config, dest, open_devices(config)?, limits, no_pairing, free_bytes_file)?;
    #[cfg(windows)]
    firewall_hint();
    let ips = lan_ips();
    let listener = TcpListener::bind(("0.0.0.0", port)).await.with_context(|| format!("port {port} is busy"))?;
    let _mdns = advertise(&ctx.pc_id, &ips, port).map_err(|e| tracing::warn!("Bonjour advertising failed: {e}")).ok();
    let n = lock(&ctx.devices).list()?.len();
    println!("Receiving into {} on port {port} ({n} paired iPhone(s)). Ctrl+C to stop.", dest.display());
    tokio::select! {
        r = serve(listener, ctx, Some(tls::acceptor(&id)?), on_session) => r?,
        _ = tokio::signal::ctrl_c() => println!("Stopped."),
    }
    Ok(())
}

fn devices(config: &Path, cmd: DevicesCmd) -> Result<()> {
    let db = open_devices(config)?;
    match cmd {
        DevicesCmd::List => {
            let list = db.list()?;
            if list.is_empty() {
                println!("No paired iPhones. Run `iostransfer pair --dest <folder>`.");
            }
            for (id, name, _) in list {
                println!("{id}  {}", escape_for_terminal(&name));
            }
        }
        DevicesCmd::Revoke { device_id } => {
            if db.revoke(&device_id)? {
                println!("Revoked {device_id}.");
            } else {
                bail!("no paired device {device_id}");
            }
        }
    }
    Ok(())
}

async fn spike_sink(config: &Path, port: u16, use_tls: bool, log_dir: Option<PathBuf>) -> Result<()> {
    let acceptor = if use_tls { Some(tls::acceptor(&Identity::load_or_create(config)?)?) } else { None };
    if let Some(d) = &log_dir {
        std::fs::create_dir_all(d)?;
    }
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    println!("spike-sink on port {port} (tls: {use_tls}); timestamps are PC time in ms since epoch");
    println!("Note: spike-sink is UNAUTHENTICATED (dev tool, max {SINK_MAX_CONNS} connections). Stop it when done.");
    let conns = Arc::new(Semaphore::new(SINK_MAX_CONNS));
    let mut n = 0u64;
    loop {
        let (tcp, addr) = match listener.accept().await {
            Ok(a) => a,
            Err(e) => {
                eprintln!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = conns.clone().try_acquire_owned() else {
            eprintln!("{addr}: too many connections, dropped");
            continue;
        };
        n += 1;
        let (acceptor, log_dir) = (acceptor.clone(), log_dir.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let res = match acceptor {
                None => sink(tcp, n, addr, log_dir).await,
                Some(acc) => match tokio::time::timeout(Duration::from_secs(10), acc.accept(tcp)).await {
                    Ok(Ok(s)) if tls::alpn_ok(s.get_ref().1) => sink(s, n, addr, log_dir).await,
                    Ok(Ok(_)) => Err(anyhow::anyhow!("client did not offer ALPN iost/1")),
                    Ok(Err(e)) => Err(e.into()),
                    Err(_) => Err(anyhow::anyhow!("TLS handshake timed out")),
                },
            };
            if let Err(e) = res {
                eprintln!("conn {n} ({addr}): {e}");
            }
        });
    }
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

async fn sink<S: tokio::io::AsyncRead + Unpin>(mut s: S, n: u64, addr: std::net::SocketAddr, log_dir: Option<PathBuf>) -> Result<()> {
    let mut csv = match log_dir {
        Some(d) => {
            let mut f = std::fs::File::create(d.join(format!("sink-{n}-{}.csv", now_ms())))?;
            writeln!(f, "pc_ms,bytes_in_interval,total_bytes")?;
            Some(f)
        }
        None => None,
    };
    let mut buf = vec![0u8; 1 << 20];
    let (mut total, mut interval) = (0u64, 0u64);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.tick().await;
    println!("{} conn {n} from {addr} open", now_ms());
    loop {
        tokio::select! {
            r = s.read(&mut buf) => {
                let k = r?;
                if k == 0 { break; }
                total += k as u64;
                interval += k as u64;
            }
            _ = tick.tick() => {
                let ms = now_ms();
                println!("{ms} conn {n} {:.1} MB/s total {:.1} MB", interval as f64 / 1e6, total as f64 / 1e6);
                if let Some(f) = csv.as_mut() { writeln!(f, "{ms},{interval},{total}")?; }
                interval = 0;
            }
        }
    }
    let ms = now_ms();
    if let Some(f) = csv.as_mut() {
        writeln!(f, "{ms},{interval},{total}")?;
    }
    println!("{ms} conn {n} closed, total {:.1} MB", total as f64 / 1e6);
    Ok(())
}

/// Minimal percent-encoding for the QR's `n` (PC name) parameter.
fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Windows Firewall silently blocks the phone if the first-run prompt was dismissed (ARCHITECTURE §4.6).
#[cfg(windows)]
fn firewall_hint() {
    let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "iostransfer.exe".into());
    let has_rule = std::process::Command::new("netsh")
        .args(["advfirewall", "firewall", "show", "rule", "name=iostransfer"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !has_rule {
        println!("If the iPhone can't find this PC, allow iostransfer through Windows Firewall (run as administrator):");
        println!("  netsh advfirewall firewall add rule name=iostransfer dir=in action=allow program=\"{exe}\" enable=yes");
    }
}

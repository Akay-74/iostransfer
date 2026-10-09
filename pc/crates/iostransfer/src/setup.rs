//! First-run chores the double-click mode does by itself: a terminal window (Linux), the firewall,
//! Apple's USB service, opening folders.

use std::path::Path;
use std::process::Command;
#[cfg(unix)]
use std::process::Stdio;

use crate::console::Console;

/// Started from a file manager, Linux gives us no terminal: reopen inside one. Returns true when a
/// terminal was started (this process should then exit).
#[cfg(unix)]
pub fn relaunch_in_terminal() -> bool {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() || std::env::var_os("IOST_IN_TERMINAL").is_some() {
        return false;
    }
    if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
        return false;
    }
    let Ok(exe) = std::env::current_exe() else { return false };
    let mut candidates: Vec<(String, Vec<&str>)> = Vec::new();
    if let Ok(t) = std::env::var("TERMINAL") {
        candidates.push((t, vec!["-e"]));
    }
    for (t, args) in [
        ("x-terminal-emulator", vec!["-e"]),
        ("konsole", vec!["-e"]),
        ("ptyxis", vec!["--"]),
        ("gnome-terminal", vec!["--"]),
        ("kgx", vec!["-e"]),
        ("xfce4-terminal", vec!["-x"]),
        ("mate-terminal", vec!["-x"]),
        ("tilix", vec!["-e"]),
        ("alacritty", vec!["-e"]),
        ("kitty", vec![]),
        ("wezterm", vec!["start", "--"]),
        ("foot", vec![]),
        ("xterm", vec!["-e"]),
    ] {
        candidates.push((t.to_string(), args));
    }
    for (term, args) in candidates {
        let spawned = Command::new(&term)
            .args(&args)
            .arg(&exe)
            .env("IOST_IN_TERMINAL", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        if spawned.is_ok() {
            return true;
        }
    }
    false
}

#[cfg(windows)]
pub fn relaunch_in_terminal() -> bool {
    false // a console program always gets a console window on Windows
}

/// Open a folder or URL with the desktop's default app.
pub fn open(target: &str) {
    #[cfg(windows)]
    let r = Command::new("explorer").arg(target).spawn();
    #[cfg(not(windows))]
    let r = Command::new("xdg-open").arg(target).stdout(Stdio::null()).stderr(Stdio::null()).spawn();
    if r.is_err() {
        println!("Open {target}");
    }
}

pub fn open_path(p: &Path) {
    open(&p.display().to_string());
}

// ---------------------------------------------------------------------------------------------
// Firewall

/// Make sure the phone can reach `port`. Returns a short status line.
#[cfg(windows)]
pub async fn firewall(_console: &Console, _port: u16) -> String {
    let Ok(exe) = std::env::current_exe() else { return "firewall: unknown program path".into() };
    let exe = exe.display().to_string();
    if windows_rule_ok(&exe) {
        return "Windows Firewall: allowed".into();
    }
    println!("Windows will ask for permission to let IOStransfer through the firewall (one time only).");
    let cmd = format!(
        "/c \"netsh advfirewall firewall delete rule name=iostransfer >nul 2>&1 & \
         netsh advfirewall firewall add rule name=iostransfer dir=in action=allow program=\"{exe}\" enable=yes profile=any\""
    );
    if !run_elevated("cmd.exe", &cmd) {
        return "Windows Firewall: not changed (permission declined). If the iPhone can't connect, run IOStransfer again and click Yes.".into();
    }
    if windows_rule_ok(&exe) {
        "Windows Firewall: allowed".into()
    } else {
        "Windows Firewall: rule could not be added; the iPhone may not be able to connect".into()
    }
}

#[cfg(windows)]
fn windows_rule_ok(exe: &str) -> bool {
    Command::new("netsh")
        .args(["advfirewall", "firewall", "show", "rule", "name=iostransfer", "verbose"])
        .output()
        .is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).to_lowercase().contains(&exe.to_lowercase()))
}

/// Run a program as administrator (UAC prompt) and wait for it. False if declined or failed.
#[cfg(windows)]
pub fn run_elevated(file: &str, params: &str) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
    use windows_sys::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;
    let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let (verb, file, params) = (wide("runas"), wide(file), wide(params));
    // SAFETY: SHELLEXECUTEINFOW is plain data; the string pointers outlive the call.
    unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = params.as_ptr();
        info.nShow = SW_HIDE;
        if ShellExecuteExW(&mut info) == 0 || info.hProcess.is_null() {
            return false;
        }
        WaitForSingleObject(info.hProcess, INFINITE);
        let mut code = 1u32;
        GetExitCodeProcess(info.hProcess, &mut code);
        CloseHandle(info.hProcess);
        code == 0
    }
}

#[cfg(unix)]
pub async fn firewall(console: &Console, port: u16) -> String {
    if active("firewall-cmd", &["--state"], "running") {
        let ports = output("firewall-cmd", &["--list-ports"]);
        if port_listed(&ports, port) {
            return "firewall (firewalld): allowed".into();
        }
        if !console.yes(&format!("The firewall blocks port {port}, so the iPhone can't connect. Open it? (asks for your password)"), true).await {
            return "firewall: not changed".into();
        }
        let script = format!("firewall-cmd --permanent --add-port={port}/tcp --add-service=mdns && firewall-cmd --reload");
        return if pkexec(&script) { "firewall (firewalld): opened".into() } else { "firewall: could not open the port".into() };
    }
    if active("systemctl", &["is-active", "ufw"], "active") {
        let script = format!("ufw allow {port}/tcp && ufw allow 5353/udp");
        return if pkexec(&script) { "firewall (ufw): allowed".into() } else { "firewall (ufw): could not open the port".into() };
    }
    "firewall: none active".into()
}

#[cfg(unix)]
fn active(cmd: &str, args: &[&str], want: &str) -> bool {
    output(cmd, args).trim() == want
}

#[cfg(unix)]
fn output(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .stderr(Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

#[cfg_attr(windows, allow(dead_code))]
/// Does a firewalld `--list-ports` line ("1025-65535/tcp 47800/tcp …") cover `port`/tcp?
pub fn port_listed(list: &str, port: u16) -> bool {
    list.split_whitespace().any(|e| {
        let Some((range, proto)) = e.split_once('/') else { return false };
        if proto != "tcp" {
            return false;
        }
        let (lo, hi) = range.split_once('-').unwrap_or((range, range));
        matches!((lo.parse::<u16>(), hi.parse::<u16>()), (Ok(lo), Ok(hi)) if lo <= port && port <= hi)
    })
}

/// Run a shell snippet as root through polkit (graphical password prompt).
#[cfg(unix)]
pub fn pkexec(script: &str) -> bool {
    Command::new("pkexec").args(["sh", "-c", script]).status().is_ok_and(|s| s.success())
}

// ---------------------------------------------------------------------------------------------
// Apple USB service (usbmuxd)

/// Make sure the iPhone USB service is installed. True when it can be reached now.
pub async fn usb_service(console: &Console) -> bool {
    if idevice::usbmuxd::UsbmuxdConnection::default().await.is_ok() {
        return true;
    }
    install_usb_service(console).await;
    idevice::usbmuxd::UsbmuxdConnection::default().await.is_ok()
}

#[cfg(windows)]
async fn install_usb_service(console: &Console) {
    println!("Windows needs Apple's iPhone USB driver, which comes with iTunes.");
    if !console.yes("Install it now? (free, from Apple, ~5 minutes)", true).await {
        return;
    }
    let ok = Command::new("winget")
        .args(["install", "-e", "--id", "Apple.iTunes", "--accept-package-agreements", "--accept-source-agreements"])
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        println!("Automatic install didn't work. Opening Apple's download page: install iTunes, then come back here.");
        open("https://www.apple.com/itunes/download/win64");
        let _ = console.ask("Press Enter when iTunes is installed… ").await;
    }
    // The Apple Mobile Device Service starts a few seconds after installing.
    for _ in 0..15 {
        if idevice::usbmuxd::UsbmuxdConnection::default().await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

#[cfg(unix)]
async fn install_usb_service(console: &Console) {
    let installed = ["/usr/sbin/usbmuxd", "/usr/bin/usbmuxd", "/sbin/usbmuxd"].iter().any(|p| Path::new(p).exists());
    if installed {
        // Started by udev when an iPhone is plugged in; nothing to install.
        return;
    }
    let pm = [
        ("dnf", "dnf install -y usbmuxd"),
        ("apt-get", "apt-get install -y usbmuxd"),
        ("pacman", "pacman -S --noconfirm usbmuxd"),
        ("zypper", "zypper --non-interactive install usbmuxd"),
    ]
    .into_iter()
    .find(|(bin, _)| Command::new("which").arg(bin).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success()));
    let Some((_, cmd)) = pm else {
        println!("Install the `usbmuxd` package with your package manager, then try again.");
        return;
    };
    if console.yes("The iPhone USB service (usbmuxd) is missing. Install it? (asks for your password)", true).await {
        pkexec(cmd);
    }
}

#[cfg(test)]
mod tests {
    use super::port_listed;

    #[test]
    fn firewalld_ports() {
        assert!(port_listed("1025-65535/tcp 1025-65535/udp", 47800));
        assert!(port_listed("22/tcp 47800/tcp", 47800));
        assert!(!port_listed("47800/udp", 47800));
        assert!(!port_listed("1-1024/tcp", 47800));
        assert!(!port_listed("", 47800));
        assert!(!port_listed("x/tcp", 47800));
    }
}

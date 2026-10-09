//! One stdin reader shared by every prompt. A blocking read can't be cancelled, so a single
//! long-lived thread reads lines and hands each one to whoever is waiting: a prompt (pairing
//! confirmation, Apple ID, 2FA code) before the idle command line.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Arc, Condvar, Mutex};

use tokio::sync::oneshot;

struct Waiter {
    prompt: bool,
    secret: bool,
    tx: oneshot::Sender<String>,
}

#[derive(Default)]
struct State {
    waiters: VecDeque<Waiter>,
    eof: bool,
}

pub struct Console {
    state: Mutex<State>,
    wake: Condvar,
    /// Serializes prompts, so two questions never interleave on screen.
    turn: tokio::sync::Mutex<()>,
}

impl Console {
    pub fn new() -> Arc<Self> {
        let c = Arc::new(Self { state: Mutex::default(), wake: Condvar::new(), turn: tokio::sync::Mutex::new(()) });
        let reader = c.clone();
        std::thread::spawn(move || reader.read_loop());
        c
    }

    fn read_loop(&self) {
        let mut line = String::new();
        loop {
            {
                let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
                while !st.waiters.iter().any(|w| !w.tx.is_closed()) {
                    st.waiters.clear();
                    st = self.wake.wait(st).unwrap_or_else(|e| e.into_inner());
                }
            }
            line.clear();
            let ok = std::io::stdin().read_line(&mut line).map(|n| n > 0).unwrap_or(false);
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if !ok {
                st.eof = true;
                st.waiters.clear(); // dropping the senders answers everyone with None
                return;
            }
            st.waiters.retain(|w| !w.tx.is_closed());
            let pick = st.waiters.iter().position(|w| w.prompt).or(if st.waiters.is_empty() { None } else { Some(0) });
            if let Some(i) = pick
                && let Some(w) = st.waiters.remove(i)
            {
                if w.secret {
                    set_echo(true);
                    println!();
                }
                let _ = w.tx.send(line.trim_end_matches(['\r', '\n']).to_string());
            }
        }
    }

    async fn line(&self, prompt: bool, secret: bool) -> Option<String> {
        let (tx, rx) = oneshot::channel();
        {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if st.eof {
                return None;
            }
            st.waiters.push_back(Waiter { prompt, secret, tx });
        }
        if secret {
            set_echo(false);
        }
        self.wake.notify_one();
        let _restore = EchoGuard(secret);
        rx.await.ok()
    }

    /// Ask a question and wait for the answer (None when stdin is closed).
    pub async fn ask(&self, question: &str) -> Option<String> {
        let _turn = self.turn.lock().await;
        print!("{question}");
        let _ = std::io::stdout().flush();
        self.line(true, false).await
    }

    /// Like [`Self::ask`], without echoing what is typed (passwords).
    pub async fn ask_secret(&self, question: &str) -> Option<String> {
        let _turn = self.turn.lock().await;
        print!("{question}");
        let _ = std::io::stdout().flush();
        self.line(true, true).await
    }

    /// The idle command line: gets a line only when no prompt is waiting.
    pub async fn command(&self) -> Option<String> {
        self.line(false, false).await
    }

    pub async fn yes(&self, question: &str, default_yes: bool) -> bool {
        let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
        match self.ask(&format!("{question} {hint} ")).await {
            Some(a) if a.trim().is_empty() => default_yes,
            Some(a) => a.trim().eq_ignore_ascii_case("y") || a.trim().eq_ignore_ascii_case("yes"),
            None => false,
        }
    }
}

/// Turns echo back on if a password prompt is abandoned (timeout, cancel).
struct EchoGuard(bool);

impl Drop for EchoGuard {
    fn drop(&mut self) {
        if self.0 {
            set_echo(true);
        }
    }
}

#[cfg(unix)]
fn set_echo(on: bool) {
    // SAFETY: tcgetattr/tcsetattr on fd 0 with a zeroed, then filled-in termios.
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(0, &mut t) != 0 {
            return;
        }
        if on {
            t.c_lflag |= libc::ECHO;
        } else {
            t.c_lflag &= !libc::ECHO;
        }
        libc::tcsetattr(0, libc::TCSANOW, &t);
    }
}

#[cfg(windows)]
fn set_echo(on: bool) {
    use windows_sys::Win32::System::Console::{ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode};
    // SAFETY: plain console-mode calls on our own stdin handle.
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode = 0;
        if GetConsoleMode(h, &mut mode) == 0 {
            return;
        }
        let mode = if on { mode | ENABLE_ECHO_INPUT } else { mode & !ENABLE_ECHO_INPUT };
        SetConsoleMode(h, mode);
    }
}

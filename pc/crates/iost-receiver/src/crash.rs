//! Crash injection for tests (THREAT_MODEL N22, WRITER_TESTS §1.6).
//!
//! `IOST_CRASH_AT=<point>[:<arg>]`, optional `IOST_CRASH_KEY=<res_key>` and `IOST_CRASH_NTH=<k>`.
//! The receiver calls `abort()` at the point: no destructors, no buffered-writer flush.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

struct Spec {
    point: String,
    arg: Option<u64>,
    key: Option<String>,
    nth: u64,
    hits: AtomicU64,
}

fn spec() -> Option<&'static Spec> {
    static SPEC: OnceLock<Option<Spec>> = OnceLock::new();
    SPEC.get_or_init(|| {
        let raw = std::env::var("IOST_CRASH_AT").ok()?;
        let (point, arg) = match raw.split_once(':') {
            Some((p, a)) => (p.to_string(), a.parse().ok()),
            None => (raw, None),
        };
        Some(Spec {
            point,
            arg,
            key: std::env::var("IOST_CRASH_KEY").ok(),
            nth: std::env::var("IOST_CRASH_NTH").ok().and_then(|n| n.parse().ok()).unwrap_or(1),
            hits: AtomicU64::new(0),
        })
    })
    .as_ref()
}

fn fire(s: &Spec) {
    if s.hits.fetch_add(1, Ordering::SeqCst) + 1 == s.nth {
        eprintln!("IOST_CRASH_AT={} firing", s.point);
        std::process::abort();
    }
}

/// Crash at a named point (`P2`, `P3`, `P4`, `P5`, `X1`, `R1`) for resource `key`.
pub fn at(point: &str, key: &str) {
    if let Some(s) = spec()
        && s.point == point && s.key.as_deref().is_none_or(|k| k == key) {
            fire(s);
        }
}

/// `P1:<n>`: after the DATA chunk that brings `written` to at least n.
pub fn at_bytes(written_before: u64, written: u64, key: &str) {
    if let Some(s) = spec()
        && s.point == "P1"
            && s.key.as_deref().is_none_or(|k| k == key)
            && s.arg.is_some_and(|n| written_before < n && written >= n)
        {
            fire(s);
        }
}

//! Post-handshake session task: liveness, phone logs, supersede, and frame pumping between the
//! socket and the session's [`Engine`] thread.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use iost_proto::msg::{Bye, Pause, Resume};
use iost_proto::{Frame, FrameType};
use serde::Deserialize;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, MissedTickBehavior};
use tracing::{info, warn};

use crate::engine::{Engine, In, Out};
use crate::handshake::Ctx;
use crate::server::Session;
use crate::text::escape_for_terminal;
use crate::lock;

/// Frames queued for the writer thread before we stop reading the socket (backpressure).
const ENGINE_QUEUE: usize = 64;
const BYE_TIMEOUT: Duration = Duration::from_secs(2);
const HOUSEKEEPING: Duration = Duration::from_millis(250);

#[derive(Deserialize)]
struct Log {
    lvl: String,
    msg: String,
}

pub async fn run(ctx: Arc<Ctx>, mut s: Session) {
    let device = escape_for_terminal(&s.device_name);

    // Supersede: tell an older session of this device to stop, then wait until its writer has
    // committed exact offsets before we compute any NEED (§4.2).
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let device_lock = {
        let mut reg = lock(&ctx.sessions);
        let entry = reg.entry(s.device_id.clone()).or_default();
        if let Some(old) = entry.cancel.replace(cancel_tx.clone()) {
            let _ = old.send(true);
        }
        entry.lock.clone()
    };
    let _guard = device_lock.lock_owned().await;

    let (engine_tx, engine_rx) = mpsc::channel::<In>(ENGINE_QUEUE);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Out>();
    let engine = Engine::new(ctx.clone(), s.device_id.clone(), s.device_name.clone(), out_tx);
    let writer = tokio::task::spawn_blocking(move || engine.run(engine_rx));

    let limits = ctx.limits;
    // Backpressure (Δ15): when the writer queue is full we hold one frame and stop reading the
    // socket; TCP then slows the phone down. While we're deliberately not reading, the phone's
    // silence is our own doing, so the peer-silence timer is suspended.
    let mut pending: Option<Frame> = None;
    let mut blocked_since: Option<Instant> = None;
    let mut slow_paused = false;
    let (mut last_in, mut last_out) = (Instant::now(), Instant::now());
    let mut ping_n = 0u64;
    let mut free_poll = tokio::time::interval(limits.free_poll);
    free_poll.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut housekeeping = tokio::time::interval(HOUSEKEEPING.min(limits.peer_silence / 2));
    housekeeping.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            _ = cancel_rx.changed() => {
                info!(%device, "superseded by a new session");
                bye(&mut s, "superseded").await;
                break;
            }
            out = out_rx.recv() => match out {
                Some(Out::Frame(f)) => {
                    if s.framed.send(f).await.is_err() {
                        break;
                    }
                    last_out = Instant::now();
                }
                Some(Out::Close) | None => break,
            },
            permit = engine_tx.reserve(), if pending.is_some() => {
                let Ok(permit) = permit else { break };
                permit.send(In::Frame(pending.take().expect("guarded")));
                blocked_since = None;
                last_in = Instant::now();
                if slow_paused {
                    slow_paused = false;
                    if send_json(&mut s, FrameType::Resume, &Resume {}).await.is_err() {
                        break;
                    }
                }
            }
            next = s.framed.next(), if pending.is_none() => {
                last_in = Instant::now();
                let frame = match next {
                    None => break,
                    Some(Err(e)) => {
                        warn!(%device, "decode error: {e}");
                        bye(&mut s, "protocol_error").await;
                        break;
                    }
                    Some(Ok(f)) => f,
                };
                match frame.ty {
                    FrameType::Ping => {
                        if s.framed.send(Frame { ty: FrameType::Pong, payload: frame.payload }).await.is_err() {
                            break;
                        }
                        last_out = Instant::now();
                    }
                    FrameType::Pong => {}
                    FrameType::Log => {
                        if let Ok(l) = serde_json::from_slice::<Log>(&frame.payload) {
                            info!(target: "phone", "[{device}] {} {}", escape_for_terminal(&l.lvl), escape_for_terminal(&l.msg));
                        }
                    }
                    FrameType::Bye => break,
                    _ => match engine_tx.try_send(In::Frame(frame)) {
                        Ok(()) => {}
                        Err(TrySendError::Full(In::Frame(f))) => {
                            pending = Some(f);
                            blocked_since = Some(Instant::now());
                        }
                        Err(_) => break,
                    },
                }
            }
            _ = free_poll.tick() => {
                let _ = engine_tx.try_send(In::Tick);
            }
            _ = housekeeping.tick() => {
                if pending.is_none() && last_in.elapsed() >= limits.peer_silence {
                    warn!(%device, "no frames for {:?}, closing", limits.peer_silence);
                    bye(&mut s, "timeout").await;
                    break;
                }
                if last_out.elapsed() >= limits.ping_after {
                    ping_n += 1;
                    if send_json(&mut s, FrameType::Ping, &serde_json::json!({ "n": ping_n })).await.is_err() {
                        break;
                    }
                    last_out = Instant::now();
                }
                if !slow_paused && blocked_since.is_some_and(|t| t.elapsed() >= limits.disk_slow_after) {
                    slow_paused = true;
                    if send_json(&mut s, FrameType::Pause, &Pause { why: "disk_slow".into() }).await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    // Close the writer's queue and wait until every open .part is durable at its exact length.
    drop(engine_tx);
    let _ = writer.await;
    // Frames the writer produced while shutting down (e.g. its final ACKs) are best effort.
    while let Ok(Out::Frame(f)) = out_rx.try_recv() {
        if tokio::time::timeout(BYE_TIMEOUT, s.framed.send(f)).await.is_err() {
            break;
        }
    }
    let mut reg = lock(&ctx.sessions);
    if let Some(entry) = reg.get_mut(&s.device_id)
        && entry.cancel.as_ref().is_some_and(|c| c.same_channel(&cancel_tx)) {
            entry.cancel = None;
        }
}

async fn send_json<T: serde::Serialize>(s: &mut Session, ty: FrameType, msg: &T) -> Result<(), ()> {
    match tokio::time::timeout(BYE_TIMEOUT, s.framed.send(Frame::json(ty, msg))).await {
        Ok(Ok(())) => Ok(()),
        _ => Err(()),
    }
}

async fn bye(s: &mut Session, code: &str) {
    let _ = tokio::time::timeout(BYE_TIMEOUT, s.framed.send(Frame::json(FrameType::Bye, &Bye::code(code)))).await;
}

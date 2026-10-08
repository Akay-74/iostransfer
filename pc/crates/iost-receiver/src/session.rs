//! Post-handshake session task: liveness, phone logs, supersede, and frame pumping between the
//! socket and the session's [`Engine`] thread.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use iost_proto::msg::Bye;
use iost_proto::{Frame, FrameType};
use serde::Deserialize;
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use crate::engine::{Engine, Out};
use crate::handshake::Ctx;
use crate::server::Session;
use crate::text::escape_for_terminal;
use crate::lock;

/// Frames queued for the writer thread before we stop reading the socket (backpressure).
const ENGINE_QUEUE: usize = 64;
const BYE_TIMEOUT: Duration = Duration::from_secs(2);

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

    let (engine_tx, engine_rx) = mpsc::channel::<Frame>(ENGINE_QUEUE);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Out>();
    let engine = Engine::new(ctx.clone(), s.device_id.clone(), s.device_name.clone(), out_tx);
    let writer = tokio::task::spawn_blocking(move || engine.run(engine_rx));

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
                }
                Some(Out::Close) | None => break,
            },
            next = tokio::time::timeout(ctx.limits.peer_silence, s.framed.next()) => {
                let frame = match next {
                    Err(_) => {
                        warn!(%device, "no frames for {:?}, closing", ctx.limits.peer_silence);
                        bye(&mut s, "timeout").await;
                        break;
                    }
                    Ok(None) => break,
                    Ok(Some(Err(e))) => {
                        warn!(%device, "decode error: {e}");
                        bye(&mut s, "protocol_error").await;
                        break;
                    }
                    Ok(Some(Ok(f))) => f,
                };
                match frame.ty {
                    FrameType::Ping => {
                        if s.framed.send(Frame { ty: FrameType::Pong, payload: frame.payload }).await.is_err() {
                            break;
                        }
                    }
                    FrameType::Pong => {}
                    FrameType::Log => {
                        if let Ok(l) = serde_json::from_slice::<Log>(&frame.payload) {
                            info!(target: "phone", "[{device}] {} {}", escape_for_terminal(&l.lvl), escape_for_terminal(&l.msg));
                        }
                    }
                    FrameType::Bye => break,
                    _ => {
                        if engine_tx.send(frame).await.is_err() {
                            break;
                        }
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

async fn bye(s: &mut Session, code: &str) {
    let _ = tokio::time::timeout(BYE_TIMEOUT, s.framed.send(Frame::json(FrameType::Bye, &Bye::code(code)))).await;
}

//! IOStransfer wire protocol v1 (docs/PROTOCOL.md is normative).

pub mod auth;
pub mod frame;
pub mod msg;

pub use frame::{DataChunk, Frame, FrameCodec, FrameError, FrameType};

/// PROTOCOL §1.2: sent by both sides right after the transport is ready.
pub const PREFACE: [u8; 8] = *b"IOST\x01\0\0\0";
/// PROTOCOL §2: 1 MiB + 16.
pub const MAX_FRAME_LEN: usize = 1_048_592;
/// PROTOCOL §2: max bytes carried by one DATA frame.
pub const MAX_CHUNK: usize = 262_144;

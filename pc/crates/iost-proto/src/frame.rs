//! Framing (PROTOCOL §2): `u32 BE len | u8 type | payload`, len = 1 + payload length.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::{MAX_CHUNK, MAX_FRAME_LEN};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Hello = 0x01,
    Welcome = 0x02,
    Challenge = 0x03,
    Auth = 0x04,
    Paired = 0x05,
    Manifest = 0x10,
    Need = 0x11,
    NeedMore = 0x12,
    ResBegin = 0x20,
    Data = 0x21,
    ResEnd = 0x22,
    ResAbort = 0x23,
    AssetEnd = 0x24,
    Ack = 0x30,
    ResNack = 0x31,
    Verify = 0x40,
    Verified = 0x41,
    Pause = 0x50,
    Resume = 0x51,
    Log = 0x60,
    Ping = 0x70,
    Pong = 0x71,
    Bye = 0x7F,
}

impl TryFrom<u8> for FrameType {
    type Error = FrameError;
    fn try_from(b: u8) -> Result<Self, FrameError> {
        use FrameType::*;
        Ok(match b {
            0x01 => Hello,
            0x02 => Welcome,
            0x03 => Challenge,
            0x04 => Auth,
            0x05 => Paired,
            0x10 => Manifest,
            0x11 => Need,
            0x12 => NeedMore,
            0x20 => ResBegin,
            0x21 => Data,
            0x22 => ResEnd,
            0x23 => ResAbort,
            0x24 => AssetEnd,
            0x30 => Ack,
            0x31 => ResNack,
            0x40 => Verify,
            0x41 => Verified,
            0x50 => Pause,
            0x51 => Resume,
            0x60 => Log,
            0x70 => Ping,
            0x71 => Pong,
            0x7F => Bye,
            other => return Err(FrameError::UnknownType(other)),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame length {0} out of range")]
    BadLength(usize),
    #[error("unknown frame type 0x{0:02x}")]
    UnknownType(u8),
    #[error("DATA payload too short or chunk empty/oversized")]
    BadData,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub ty: FrameType,
    pub payload: Bytes,
}

impl Frame {
    /// Control frame with a JSON payload.
    pub fn json<T: serde::Serialize>(ty: FrameType, msg: &T) -> Self {
        let payload = serde_json::to_vec(msg).expect("control messages always serialize");
        Frame { ty, payload: payload.into() }
    }

    pub fn data(chunk: &DataChunk) -> Self {
        let mut b = BytesMut::with_capacity(10 + chunk.bytes.len());
        b.put_u16(chunk.slot);
        b.put_u64(chunk.offset);
        b.put_slice(&chunk.bytes);
        Frame { ty: FrameType::Data, payload: b.freeze() }
    }

    pub fn as_data(&self) -> Result<DataChunk, FrameError> {
        if self.ty != FrameType::Data || self.payload.len() < 11 {
            return Err(FrameError::BadData);
        }
        let mut p = self.payload.clone();
        let slot = p.get_u16();
        let offset = p.get_u64();
        if p.len() > MAX_CHUNK {
            return Err(FrameError::BadData);
        }
        Ok(DataChunk { slot, offset, bytes: p })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataChunk {
    pub slot: u16,
    pub offset: u64,
    pub bytes: Bytes,
}

/// Not reusable after it returns `Err`: the connection must be closed (part of the bad frame may
/// already be consumed).
#[derive(Debug, Default)]
pub struct FrameCodec;

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = FrameError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Frame>, FrameError> {
        if src.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes(src[..4].try_into().unwrap()) as usize;
        if len == 0 || len > MAX_FRAME_LEN {
            return Err(FrameError::BadLength(len));
        }
        if src.len() < 4 + len {
            src.reserve(4 + len - src.len());
            return Ok(None);
        }
        src.advance(4);
        let ty = FrameType::try_from(src.get_u8())?;
        let payload = src.split_to(len - 1).freeze();
        Ok(Some(Frame { ty, payload }))
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = FrameError;

    fn encode(&mut self, f: Frame, dst: &mut BytesMut) -> Result<(), FrameError> {
        let len = 1 + f.payload.len();
        if len > MAX_FRAME_LEN {
            return Err(FrameError::BadLength(len));
        }
        dst.reserve(4 + len);
        dst.put_u32(len as u32);
        dst.put_u8(f.ty as u8);
        dst.put_slice(&f.payload);
        Ok(())
    }
}

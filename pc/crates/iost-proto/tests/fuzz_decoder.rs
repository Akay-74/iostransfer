//! Hostile bytes from the LAN must never panic the decoder, and it must never
//! buffer more than one maximum-size frame.

use bytes::BytesMut;
use iost_proto::{DataChunk, Frame, FrameCodec, FrameType, MAX_FRAME_LEN};
use proptest::prelude::*;
use tokio_util::codec::{Decoder, Encoder};

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic(input in proptest::collection::vec(any::<u8>(), 0..4096),
                                   split in 0usize..4096) {
        fn drain(buf: &mut BytesMut) -> bool {
            loop {
                match FrameCodec.decode(buf) {
                    Ok(Some(f)) => { let _ = f.as_data(); }
                    Ok(None) => return true,
                    Err(_) => return false,
                }
            }
        }
        let split = split.min(input.len());
        let mut buf = BytesMut::from(&input[..split]);
        if drain(&mut buf) {
            buf.extend_from_slice(&input[split..]);
            drain(&mut buf);
        }
        prop_assert!(buf.capacity() <= 4 + MAX_FRAME_LEN + 8192);
    }

    #[test]
    fn data_roundtrip_any_split(slot: u16, offset: u64,
                                bytes in proptest::collection::vec(any::<u8>(), 1..2048),
                                split in 0usize..2100) {
        let chunk = DataChunk { slot, offset, bytes: bytes.into() };
        let mut wire = BytesMut::new();
        FrameCodec.encode(Frame::data(&chunk), &mut wire).unwrap();
        let split = split.min(wire.len());
        let mut buf = BytesMut::from(&wire[..split]);
        let first = FrameCodec.decode(&mut buf).unwrap();
        let f = match first {
            Some(f) => f,
            None => { buf.extend_from_slice(&wire[split..]); FrameCodec.decode(&mut buf).unwrap().unwrap() }
        };
        prop_assert_eq!(f.ty, FrameType::Data);
        prop_assert_eq!(f.as_data().unwrap(), chunk);
    }
}

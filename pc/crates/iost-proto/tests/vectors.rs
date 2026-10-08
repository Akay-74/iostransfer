//! Shared vectors from testdata/protocol-vectors.json (the Swift TransferCore loads the same file).

use bytes::BytesMut;
use iost_proto::{auth, DataChunk, Frame, FrameCodec, FrameError, FrameType, MAX_CHUNK, MAX_FRAME_LEN, PREFACE};
use serde_json::{Map, Value};
use tokio_util::codec::{Decoder, Encoder};

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../testdata/protocol-vectors.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn encode(f: Frame) -> Vec<u8> {
    let mut b = BytesMut::new();
    FrameCodec.encode(f, &mut b).unwrap();
    b.to_vec()
}

fn gen_input(g: &Value) -> Vec<u8> {
    let ty = g["type"].as_u64().unwrap() as u8;
    let mut out = (g["header_len"].as_u64().unwrap() as u32).to_be_bytes().to_vec();
    out.push(ty);
    if ty == FrameType::Data as u8 {
        out.extend((g["slot"].as_u64().unwrap() as u16).to_be_bytes());
        out.extend(g["offset"].as_u64().unwrap().to_be_bytes());
    }
    let fill = unhex(&g["payload_fill"])[0];
    out.resize(out.len() + g["payload_len"].as_u64().unwrap() as usize, fill);
    out
}

fn error_name(e: &FrameError) -> &'static str {
    match e {
        FrameError::BadLength(_) => "bad_length",
        FrameError::UnknownType(_) => "unknown_type",
        FrameError::BadData => "bad_data",
        FrameError::Io(_) => "io",
    }
}

fn preface_result(input: &[u8]) -> &'static str {
    if input.len() < PREFACE.len() {
        "need_more"
    } else if input[..8] == PREFACE {
        "ok"
    } else {
        "bad_preface"
    }
}

/// Decode one frame and apply the layer named by `stage`.
fn frame_result(stage: &str, input: &[u8]) -> &'static str {
    let mut buf = BytesMut::from(input);
    let frame = match FrameCodec.decode(&mut buf) {
        Ok(None) => return "need_more",
        Err(e) => return error_name(&e),
        Ok(Some(f)) => f,
    };
    match stage {
        "data" => frame.as_data().map_or_else(|e| error_name(&e), |_| "ok"),
        "message" => serde_json::from_slice::<Map<String, Value>>(&frame.payload).map_or("bad_json", |_| "ok"),
        _ => "ok",
    }
}

#[test]
fn constants() {
    let c = &vectors()["constants"];
    assert_eq!(c["max_frame_len"], MAX_FRAME_LEN);
    assert_eq!(c["max_chunk"], MAX_CHUNK);
    assert_eq!(unhex(&c["preface_hex"]), PREFACE);
}

#[test]
fn frames() {
    for v in vectors()["frames"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let wire = unhex(&v["hex"]);
        let mut buf = BytesMut::from(&wire[..]);
        let f = FrameCodec.decode(&mut buf).unwrap().unwrap();
        assert!(buf.is_empty(), "{name}");
        assert_eq!(f.ty as u64, v["type"].as_u64().unwrap(), "{name}");
        if v["kind"] == "data" {
            let chunk = DataChunk {
                slot: v["slot"].as_u64().unwrap() as u16,
                offset: v["offset"].as_u64().unwrap(),
                bytes: unhex(&v["bytes_hex"]).into(),
            };
            assert_eq!(f.as_data().unwrap(), chunk, "{name}");
            assert_eq!(encode(Frame::data(&chunk)), wire, "{name}: DATA encoding is byte-exact");
        } else {
            let expected: Value = serde_json::from_str(v["json_text"].as_str().unwrap()).unwrap();
            let got: Value = serde_json::from_slice(&f.payload).unwrap();
            assert_eq!(got, expected, "{name}");
            let reencoded = encode(Frame::json(f.ty, &got));
            let back = FrameCodec.decode(&mut BytesMut::from(&reencoded[..])).unwrap().unwrap();
            assert_eq!(serde_json::from_slice::<Value>(&back.payload).unwrap(), expected, "{name}");
        }
    }
}

#[test]
fn streams() {
    let v = vectors();
    for s in v["streams"].as_array().unwrap() {
        let name = s["name"].as_str().unwrap();
        let mut wire = unhex(&s["hex"]);
        if wire.starts_with(&PREFACE) {
            wire.drain(..PREFACE.len());
        }
        // Byte-by-byte feeding must give the same frames as one buffer.
        let mut buf = BytesMut::new();
        let mut types = vec![];
        for b in wire {
            buf.extend_from_slice(&[b]);
            while let Some(f) = FrameCodec.decode(&mut buf).unwrap() {
                types.push(Value::from(f.ty as u64));
            }
        }
        assert_eq!(&Value::from(types), &s["expect_types"], "{name}");
    }
}

#[test]
fn decode_errors() {
    for v in vectors()["decode_errors"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let input = if v["gen"].is_object() { gen_input(&v["gen"]) } else { unhex(&v["input"]) };
        let stage = v["stage"].as_str().unwrap();
        let got = match stage {
            "preface" => preface_result(&input),
            _ => frame_result(stage, &input),
        };
        assert_eq!(got, v["expect"].as_str().unwrap(), "{name}");
    }
}

#[test]
fn hmac() {
    for v in vectors()["hmac"].as_array().unwrap() {
        let k = |f: &str| -> [u8; 32] { unhex(&v[f]).try_into().unwrap() };
        let (sec, s, r) = (k("secret"), k("s_nonce"), k("r_nonce"));
        assert_eq!(auth::r_proof(&sec, &s, &r), k("r_proof"));
        assert_eq!(auth::s_proof(&sec, &s, &r), k("s_proof"));
    }
}

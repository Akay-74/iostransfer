//! Handshake control messages (PROTOCOL §4.3). Optional fields are omitted, never `null`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtoRange {
    pub min: u32,
    pub max: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum HelloAuth {
    Pair { token: String },
    Secret { s_nonce: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub proto: ProtoRange,
    pub device_id: String,
    pub device_name: String,
    pub app_version: String,
    pub os: String,
    pub auth: HelloAuth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    pub proto: u32,
    pub r_nonce: String,
    pub r_proof: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Auth {
    pub s_proof: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Welcome {
    pub proto: u32,
    pub pc_id: String,
    pub pc_name: String,
    pub session_id: String,
    pub store_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paired: Option<bool>,
    pub max_slots: u32,
    pub max_unacked_assets: u32,
    pub max_unacked_bytes: u64,
    pub free_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Paired {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bye {
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub msg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<u32>,
}

impl Bye {
    pub fn code(code: &str) -> Self {
        Bye { code: code.into(), msg: None, min: None, max: None }
    }
}

/// PROTOCOL §3: pick the highest common version, if any.
pub fn negotiate(ours: ProtoRange, theirs: ProtoRange) -> Option<u32> {
    let lo = ours.min.max(theirs.min);
    let hi = ours.max.min(theirs.max);
    (lo <= hi).then_some(hi)
}

// ---- Ready phase (PROTOCOL §5.2, §6) ----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub job_id: String,
    pub label: String,
    pub section: String,
    pub mode: String,
}

impl Job {
    pub fn is_move(&self) -> bool {
        self.mode == "move"
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Loc {
    pub lat: f64,
    pub lon: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alt: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResDesc {
    pub key: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub uti: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Asset {
    pub id: String,
    pub kind: String,
    pub created_ms: i64,
    pub tz_min: i32,
    pub modified_ms: i64,
    #[serde(default)]
    pub w: u32,
    #[serde(default)]
    pub h: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dur_ms: Option<i64>,
    #[serde(default)]
    pub fav: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loc: Option<Loc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst_id: Option<String>,
    #[serde(default)]
    pub subtypes: Vec<String>,
    pub res: Vec<ResDesc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub job: Job,
    pub page: u32,
    pub last: bool,
    pub assets: Vec<Asset>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResOffset {
    pub key: String,
    pub offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Want {
    pub id: String,
    pub res: Vec<ResOffset>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Need {
    pub job_id: String,
    pub page: u32,
    pub want: Vec<Want>,
    pub have: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeedMore {
    pub id: String,
    pub res: Vec<ResOffset>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResBegin {
    pub slot: u16,
    pub id: String,
    pub key: String,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResEnd {
    pub slot: u16,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResAbort {
    pub slot: u16,
    pub why: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetEnd {
    pub id: String,
    pub res_keys: Vec<String>,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailedKey {
    pub key: String,
    pub why: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ack {
    pub id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<Vec<FailedKey>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResNack {
    pub id: String,
    pub key: String,
    pub why: String,
    pub attempt: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pause {
    pub why: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resume {}

/// PROTOCOL §5.1: original-family bytes never change for an asset.
pub fn is_original_family(ty: &str) -> bool {
    matches!(ty, "photo" | "video" | "audio" | "alternate_photo" | "paired_video")
}

// ---- VERIFY (PROTOCOL §6.4) ----

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifyMeta {
    pub created_ms: i64,
    pub fav: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loc: Option<Loc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyRes {
    pub key: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifyAsset {
    pub id: String,
    pub meta: VerifyMeta,
    pub res: Vec<VerifyRes>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verify {
    pub seq: u64,
    pub assets: Vec<VerifyAsset>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BadAsset {
    pub id: String,
    pub why: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verified {
    pub seq: u64,
    pub ok: Vec<String>,
    pub bad: Vec<BadAsset>,
}

/// PROTOCOL §6.4: VERIFY frame limit.
pub const MAX_VERIFY_ASSETS: usize = 1000;

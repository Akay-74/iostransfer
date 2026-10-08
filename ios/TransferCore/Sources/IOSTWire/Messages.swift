// Control messages (PROTOCOL §4.3, §5.2, §6). Field names are exactly the wire names; optional
// fields are omitted when nil, never `null` (synthesized Codable uses encodeIfPresent).

public struct ProtoRange: Codable, Equatable, Sendable {
    public var min: UInt32
    public var max: UInt32
    public init(min: UInt32, max: UInt32) {
        self.min = min
        self.max = max
    }
}

public enum HelloAuth: Codable, Equatable, Sendable {
    case pair(token: String)
    case secret(sNonce: String)

    private enum K: String, CodingKey { case mode, token, s_nonce }

    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: K.self)
        switch try c.decode(String.self, forKey: .mode) {
        case "pair": self = .pair(token: try c.decode(String.self, forKey: .token))
        case "secret": self = .secret(sNonce: try c.decode(String.self, forKey: .s_nonce))
        case let m: throw DecodingError.dataCorruptedError(forKey: .mode, in: c, debugDescription: "mode \(m)")
        }
    }

    public func encode(to e: Encoder) throws {
        var c = e.container(keyedBy: K.self)
        switch self {
        case .pair(let token):
            try c.encode("pair", forKey: .mode)
            try c.encode(token, forKey: .token)
        case .secret(let n):
            try c.encode("secret", forKey: .mode)
            try c.encode(n, forKey: .s_nonce)
        }
    }
}

public struct Hello: Codable, Equatable, Sendable {
    public var proto: ProtoRange
    public var device_id: String
    public var device_name: String
    public var app_version: String
    public var os: String
    public var auth: HelloAuth
    public init(proto: ProtoRange, device_id: String, device_name: String, app_version: String, os: String, auth: HelloAuth) {
        self.proto = proto
        self.device_id = device_id
        self.device_name = device_name
        self.app_version = app_version
        self.os = os
        self.auth = auth
    }
}

public struct Challenge: Codable, Equatable, Sendable {
    public var proto: UInt32
    public var r_nonce: String
    public var r_proof: String
    public init(proto: UInt32, r_nonce: String, r_proof: String) {
        self.proto = proto
        self.r_nonce = r_nonce
        self.r_proof = r_proof
    }
}

public struct AuthMsg: Codable, Equatable, Sendable {
    public var s_proof: String
    public init(s_proof: String) { self.s_proof = s_proof }
}

public struct Welcome: Codable, Equatable, Sendable {
    public var proto: UInt32
    public var pc_id: String
    public var pc_name: String
    public var session_id: String
    public var store_id: String
    public var device_secret: String?
    public var paired: Bool?
    public var max_slots: UInt32
    public var max_unacked_assets: UInt32
    public var max_unacked_bytes: UInt64
    public var free_bytes: UInt64
    public init(proto: UInt32, pc_id: String, pc_name: String, session_id: String, store_id: String, device_secret: String? = nil, paired: Bool? = nil, max_slots: UInt32, max_unacked_assets: UInt32, max_unacked_bytes: UInt64, free_bytes: UInt64) {
        self.proto = proto
        self.pc_id = pc_id
        self.pc_name = pc_name
        self.session_id = session_id
        self.store_id = store_id
        self.device_secret = device_secret
        self.paired = paired
        self.max_slots = max_slots
        self.max_unacked_assets = max_unacked_assets
        self.max_unacked_bytes = max_unacked_bytes
        self.free_bytes = free_bytes
    }
}

public struct Empty: Codable, Equatable, Sendable {
    public init() {}
}

public struct Bye: Codable, Equatable, Sendable {
    public var code: String
    public var msg: String?
    public var min: UInt32?
    public var max: UInt32?
    public init(code: String, msg: String? = nil) {
        self.code = code
        self.msg = msg
    }
}

public struct Ping: Codable, Equatable, Sendable {
    public var n: UInt64
    public init(n: UInt64) { self.n = n }
}

public struct LogMsg: Codable, Equatable, Sendable {
    public var lvl: String
    public var ts_ms: Int64
    public var msg: String
    public init(lvl: String, ts_ms: Int64, msg: String) {
        self.lvl = lvl
        self.ts_ms = ts_ms
        self.msg = msg
    }
}

// MARK: Ready phase

public struct JobMsg: Codable, Equatable, Sendable {
    public var job_id: String
    public var label: String
    public var section: String
    public var mode: String
    public init(job_id: String, label: String, section: String, mode: String) {
        self.job_id = job_id
        self.label = label
        self.section = section
        self.mode = mode
    }
}

public struct LocMsg: Codable, Equatable, Sendable {
    public var lat: Double
    public var lon: Double
    public var alt: Double?
    public init(lat: Double, lon: Double, alt: Double?) {
        self.lat = lat
        self.lon = lon
        self.alt = alt
    }
}

public struct ResDescMsg: Codable, Equatable, Sendable {
    public var key: String
    public var type: String
    public var uti: String
    public var name: String
    public var size: UInt64?
    public init(key: String, type: String, uti: String, name: String, size: UInt64?) {
        self.key = key
        self.type = type
        self.uti = uti
        self.name = name
        self.size = size
    }
}

public struct AssetMsg: Codable, Equatable, Sendable {
    public var id: String
    public var kind: String
    public var created_ms: Int64
    public var tz_min: Int32
    public var modified_ms: Int64
    public var w: UInt32
    public var h: UInt32
    public var dur_ms: Int64?
    public var fav: Bool
    public var loc: LocMsg?
    public var burst_id: String?
    public var subtypes: [String]
    public var res: [ResDescMsg]
    public init(id: String, kind: String, created_ms: Int64, tz_min: Int32, modified_ms: Int64, w: UInt32, h: UInt32,
                dur_ms: Int64?, fav: Bool, loc: LocMsg?, burst_id: String?, subtypes: [String], res: [ResDescMsg]) {
        self.id = id
        self.kind = kind
        self.created_ms = created_ms
        self.tz_min = tz_min
        self.modified_ms = modified_ms
        self.w = w
        self.h = h
        self.dur_ms = dur_ms
        self.fav = fav
        self.loc = loc
        self.burst_id = burst_id
        self.subtypes = subtypes
        self.res = res
    }
}

public struct Manifest: Codable, Equatable, Sendable {
    public var job: JobMsg
    public var page: UInt32
    public var last: Bool
    public var assets: [AssetMsg]
    public init(job: JobMsg, page: UInt32, last: Bool, assets: [AssetMsg]) {
        self.job = job
        self.page = page
        self.last = last
        self.assets = assets
    }
}

public struct ResOffset: Codable, Equatable, Sendable {
    public var key: String
    public var offset: UInt64
    public init(key: String, offset: UInt64) {
        self.key = key
        self.offset = offset
    }
}

public struct Want: Codable, Equatable, Sendable {
    public var id: String
    public var res: [ResOffset]
    public init(id: String, res: [ResOffset]) {
        self.id = id
        self.res = res
    }
}

public struct Need: Codable, Equatable, Sendable {
    public var job_id: String
    public var page: UInt32
    public var want: [Want]
    public var have: [String]
    public init(job_id: String, page: UInt32, want: [Want], have: [String]) {
        self.job_id = job_id
        self.page = page
        self.want = want
        self.have = have
    }
}

public struct NeedMore: Codable, Equatable, Sendable {
    public var id: String
    public var res: [ResOffset]
    public init(id: String, res: [ResOffset]) {
        self.id = id
        self.res = res
    }
}

public struct ResBegin: Codable, Equatable, Sendable {
    public var slot: UInt16
    public var id: String
    public var key: String
    public var offset: UInt64
    public var size: UInt64
    public init(slot: UInt16, id: String, key: String, offset: UInt64, size: UInt64) {
        self.slot = slot
        self.id = id
        self.key = key
        self.offset = offset
        self.size = size
    }
}

public struct ResEnd: Codable, Equatable, Sendable {
    public var slot: UInt16
    public var size: UInt64
    public var sha256: String
    public init(slot: UInt16, size: UInt64, sha256: String) {
        self.slot = slot
        self.size = size
        self.sha256 = sha256
    }
}

public struct ResAbort: Codable, Equatable, Sendable {
    public var slot: UInt16
    public var why: String
    public init(slot: UInt16, why: String) {
        self.slot = slot
        self.why = why
    }
}

public struct AssetEnd: Codable, Equatable, Sendable {
    public var id: String
    public var res_keys: [String]
    public var complete: Bool
    public var why: String?
    public init(id: String, res_keys: [String], complete: Bool, why: String? = nil) {
        self.id = id
        self.res_keys = res_keys
        self.complete = complete
        self.why = why
    }
}

public struct FailedKey: Codable, Equatable, Sendable {
    public var key: String
    public var why: String
    public init(key: String, why: String) {
        self.key = key
        self.why = why
    }
}

public struct Ack: Codable, Equatable, Sendable {
    public var id: String
    public var status: String
    public var failed: [FailedKey]?
    public init(id: String, status: String, failed: [FailedKey]? = nil) {
        self.id = id
        self.status = status
        self.failed = failed
    }
}

public struct ResNack: Codable, Equatable, Sendable {
    public var id: String
    public var key: String
    public var why: String
    public var attempt: UInt32
    public init(id: String, key: String, why: String, attempt: UInt32) {
        self.id = id
        self.key = key
        self.why = why
        self.attempt = attempt
    }
}

public struct Pause: Codable, Equatable, Sendable {
    public var why: String
    public init(why: String) {
        self.why = why
    }
}

public struct VerifyMeta: Codable, Equatable, Sendable {
    public var created_ms: Int64
    public var fav: Bool
    public var loc: LocMsg?
    public init(created_ms: Int64, fav: Bool, loc: LocMsg?) {
        self.created_ms = created_ms
        self.fav = fav
        self.loc = loc
    }
}

public struct VerifyRes: Codable, Equatable, Sendable {
    public var key: String
    public var size: UInt64
    public var sha256: String?
    public init(key: String, size: UInt64, sha256: String?) {
        self.key = key
        self.size = size
        self.sha256 = sha256
    }
}

public struct VerifyAsset: Codable, Equatable, Sendable {
    public var id: String
    public var meta: VerifyMeta
    public var res: [VerifyRes]
    public init(id: String, meta: VerifyMeta, res: [VerifyRes]) {
        self.id = id
        self.meta = meta
        self.res = res
    }
}

public struct Verify: Codable, Equatable, Sendable {
    public var seq: UInt64
    public var assets: [VerifyAsset]
    public init(seq: UInt64, assets: [VerifyAsset]) {
        self.seq = seq
        self.assets = assets
    }
}

public struct BadAsset: Codable, Equatable, Sendable {
    public var id: String
    public var why: String
    public var key: String?
    public init(id: String, why: String, key: String? = nil) {
        self.id = id
        self.why = why
        self.key = key
    }
}

public struct Verified: Codable, Equatable, Sendable {
    public var seq: UInt64
    public var ok: [String]
    public var bad: [BadAsset]
    public init(seq: UInt64, ok: [String], bad: [BadAsset]) {
        self.seq = seq
        self.ok = ok
        self.bad = bad
    }
}

public enum Limits {
    /// PROTOCOL §6.1.
    public static let maxPageAssets = 500
    /// PROTOCOL §6.4.
    public static let maxVerifyAssets = 1000
}

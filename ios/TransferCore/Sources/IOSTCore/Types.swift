// Domain types, events and actions of the sans-I/O sender core (TRANSFERCORE §3–§5).
import Foundation
@_exported import IOSTCrypto
@_exported import IOSTJournal
import IOSTWire

public typealias ResKey = String

/// Every event carries both clocks: `mono` drives timers only (resets at boot, never persisted);
/// `wallMs` is the only clock written to the journal.
public struct Now: Sendable, Equatable {
    public var mono: UInt64
    public var wallMs: Int64
    public init(mono: UInt64, wallMs: Int64) {
        self.mono = mono
        self.wallMs = wallMs
    }
}

public enum Lane: Hashable, Sendable { case photo, video }

public struct AssetMeta: Codable, Equatable, Sendable {
    public var createdMs: Int64
    public var tzMin: Int32
    public var fav: Bool
    public var loc: FingerprintLocationCodable?
    public init(createdMs: Int64, tzMin: Int32, fav: Bool, loc: FingerprintLocationCodable?) {
        self.createdMs = createdMs
        self.tzMin = tzMin
        self.fav = fav
        self.loc = loc
    }
}

public struct FingerprintLocationCodable: Codable, Equatable, Sendable {
    public var lat: Double
    public var lon: Double
    public var alt: Double?
    public init(lat: Double, lon: Double, alt: Double?) {
        self.lat = lat
        self.lon = lon
        self.alt = alt
    }
    var plain: FingerprintLocation { FingerprintLocation(lat: lat, lon: lon, alt: alt) }
}

public struct ResourceDescriptor: Codable, Equatable, Sendable {
    public var key: ResKey
    public var type: String
    public var uti: String
    public var name: String
    /// KVC fileSize, best effort.
    public var sizeHint: UInt64?
    public init(key: ResKey, type: String, uti: String, name: String, sizeHint: UInt64?) {
        self.key = key
        self.type = type
        self.uti = uti
        self.name = name
        self.sizeHint = sizeHint
    }
}

public struct AssetDescriptor: Codable, Equatable, Sendable {
    public var id: AssetID
    public var kind: Section
    public var meta: AssetMeta
    public var modifiedMs: Int64
    public var w: Int
    public var h: Int
    public var durMs: Int64?
    public var burstID: String?
    public var subtypes: [String]
    /// Already without `photo_proxy`.
    public var resources: [ResourceDescriptor]
    public init(id: AssetID, kind: Section, meta: AssetMeta, modifiedMs: Int64, w: Int, h: Int, durMs: Int64?,
                burstID: String?, subtypes: [String], resources: [ResourceDescriptor]) {
        self.id = id
        self.kind = kind
        self.meta = meta
        self.modifiedMs = modifiedMs
        self.w = w
        self.h = h
        self.durMs = durMs
        self.burstID = burstID
        self.subtypes = subtypes
        self.resources = resources
    }
}

/// Core-chosen spool location; the driver owns the storage.
public struct SpoolRef: Hashable, Sendable {
    public var jobID: UUID
    /// Lowercase hex sha256(AssetID): identifiers contain "/".
    public var assetDir: String
    public var key: ResKey
    public init(jobID: UUID, assetDir: String, key: ResKey) {
        self.jobID = jobID
        self.assetDir = assetDir
        self.key = key
    }
    public static func dir(for id: AssetID) -> String {
        IOSTCrypto.sha256(Array(id.utf8)).hexString
    }
}

public struct Credentials: Sendable {
    public enum Auth: Sendable {
        case pair(token: String)
        case secret([UInt8])
    }
    public var deviceID: UUID
    public var deviceName: String
    public var appVersion: String
    public var os: String
    public var auth: Auth
    /// The paired PC; nil only while pairing.
    public var expectedPCID: String?
    public var pcName: String
    /// The first move to this PC needs an extra confirmation (THREAT_MODEL N13).
    public var firstMoveToPC: Bool

    public init(deviceID: UUID, deviceName: String, appVersion: String, os: String, auth: Auth, expectedPCID: String?,
                pcName: String, firstMoveToPC: Bool) {
        self.deviceID = deviceID
        self.deviceName = deviceName
        self.appVersion = appVersion
        self.os = os
        self.auth = auth
        self.expectedPCID = expectedPCID
        self.pcName = pcName
        self.firstMoveToPC = firstMoveToPC
    }
}

public enum TransportDownReason: Sendable, Equatable {
    case closed
    case error(String)
}

public enum ExportFailure: String, Sendable {
    case notLocal = "not_local"
    case readError = "read_error"
    case noSpace = "spool_space"
    case assetGone = "asset_gone"
}

public enum DeleteOutcome: Sendable, Equatable {
    case success
    case userCancelled
    case error(String)
}

public enum ThermalLevel: Sendable { case nominal, fair, serious, critical }

public enum LogLevel: String, Sendable { case d, i, w, e }

public enum UserAction: Sendable, Equatable {
    case pairAgain(reason: String)
    case updateApp(olderSide: String)
    case freeSpace(bytes: UInt64)
    case pcDiskFull
    case wrongPC
    case journalError(String)
    /// Gate before the first delete batch to a newly paired PC (N13).
    case confirmFirstMove(pcName: String)
    /// The system delete prompt was cancelled.
    case confirmDeleteAgain(count: Int)
}

public enum UserReply: Sendable, Equatable {
    case confirmFirstMove(Bool)
    case deleteAgain(Bool)
}

public struct AssetCurrentState: Sendable {
    public var id: AssetID
    public var exists: Bool
    /// canPerform(.delete) && sourceType == .typeUserLibrary
    public var canDelete: Bool
    public var isLocal: Bool
    public var modifiedMs: Int64
    /// Present iff the core asked for it.
    public var fingerprint: FingerprintInput?
    public init(id: AssetID, exists: Bool, canDelete: Bool, isLocal: Bool, modifiedMs: Int64, fingerprint: FingerprintInput?) {
        self.id = id
        self.exists = exists
        self.canDelete = canDelete
        self.isLocal = isLocal
        self.modifiedMs = modifiedMs
        self.fingerprint = fingerprint
    }
}

public enum Phase: String, Sendable {
    case connecting, transferring, verifying, deleting, done, blocked
}

public struct JobProgress: Sendable, Equatable {
    public var phase: Phase = .connecting
    public var assetsDone = 0
    public var assetsFailed = 0
    public var assetsSkipped = 0
    public var assetsKnown = 0
    public var bytesSent: UInt64 = 0
    public var paused: String?
    public init() {}
}

public struct JobSummary: Sendable, Equatable {
    public var copied = 0
    public var alreadyOnPC = 0
    public var failed: [String: Int] = [:]
    public var deleted = 0
    public var declined = 0
    public var dropped: [String: Int] = [:]
    public var bytes: UInt64 = 0
    public init() {}
}

public enum Event: Sendable {
    case startJob(JobSpec, now: Now)
    case cancelJob(now: Now)
    case tick(now: Now)

    case transportUp(isTLS: Bool, now: Now)
    case received([UInt8], now: Now)
    case sendCompleted(token: UInt64, now: Now)
    case transportDown(TransportDownReason, now: Now)
    case secretStored(now: Now)

    case assetsLoaded([AssetDescriptor], exhausted: Bool, now: Now)
    /// Answer to `.describeAssets` (re-manifest after a fingerprint change).
    case assetsDescribed([AssetDescriptor], now: Now)

    case exported(SpoolRef, size: UInt64, now: Now)
    case exportFailed(SpoolRef, ExportFailure, now: Now)

    case readDone(token: UInt64, [UInt8], now: Now)
    case readFailed(token: UInt64, now: Now)

    case currentState([AssetCurrentState], now: Now)
    case deleteFinished(batchID: UUID, DeleteOutcome, now: Now)
    case userReply(UserReply, now: Now)

    case freeSpaceChanged(bytes: UInt64, now: Now)
    case thermal(ThermalLevel, now: Now)
}

public enum Action: Sendable, Equatable {
    case connect(attempt: Int)
    case send([UInt8], token: UInt64)
    case closeTransport(after: [UInt8]?)
    case storeSecret([UInt8], pcID: String, pcName: String)

    case beginAssetSource(skip: Set<AssetID>)
    case loadAssets(max: Int)
    case describeAssets([AssetID])

    case export(AssetID, ResourceDescriptor, to: SpoolRef)
    case read(SpoolRef, offset: UInt64, length: Int, token: UInt64)
    case deleteSpool(jobID: UUID, assetDir: String?)
    case sweepSpool(keepJob: UUID, dropAssetDirs: Set<String>)

    case inspectAssets([AssetID], wantFingerprint: Set<AssetID>)
    case performDelete(batchID: UUID, [AssetID])

    case progress(JobProgress)
    case log(LogLevel, String)
    case needsUser(UserAction)
    case jobFinished(JobSummary)
}

public protocol RandomSource {
    mutating func bytes(_ n: Int) -> [UInt8]
}

public struct SystemRandom: RandomSource {
    public init() {}
    public mutating func bytes(_ n: Int) -> [UInt8] {
        var g = SystemRandomNumberGenerator()
        return (0..<n).map { _ in UInt8.random(in: 0...255, using: &g) }
    }
}

public struct CoreConfig: Sendable {
    public var photoSlots = 3
    public var videoSlots = 1
    public var chunk = 256 * 1024
    public var sendWatermark = 4 * 1024 * 1024
    public var pageSize = Limits.maxPageAssets
    public var verifyBatch = Limits.maxVerifyAssets
    public var deleteBatch = 2000
    public var maxAttempts = 3
    public var peerSilenceMs: UInt64 = 30_000
    public var pingAfterMs: UInt64 = 10_000
    public var handshakeMs: UInt64 = 15_000
    public var pairingMs: UInt64 = 60_000
    public var verifyFreshMs: Int64 = 10 * 60_000
    public var backoffMs: [UInt64] = [1000, 2000, 4000, 8000, 16_000, 30_000]
    public init() {}
}

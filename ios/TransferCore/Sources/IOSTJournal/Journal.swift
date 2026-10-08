// The phone's persisted journal (PROTOCOL §8.3). Only terminal-ish states are stored; everything
// else is recomputed after a crash. Every timestamp here is WALL clock (never the monotonic one).
import Foundation

public typealias AssetID = String

public enum Section: String, Codable, Sendable { case photos, videos }
public enum JobMode: String, Codable, Sendable { case copy, move }

public struct JobSpec: Codable, Equatable, Sendable {
    public var jobID: UUID
    public var mode: JobMode
    public var section: Section
    public var label: String
    /// Selection rules, opaque to the core.
    public var rulesJSON: Data
    public init(jobID: UUID, mode: JobMode, section: Section, label: String, rulesJSON: Data) {
        self.jobID = jobID
        self.mode = mode
        self.section = section
        self.label = label
        self.rulesJSON = rulesJSON
    }
}

public enum PersistedState: String, Codable, Sendable {
    case acked, failed, verified, deleted, declined, dropped
}

public struct AssetRecord: Equatable, Sendable {
    public var state: PersistedState
    public var lastError: String?
    public var verifiedFP: [UInt8]?
    public var verifiedModifiedMs: Int64?
    public var verifiedAtMs: Int64?
    public var reverifyCount: Int
    public var droppedReason: String?

    public init(state: PersistedState) {
        self.state = state
        reverifyCount = 0
    }
}

public struct JobRecord: Equatable, Sendable {
    public var spec: JobSpec
    public var createdMs: Int64
    public var pcID: String?
    public var storeID: String?
    public var state: String
}

public enum JournalUpdate: Equatable, Sendable {
    case state(job: UUID, asset: AssetID, PersistedState, reason: String?)
    case verified(job: UUID, asset: AssetID, fp: [UInt8], modifiedMs: Int64, atMs: Int64)
    /// Fingerprint changed after VERIFY: back to `acked`, reverify_count + 1 (PROTOCOL §8.4).
    case reverify(job: UUID, asset: AssetID)
    /// The PC (pc_id, store_id) this job's `acked` marks are valid for (Δ16).
    case binding(job: UUID, pcID: String, storeID: String)
    /// Forget `acked` marks: the PC index they referred to is gone.
    case clearAcked(job: UUID)
    case jobState(job: UUID, String)
    case deleteBatch(job: UUID, batch: UUID, assets: [AssetID], atMs: Int64)
    case batchState(batch: UUID, String)
}

public enum JournalError: Error, Equatable {
    case sqlite(String)
}

public protocol JournalStore: AnyObject {
    /// Create the job, or resume it. Every `verified` row is demoted to `acked`: a VERIFY never
    /// survives a restart (TRANSFERCORE §7).
    func createOrResume(_ job: JobSpec, wallMs: Int64) throws -> JobRecord
    func assets(job: UUID) throws -> [AssetID: AssetRecord]
    /// All updates in one transaction.
    func record(_ updates: [JournalUpdate]) throws
    /// Delete batches in a given state, with their items.
    func deleteBatches(job: UUID, state: String) throws -> [(batch: UUID, assets: [AssetID])]
}

/// Reference implementation; also the oracle for SQLiteJournal and the crash simulation (a copy
/// is the journal "as of its last commit").
public final class InMemoryJournal: JournalStore, @unchecked Sendable {
    public private(set) var jobs: [UUID: JobRecord] = [:]
    public private(set) var rows: [UUID: [AssetID: AssetRecord]] = [:]
    public private(set) var batches: [UUID: (job: UUID, state: String, assets: [AssetID])] = [:]

    public init() {}

    public func copy() -> InMemoryJournal {
        let j = InMemoryJournal()
        j.jobs = jobs
        j.rows = rows
        j.batches = batches
        return j
    }

    public func createOrResume(_ job: JobSpec, wallMs: Int64) throws -> JobRecord {
        if jobs[job.jobID] == nil {
            jobs[job.jobID] = JobRecord(spec: job, createdMs: wallMs, pcID: nil, storeID: nil, state: "active")
        }
        for (id, var r) in rows[job.jobID] ?? [:] where r.state == .verified {
            r.state = .acked
            rows[job.jobID]![id] = r
        }
        return jobs[job.jobID]!
    }

    public func assets(job: UUID) throws -> [AssetID: AssetRecord] {
        rows[job] ?? [:]
    }

    public func record(_ updates: [JournalUpdate]) throws {
        for u in updates { apply(u) }
    }

    private func apply(_ u: JournalUpdate) {
        switch u {
        case let .state(job, asset, st, reason):
            var r = rows[job]?[asset] ?? AssetRecord(state: st)
            r.state = st
            if st == .dropped { r.droppedReason = reason } else if reason != nil { r.lastError = reason }
            rows[job, default: [:]][asset] = r
        case let .verified(job, asset, fp, mod, at):
            var r = rows[job]?[asset] ?? AssetRecord(state: .verified)
            r.state = .verified
            r.verifiedFP = fp
            r.verifiedModifiedMs = mod
            r.verifiedAtMs = at
            rows[job, default: [:]][asset] = r
        case let .reverify(job, asset):
            guard var r = rows[job]?[asset] else { return }
            r.state = .acked
            r.reverifyCount += 1
            rows[job]![asset] = r
        case let .binding(job, pc, store):
            jobs[job]?.pcID = pc
            jobs[job]?.storeID = store
        case let .clearAcked(job):
            rows[job] = rows[job]?.filter { $0.value.state != .acked && $0.value.state != .verified }
        case let .jobState(job, st):
            jobs[job]?.state = st
        case let .deleteBatch(job, batch, assets, _):
            batches[batch] = (job, "requested", assets)
        case let .batchState(batch, st):
            batches[batch]?.state = st
        }
    }

    public func deleteBatches(job: UUID, state: String) throws -> [(batch: UUID, assets: [AssetID])] {
        batches.filter { $0.value.job == job && $0.value.state == state }.map { ($0.key, $0.value.assets) }
    }
}

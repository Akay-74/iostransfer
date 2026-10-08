// SQLite journal in Application Support (system libsqlite3 on iOS and Linux).
import CSQLite
import Foundation

private let TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

public final class SQLiteJournal: JournalStore, @unchecked Sendable {
    private var db: OpaquePointer?

    public init(path: String) throws {
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK
        else { throw JournalError.sqlite("open \(path)") }
        try exec("PRAGMA journal_mode=WAL")
        try exec("PRAGMA synchronous=FULL")
        try exec("""
            CREATE TABLE IF NOT EXISTS job (job_id TEXT PRIMARY KEY, spec BLOB NOT NULL, state TEXT NOT NULL,
                created_ms INTEGER NOT NULL, pc_id TEXT, store_id TEXT);
            CREATE TABLE IF NOT EXISTS job_asset (job_id TEXT NOT NULL, asset_id TEXT NOT NULL, state TEXT NOT NULL,
                last_error TEXT, verified_fp BLOB, verified_modified_ms INTEGER, verified_at_ms INTEGER,
                reverify_count INTEGER NOT NULL DEFAULT 0, dropped_reason TEXT, PRIMARY KEY (job_id, asset_id));
            CREATE TABLE IF NOT EXISTS delete_batch (batch_id TEXT PRIMARY KEY, job_id TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('requested','done','declined')), created_ms INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS delete_item (batch_id TEXT NOT NULL, asset_id TEXT NOT NULL);
            """)
    }

    deinit { sqlite3_close(db) }

    // MARK: Low-level helpers

    private var lastError: String { String(cString: sqlite3_errmsg(db)) }

    private func exec(_ sql: String) throws {
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw JournalError.sqlite(lastError) }
    }

    private enum V {
        case text(String?), int(Int64?), blob([UInt8]?)
    }

    private func bind(_ st: OpaquePointer?, _ values: [V]) {
        for (i, v) in values.enumerated() {
            let idx = Int32(i + 1)
            switch v {
            case .text(let s?): sqlite3_bind_text(st, idx, s, -1, TRANSIENT)
            case .int(let n?): sqlite3_bind_int64(st, idx, n)
            case .blob(let b?): sqlite3_bind_blob(st, idx, b, Int32(b.count), TRANSIENT)
            default: sqlite3_bind_null(st, idx)
            }
        }
    }

    private func run(_ sql: String, _ values: [V] = []) throws {
        var st: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &st, nil) == SQLITE_OK else { throw JournalError.sqlite(lastError) }
        defer { sqlite3_finalize(st) }
        bind(st, values)
        guard sqlite3_step(st) == SQLITE_DONE else { throw JournalError.sqlite(lastError) }
    }

    private func query(_ sql: String, _ values: [V], _ row: (OpaquePointer?) -> Void) throws {
        var st: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &st, nil) == SQLITE_OK else { throw JournalError.sqlite(lastError) }
        defer { sqlite3_finalize(st) }
        bind(st, values)
        while true {
            let rc = sqlite3_step(st)
            if rc == SQLITE_DONE { return }
            guard rc == SQLITE_ROW else { throw JournalError.sqlite(lastError) }
            row(st)
        }
    }

    private func text(_ st: OpaquePointer?, _ i: Int32) -> String? {
        sqlite3_column_type(st, i) == SQLITE_NULL ? nil : String(cString: sqlite3_column_text(st, i))
    }

    private func int(_ st: OpaquePointer?, _ i: Int32) -> Int64? {
        sqlite3_column_type(st, i) == SQLITE_NULL ? nil : sqlite3_column_int64(st, i)
    }

    private func blob(_ st: OpaquePointer?, _ i: Int32) -> [UInt8]? {
        guard sqlite3_column_type(st, i) != SQLITE_NULL, let p = sqlite3_column_blob(st, i) else { return nil }
        return Array(UnsafeRawBufferPointer(start: p, count: Int(sqlite3_column_bytes(st, i))))
    }

    private func transaction(_ body: () throws -> Void) throws {
        try exec("BEGIN IMMEDIATE")
        do {
            try body()
            try exec("COMMIT")
        } catch {
            try? exec("ROLLBACK")
            throw error
        }
    }

    // MARK: JournalStore

    public func createOrResume(_ job: JobSpec, wallMs: Int64) throws -> JobRecord {
        let spec = Array(try JSONEncoder().encode(job))
        try transaction {
            try run("INSERT OR IGNORE INTO job(job_id, spec, state, created_ms) VALUES (?,?,'active',?)",
                    [.text(job.jobID.uuidString), .blob(spec), .int(wallMs)])
            try run("UPDATE job_asset SET state='acked' WHERE job_id=? AND state='verified'", [.text(job.jobID.uuidString)])
        }
        var rec: JobRecord?
        try query("SELECT created_ms, pc_id, store_id, state FROM job WHERE job_id=?", [.text(job.jobID.uuidString)]) { st in
            rec = JobRecord(spec: job, createdMs: self.int(st, 0) ?? wallMs, pcID: self.text(st, 1),
                            storeID: self.text(st, 2), state: self.text(st, 3) ?? "active")
        }
        guard let rec else { throw JournalError.sqlite("job row missing") }
        return rec
    }

    public func assets(job: UUID) throws -> [AssetID: AssetRecord] {
        var out = [AssetID: AssetRecord]()
        try query("""
            SELECT asset_id, state, last_error, verified_fp, verified_modified_ms, verified_at_ms, reverify_count,
                   dropped_reason FROM job_asset WHERE job_id=?
            """, [.text(job.uuidString)]) { st in
            guard let id = self.text(st, 0), let state = self.text(st, 1).flatMap(PersistedState.init) else { return }
            var r = AssetRecord(state: state)
            r.lastError = self.text(st, 2)
            r.verifiedFP = self.blob(st, 3)
            r.verifiedModifiedMs = self.int(st, 4)
            r.verifiedAtMs = self.int(st, 5)
            r.reverifyCount = Int(self.int(st, 6) ?? 0)
            r.droppedReason = self.text(st, 7)
            out[id] = r
        }
        return out
    }

    public func record(_ updates: [JournalUpdate]) throws {
        guard !updates.isEmpty else { return }
        try transaction {
            for u in updates { try apply(u) }
        }
    }

    private func apply(_ u: JournalUpdate) throws {
        switch u {
        case let .state(job, asset, st, reason):
            let dropped = st == .dropped ? reason : nil
            let err = st == .dropped ? nil : reason
            try run("""
                INSERT INTO job_asset(job_id, asset_id, state, last_error, dropped_reason) VALUES (?,?,?,?,?)
                ON CONFLICT(job_id, asset_id) DO UPDATE SET state=excluded.state,
                    last_error=COALESCE(excluded.last_error, last_error),
                    dropped_reason=COALESCE(excluded.dropped_reason, dropped_reason)
                """, [.text(job.uuidString), .text(asset), .text(st.rawValue), .text(err), .text(dropped)])
        case let .verified(job, asset, fp, mod, at):
            try run("""
                INSERT INTO job_asset(job_id, asset_id, state, verified_fp, verified_modified_ms, verified_at_ms)
                VALUES (?,?,'verified',?,?,?)
                ON CONFLICT(job_id, asset_id) DO UPDATE SET state='verified', verified_fp=excluded.verified_fp,
                    verified_modified_ms=excluded.verified_modified_ms, verified_at_ms=excluded.verified_at_ms
                """, [.text(job.uuidString), .text(asset), .blob(fp), .int(mod), .int(at)])
        case let .reverify(job, asset):
            try run("UPDATE job_asset SET state='acked', reverify_count=reverify_count+1 WHERE job_id=? AND asset_id=?",
                    [.text(job.uuidString), .text(asset)])
        case let .binding(job, pc, store):
            try run("UPDATE job SET pc_id=?, store_id=? WHERE job_id=?", [.text(pc), .text(store), .text(job.uuidString)])
        case let .clearAcked(job):
            try run("DELETE FROM job_asset WHERE job_id=? AND state IN ('acked','verified')", [.text(job.uuidString)])
        case let .jobState(job, st):
            try run("UPDATE job SET state=? WHERE job_id=?", [.text(st), .text(job.uuidString)])
        case let .deleteBatch(job, batch, assets, at):
            try run("INSERT INTO delete_batch(batch_id, job_id, state, created_ms) VALUES (?,?,'requested',?)",
                    [.text(batch.uuidString), .text(job.uuidString), .int(at)])
            for a in assets {
                try run("INSERT INTO delete_item(batch_id, asset_id) VALUES (?,?)", [.text(batch.uuidString), .text(a)])
            }
        case let .batchState(batch, st):
            try run("UPDATE delete_batch SET state=? WHERE batch_id=?", [.text(st), .text(batch.uuidString)])
        }
    }

    public func deleteBatches(job: UUID, state: String) throws -> [(batch: UUID, assets: [AssetID])] {
        var byBatch = [UUID: [AssetID]]()
        var order = [UUID]()
        try query("""
            SELECT b.batch_id, i.asset_id FROM delete_batch b JOIN delete_item i ON i.batch_id = b.batch_id
            WHERE b.job_id=? AND b.state=? ORDER BY b.created_ms
            """, [.text(job.uuidString), .text(state)]) { st in
            guard let b = self.text(st, 0).flatMap(UUID.init(uuidString:)), let a = self.text(st, 1) else { return }
            if byBatch[b] == nil { order.append(b) }
            byBatch[b, default: []].append(a)
        }
        return order.map { ($0, byBatch[$0]!) }
    }
}

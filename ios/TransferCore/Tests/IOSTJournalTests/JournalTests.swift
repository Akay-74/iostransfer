// SQLiteJournal must behave exactly like InMemoryJournal (the reference).
import Foundation
import Testing
@testable import IOSTJournal

private func spec(_ id: UUID = UUID()) -> JobSpec {
    JobSpec(jobID: id, mode: .move, section: .photos, label: "Screenshots", rulesJSON: Data("[]".utf8))
}

private func sqlite() throws -> SQLiteJournal {
    let path = FileManager.default.temporaryDirectory.appendingPathComponent("journal-\(UUID()).db").path
    return try SQLiteJournal(path: path)
}

private func exercise(_ j: JournalStore) throws -> ([AssetID: AssetRecord], [(batch: UUID, assets: [AssetID])], JobRecord) {
    let s = spec()
    _ = try j.createOrResume(s, wallMs: 1000)
    let batch = UUID()
    try j.record([
        .binding(job: s.jobID, pcID: "pc", storeID: "store"),
        .state(job: s.jobID, asset: "a", .acked, reason: nil),
        .state(job: s.jobID, asset: "b", .failed, reason: "not_local"),
        .verified(job: s.jobID, asset: "c", fp: [1, 2, 3], modifiedMs: 77, atMs: 2000),
        .state(job: s.jobID, asset: "d", .acked, reason: nil),
        .reverify(job: s.jobID, asset: "d"),
        .state(job: s.jobID, asset: "e", .dropped, reason: "changed_during_move"),
        .deleteBatch(job: s.jobID, batch: batch, assets: ["c", "a"], atMs: 3000),
    ])
    // Resume: verified is demoted to acked, its fingerprint kept.
    let rec = try j.createOrResume(s, wallMs: 9999)
    return (try j.assets(job: s.jobID), try j.deleteBatches(job: s.jobID, state: "requested"), rec)
}

@Test func sqliteMatchesReference() throws {
    let (memRows, memBatches, memJob) = try exercise(InMemoryJournal())
    let (sqlRows, sqlBatches, sqlJob) = try exercise(try sqlite())
    #expect(sqlRows == memRows)
    #expect(sqlRows["c"]?.state == .acked && sqlRows["c"]?.verifiedFP == [1, 2, 3])
    #expect(sqlRows["d"]?.reverifyCount == 1)
    #expect(sqlRows["e"]?.droppedReason == "changed_during_move")
    #expect(sqlRows["b"]?.lastError == "not_local")
    #expect(sqlBatches.map(\.assets) == memBatches.map(\.assets))
    #expect(Set(sqlBatches[0].assets) == ["c", "a"])
    #expect(sqlJob.createdMs == 1000 && memJob.createdMs == 1000, "created_ms is set once")
    #expect(sqlJob.pcID == "pc" && sqlJob.storeID == "store")
}

@Test func clearAckedForgetsBindingMarks() throws {
    for j in [InMemoryJournal() as JournalStore, try sqlite()] {
        let s = spec()
        _ = try j.createOrResume(s, wallMs: 1)
        try j.record([.state(job: s.jobID, asset: "a", .acked, reason: nil),
                      .state(job: s.jobID, asset: "b", .failed, reason: "x"),
                      .clearAcked(job: s.jobID)])
        #expect(Set(try j.assets(job: s.jobID).keys) == ["b"])
    }
}

@Test func survivesReopen() throws {
    let path = FileManager.default.temporaryDirectory.appendingPathComponent("journal-\(UUID()).db").path
    let s = spec()
    do {
        let j = try SQLiteJournal(path: path)
        _ = try j.createOrResume(s, wallMs: 5)
        try j.record([.state(job: s.jobID, asset: "x/y/z", .acked, reason: nil)])
    }
    let j = try SQLiteJournal(path: path)
    #expect(try j.assets(job: s.jobID)["x/y/z"]?.state == .acked)
}

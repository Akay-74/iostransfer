// The export spool (ARCHITECTURE §2.6): Application Support, readable after the first unlock,
// excluded from backups. Bounded by the core's unacked window, freed on ACK.
import Foundation
import IOSTCore

final class Spool {
    let root: URL

    init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        root = base.appendingPathComponent("spool", isDirectory: true)
        ensure(root)
    }

    private func ensure(_ dir: URL) {
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                 attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication])
        var u = dir
        var v = URLResourceValues()
        v.isExcludedFromBackup = true
        try? u.setResourceValues(v)
    }

    func url(_ ref: SpoolRef) -> URL {
        let dir = root.appendingPathComponent(ref.jobID.uuidString).appendingPathComponent(ref.assetDir)
        ensure(dir)
        return dir.appendingPathComponent(ref.key.replacingOccurrences(of: "#", with: "_"))
    }

    func read(_ ref: SpoolRef, offset: UInt64, length: Int) -> [UInt8]? {
        guard let h = try? FileHandle(forReadingFrom: url(ref)) else { return nil }
        defer { try? h.close() }
        do {
            try h.seek(toOffset: offset)
            return [UInt8](try h.read(upToCount: length) ?? Data())
        } catch {
            return nil
        }
    }

    func delete(jobID: UUID, assetDir: String?) {
        var u = root.appendingPathComponent(jobID.uuidString)
        if let d = assetDir { u.appendPathComponent(d) }
        try? FileManager.default.removeItem(at: u)
    }

    /// Startup sweep: other jobs' spools, terminal assets of this job, and every `.tmp`.
    func sweep(keepJob: UUID, drop: Set<String>) {
        let fm = FileManager.default
        for job in (try? fm.contentsOfDirectory(atPath: root.path)) ?? [] where job != keepJob.uuidString {
            try? fm.removeItem(at: root.appendingPathComponent(job))
        }
        let jobDir = root.appendingPathComponent(keepJob.uuidString)
        for d in drop { try? fm.removeItem(at: jobDir.appendingPathComponent(d)) }
        if let e = fm.enumerator(at: jobDir, includingPropertiesForKeys: nil) {
            for case let f as URL in e where f.pathExtension == "tmp" { try? fm.removeItem(at: f) }
        }
    }

    var freeBytes: UInt64 {
        let v = try? root.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        return UInt64(max(v?.volumeAvailableCapacityForImportantUsage ?? 0, 0))
    }
}

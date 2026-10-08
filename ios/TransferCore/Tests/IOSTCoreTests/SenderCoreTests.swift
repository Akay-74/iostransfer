// SenderCore against a scripted receiver. A small rig services the driver side automatically
// (exports, spool reads, send completions, asset pages) and records every frame the core sends.
import Foundation
import Testing
@testable import IOSTCore
import IOSTWire

let secret = [UInt8](repeating: 0x42, count: 32)
let pcID = "pc-1"

struct FixedRandom: RandomSource {
    var n: UInt8 = 0
    mutating func bytes(_ count: Int) -> [UInt8] {
        n &+= 1
        return [UInt8](repeating: n, count: count)
    }
}

func asset(_ id: String, _ resources: [(String, String, Int)], video: Bool = false, fav: Bool = false) -> AssetDescriptor {
    AssetDescriptor(
        id: id, kind: video ? .videos : .photos, meta: AssetMeta(createdMs: 1000, tzMin: 0, fav: fav, loc: nil), modifiedMs: 5,
        w: 1, h: 1, durMs: nil, burstID: nil, subtypes: [],
        resources: resources.map { ResourceDescriptor(key: $0.0, type: $0.1, uti: "public.heic", name: "\(id).HEIC", sizeHint: UInt64($0.2)) })
}

func content(_ id: String, _ key: String, _ n: Int) -> [UInt8] {
    let seed = UInt8(truncatingIfNeeded: (id + key).utf8.reduce(0) { $0 &+ Int($1) })
    return (0..<n).map { UInt8(truncatingIfNeeded: Int(seed) &+ $0 &* 31) }
}

final class Rig {
    let journal: InMemoryJournal
    var core: SenderCore
    var mono: UInt64 = 0
    var wall: Int64 = 1_700_000_000_000
    var library: [AssetDescriptor]
    var served = 0
    var frames: [Frame] = []
    var decoder = FrameDecoder()
    var gotPreface = false
    var needsUser: [UserAction] = []
    var finished: JobSummary?
    var stored: [UInt8]?
    var inspected: [[AssetID]] = []
    var deletes: [(UUID, [AssetID])] = []
    /// Asset ids → fingerprint overrides for inspect answers (simulate edits during a move).
    var changed: Set<AssetID> = []
    /// `changed` assets report a different size on every inspection from this one on (1-based).
    var changeFromInspect = 1
    var notDeletable: Set<AssetID> = []
    var autoDelete: DeleteOutcome? = .success
    var spec: JobSpec

    init(_ library: [AssetDescriptor], mode: JobMode = .copy, auth: Credentials.Auth = .secret(secret),
         firstMove: Bool = false, journal: InMemoryJournal = InMemoryJournal(), jobID: UUID = UUID()) {
        self.library = library
        self.journal = journal
        let creds = Credentials(deviceID: UUID(), deviceName: "t", appVersion: "t", os: "t", auth: auth,
                                expectedPCID: { if case .secret = auth { return pcID } else { return nil } }(),
                                pcName: "PC", firstMoveToPC: firstMove)
        core = SenderCore(credentials: creds, journal: journal, random: FixedRandom())
        spec = JobSpec(jobID: jobID, mode: mode, section: .photos, label: "t", rulesJSON: Data())
    }

    var now: Now {
        mono += 1
        return Now(mono: mono, wallMs: wall + Int64(mono))
    }

    /// Feed one event and service every driver action until quiescent.
    func run(_ e: Event) {
        var queue = [e]
        while !queue.isEmpty {
            let ev = queue.removeFirst()
            for a in core.handle(ev) { queue += service(a) }
        }
    }

    private func service(_ a: Action) -> [Event] {
        switch a {
        case let .send(bytes, token):
            var b = bytes[...]
            if !gotPreface {
                #expect(Array(b.prefix(8)) == Wire.preface)
                b = b.dropFirst(8)
                gotPreface = true
            }
            decoder.append(b)
            while let f = try! decoder.next() { frames.append(f) }
            return [.sendCompleted(token: token, now: now)]
        case let .closeTransport(after?):
            decoder.append(after)
            while let f = try? decoder.next() { frames.append(f) }
            return []
        case .beginAssetSource(let skip):
            served = 0
            library = library.filter { !skip.contains($0.id) } + library.filter { skip.contains($0.id) }.prefix(0)
            return []
        case let .loadAssets(max):
            let page = Array(library[served..<min(served + max, library.count)])
            served += page.count
            return [.assetsLoaded(page, exhausted: served >= library.count, now: now)]
        case let .describeAssets(ids):
            return [.assetsDescribed(library.filter { ids.contains($0.id) }, now: now)]
        case let .export(id, res, ref):
            return [.exported(ref, size: UInt64(res.sizeHint ?? 0), now: now)]
        case let .read(ref, offset, length, token):
            let a = library.first { SpoolRef.dir(for: $0.id) == ref.assetDir }!
            let data = content(a.id, ref.key, Int(a.resources.first { $0.key == ref.key }!.sizeHint!))
            return [.readDone(token: token, Array(data[Int(offset)..<Int(offset) + length]), now: now)]
        case let .storeSecret(s, _, _):
            stored = s
            return []
        case let .inspectAssets(ids, want):
            inspected.append(ids)
            return [.currentState(ids.map { id in
                let a = library.first { $0.id == id }
                let fp = a.map { a in
                    FingerprintInput(createdMs: a.meta.createdMs, fav: a.meta.fav, loc: nil,
                                     resources: a.resources.map {
                                         let drift = changed.contains(id) && inspected.count >= changeFromInspect ? UInt64(inspected.count) : 0
                                         return (key: $0.key, size: ($0.sizeHint ?? 0) + drift)
                                     },
                                     adjustmentSHA256: [:])
                }
                return AssetCurrentState(id: id, exists: a != nil, canDelete: !notDeletable.contains(id), isLocal: true,
                                         modifiedMs: 5, fingerprint: want.contains(id) ? fp : nil)
            }, now: now)]
        case let .performDelete(batch, ids):
            deletes.append((batch, ids))
            return autoDelete.map { [.deleteFinished(batchID: batch, $0, now: now)] } ?? []
        case let .needsUser(u):
            needsUser.append(u)
            return []
        case let .jobFinished(s):
            finished = s
            return []
        default:
            return []
        }
    }

    // MARK: Receiver script helpers

    func feed<T: Encodable>(_ type: FrameType, _ msg: T) {
        run(.received(try! ControlJSON.frame(type, msg).encoded(), now: now))
    }

    func take<T: Decodable>(_ type: FrameType, _: T.Type = T.self) -> T {
        guard let i = frames.firstIndex(where: { $0.type == type }) else {
            Issue.record("no \(type) among \(frames.map(\.type))")
            fatalError()
        }
        let f = frames.remove(at: i)
        return try! ControlJSON.decode(T.self, from: f.payload)
    }

    func has(_ type: FrameType) -> Bool { frames.contains { $0.type == type } }

    func welcome(secret: String? = nil, slots: UInt32 = 8) -> Welcome {
        Welcome(proto: 1, pc_id: pcID, pc_name: "PC", session_id: "s", store_id: "store", device_secret: secret,
                paired: secret.map { _ in true }, max_slots: slots, max_unacked_assets: 64, max_unacked_bytes: 1 << 30,
                free_bytes: 1 << 40)
    }

    /// startJob → connect → handshake (secret auth) → ready.
    func connect() {
        run(.startJob(spec, now: now))
        run(.transportUp(isTLS: true, now: now))
        run(.received(Wire.preface, now: now))
        let hello: Hello = take(.hello)
        guard case let .secret(sHex) = hello.auth else { fatalError() }
        let sNonce = [UInt8](hexBytes: sHex)!
        let rNonce = [UInt8](repeating: 9, count: 32)
        feed(.challenge, Challenge(proto: 1, r_nonce: rNonce.hexString,
                                   r_proof: IOSTCrypto.rProof(secret: secret, sNonce: sNonce, rNonce: rNonce).hexString))
        let auth: AuthMsg = take(.auth)
        #expect(auth.s_proof == IOSTCrypto.sProof(secret: secret, sNonce: sNonce, rNonce: rNonce).hexString)
        feed(.welcome, welcome())
    }

    /// Answer the next MANIFEST: want every resource of `want` at offset 0, the rest `have`.
    func need(want: Set<AssetID>? = nil, offsets: [AssetID: [String: UInt64]] = [:]) -> Manifest {
        let m: Manifest = take(.manifest)
        let wanted = m.assets.filter { want?.contains($0.id) ?? true }
        feed(.need, Need(job_id: m.job.job_id, page: m.page,
                         want: wanted.map { a in Want(id: a.id, res: a.res.map { ResOffset(key: $0.key, offset: offsets[a.id]?[$0.key] ?? 0) }) },
                         have: m.assets.filter { !(want?.contains($0.id) ?? true) }.map(\.id)))
        return m
    }

    /// Receiver side of a whole resource: RES_BEGIN … DATA … RES_END, returning the bytes.
    func receiveResource() -> (ResBegin, [UInt8], ResEnd) {
        let b: ResBegin = take(.resBegin)
        var bytes: [UInt8] = []
        while let i = frames.firstIndex(where: { $0.type == .data }) {
            let c = try! DataChunk(frame: frames.remove(at: i))
            #expect(c.slot == b.slot)
            #expect(c.offset == b.offset + UInt64(bytes.count))
            bytes += c.bytes
            if b.offset + UInt64(bytes.count) == b.size { break }
        }
        let e: ResEnd = take(.resEnd)
        return (b, bytes, e)
    }

    func ack(_ id: String, _ status: String = "durable") {
        feed(.ack, Ack(id: id, status: status, failed: nil))
    }
}

@Test func copyHappyPathWithResumeOffsetAndHaveAsset() throws {
    let lib = [asset("A", [("photo#0", "photo", 600_000)]), asset("B", [("photo#0", "photo", 10)])]
    let rig = Rig(lib)
    rig.connect()
    _ = rig.need(want: ["A"], offsets: ["A": ["photo#0": 300_000]])
    let (b, bytes, e) = rig.receiveResource()
    #expect(b.offset == 300_000 && b.size == 600_000)
    let full = content("A", "photo#0", 600_000)
    #expect(bytes == Array(full[300_000...]), "only the bytes past the offset are sent")
    #expect(e.sha256 == IOSTCrypto.sha256(full).hexString, "hash covers the whole file from 0")
    let end: AssetEnd = rig.take(.assetEnd)
    #expect(end.complete && end.res_keys == ["photo#0"])
    rig.ack("A")
    #expect(rig.finished?.copied == 1 && rig.finished?.alreadyOnPC == 1)
    #expect(rig.take(.bye, Bye.self).code == "done")
    #expect(try rig.journal.assets(job: rig.spec.jobID).values.allSatisfy { $0.state == .acked })
}

@Test func pairingStoresSecretBeforePaired() throws {
    let rig = Rig([], auth: .pair(token: "t0k"))
    rig.run(.startJob(rig.spec, now: rig.now))
    rig.run(.transportUp(isTLS: true, now: rig.now))
    rig.run(.received(Wire.preface, now: rig.now))
    let hello: Hello = rig.take(.hello)
    #expect(hello.auth == .pair(token: "t0k"))
    rig.feed(.welcome, rig.welcome(secret: secret.hexString))
    #expect(rig.stored == secret)
    #expect(!rig.has(.paired), "PAIRED only after the Keychain write")
    rig.run(.secretStored(now: rig.now))
    #expect(rig.has(.paired))
    #expect(rig.has(.manifest))
}

@Test func pairingRefusedOverPlainTransport() throws {
    let rig = Rig([], auth: .pair(token: "t"))
    rig.run(.startJob(rig.spec, now: rig.now))
    rig.run(.transportUp(isTLS: false, now: rig.now))
    #expect(!rig.has(.hello))
}

@Test func impostorPCIsRejectedBeforeWeProveAnything() throws {
    let rig = Rig([])
    rig.run(.startJob(rig.spec, now: rig.now))
    rig.run(.transportUp(isTLS: true, now: rig.now))
    rig.run(.received(Wire.preface, now: rig.now))
    _ = rig.take(.hello, Hello.self)
    rig.feed(.challenge, Challenge(proto: 1, r_nonce: String(repeating: "09", count: 32), r_proof: String(repeating: "00", count: 32)))
    #expect(!rig.has(.auth))
    #expect(rig.needsUser.contains { if case .pairAgain = $0 { return true } else { return false } })
}

@Test func wrongPCIsBlocked() throws {
    let rig = Rig([])
    rig.run(.startJob(rig.spec, now: rig.now))
    rig.run(.transportUp(isTLS: true, now: rig.now))
    rig.run(.received(Wire.preface, now: rig.now))
    let hello: Hello = rig.take(.hello)
    guard case let .secret(s) = hello.auth else { return }
    let r = [UInt8](repeating: 9, count: 32)
    rig.feed(.challenge, Challenge(proto: 1, r_nonce: r.hexString,
                                   r_proof: IOSTCrypto.rProof(secret: secret, sNonce: [UInt8](hexBytes: s)!, rNonce: r).hexString))
    var w = rig.welcome()
    w.pc_id = "other-pc"
    rig.feed(.welcome, w)
    #expect(rig.needsUser == [.wrongPC])
}

/// A NACK for the last resource arrives after our ASSET_END (always, for a hash mismatch over a real
/// network), so the PC answers ACK failed. A retry pass reconnects and re-sends the asset.
@Test func failedAckTriggersARetryPass() throws {
    let rig = Rig([asset("A", [("photo#0", "photo", 1000)])])
    rig.connect()
    _ = rig.need()
    _ = rig.receiveResource()
    _ = rig.take(.assetEnd, AssetEnd.self)
    rig.feed(.resNack, ResNack(id: "A", key: "photo#0", why: "hash_mismatch", attempt: 1))
    rig.feed(.ack, Ack(id: "A", status: "failed", failed: [FailedKey(key: "photo#0", why: "missing")]))
    #expect(rig.finished == nil, "not finished: a retry pass follows")
    rig.frames = []
    rig.gotPreface = false
    rig.decoder = FrameDecoder()
    rig.mono += 10
    rig.run(.tick(now: rig.now))
    rig.run(.transportUp(isTLS: true, now: rig.now))
    rig.run(.received(Wire.preface, now: rig.now))
    let hello: Hello = rig.take(.hello)
    guard case let .secret(sh) = hello.auth else { return }
    let r = [UInt8](repeating: 9, count: 32)
    rig.feed(.challenge, Challenge(proto: 1, r_nonce: r.hexString,
                                   r_proof: IOSTCrypto.rProof(secret: secret, sNonce: [UInt8](hexBytes: sh)!, rNonce: r).hexString))
    rig.feed(.welcome, rig.welcome())
    let m = rig.need()
    #expect(m.assets.map(\.id) == ["A"])
    _ = rig.receiveResource()
    _ = rig.take(.assetEnd, AssetEnd.self)
    rig.ack("A")
    #expect(rig.finished?.copied == 1)
}

@Test func needMoreReopensTheAsset() throws {
    let rig = Rig([asset("E", [("photo#0", "photo", 10), ("full_size_photo#0", "full_size_photo", 20), ("adjustment_data#0", "adjustment_data", 5)])])
    rig.connect()
    let m: Manifest = rig.take(.manifest)
    rig.feed(.need, Need(job_id: m.job.job_id, page: 0, want: [Want(id: "E", res: [ResOffset(key: "adjustment_data#0", offset: 0)])], have: []))
    let (b, _, _) = rig.receiveResource()
    #expect(b.key == "adjustment_data#0")
    _ = rig.take(.assetEnd, AssetEnd.self)
    rig.feed(.needMore, NeedMore(id: "E", res: [ResOffset(key: "full_size_photo#0", offset: 0)]))
    let (b2, _, _) = rig.receiveResource()
    #expect(b2.key == "full_size_photo#0")
    #expect(rig.take(.assetEnd, AssetEnd.self).complete)
}

@Test func adjustmentDataGoesFirst() throws {
    let rig = Rig([asset("E", [("photo#0", "photo", 10), ("adjustment_data#0", "adjustment_data", 5)])])
    rig.connect()
    _ = rig.need()
    #expect(rig.receiveResource().0.key == "adjustment_data#0")
}

@Test func pauseStopsDataUntilResume() throws {
    let rig = Rig([asset("A", [("photo#0", "photo", 10)]), asset("B", [("photo#0", "photo", 10)])])
    rig.connect()
    let m: Manifest = rig.take(.manifest)
    rig.feed(.pause, Pause(why: "disk_low"))
    rig.feed(.need, Need(job_id: m.job.job_id, page: 0, want: m.assets.map { Want(id: $0.id, res: [ResOffset(key: "photo#0", offset: 0)]) }, have: []))
    #expect(!rig.has(.resBegin))
    rig.feed(.resume, Empty())
    #expect(rig.has(.resBegin))
}

@Test func exportFailureClosesTheAssetIncomplete() throws {
    let rig = Rig([asset("A", [("photo#0", "photo", 10)])])
    rig.connect()
    _ = rig.need()
    // The rig auto-exported; simulate a late failure report for a fresh asset instead.
    rig.run(.exportFailed(SpoolRef(jobID: rig.spec.jobID, assetDir: SpoolRef.dir(for: "A"), key: "photo#0"), .notLocal, now: rig.now))
    #expect(rig.frames.contains { $0.type == .resAbort } || rig.frames.contains { $0.type == .assetEnd })
}

// MARK: Move

func moveRig(_ ids: [String], firstMove: Bool = false) -> Rig {
    let rig = Rig(ids.map { asset($0, [("photo#0", "photo", 100)]) }, mode: .move, firstMove: firstMove)
    rig.connect()
    _ = rig.need()
    for id in ids {
        _ = rig.receiveResource()
        _ = rig.take(.assetEnd, AssetEnd.self)
        rig.ack(id)
    }
    return rig
}

func answerVerify(_ rig: Rig, bad: Set<String> = []) {
    let v: Verify = rig.take(.verify)
    rig.feed(.verified, Verified(seq: v.seq, ok: v.assets.map(\.id).filter { !bad.contains($0) },
                                 bad: bad.map { BadAsset(id: $0, why: "size_mismatch", key: "photo#0") }))
}

@Test func moveVerifiesThenDeletesInOneBatch() throws {
    let rig = moveRig(["A", "B", "C"])
    answerVerify(rig, bad: ["C"])
    #expect(rig.deletes.count == 1 && Set(rig.deletes[0].1) == ["A", "B"], "C failed VERIFY and is kept")
    #expect(rig.finished?.deleted == 2)
    let rows = try! rig.journal.assets(job: rig.spec.jobID)
    #expect(rows["A"]?.state == .deleted && rows["C"]?.state == .failed)
}

@Test func firstMoveToNewPCIsGated() throws {
    let rig = moveRig(["A"], firstMove: true)
    answerVerify(rig)
    #expect(rig.deletes.isEmpty)
    #expect(rig.needsUser == [.confirmFirstMove(pcName: "PC")])
    rig.run(.userReply(.confirmFirstMove(true), now: rig.now))
    #expect(rig.deletes.count == 1)
}

@Test func undeletableAssetIsDroppedNotBatched() throws {
    let rig = moveRig(["A", "B"])
    rig.notDeletable = ["B"]
    answerVerify(rig)
    #expect(rig.deletes.first?.1 == ["A"])
    #expect(try! rig.journal.assets(job: rig.spec.jobID)["B"]?.droppedReason == "not_deletable")
}

@Test func changedDuringMoveIsReverifiedOnceThenDropped() throws {
    let rig = moveRig(["A", "B"])
    rig.changed = ["B"] // B's content changes after VERIFY, on every look
    rig.changeFromInspect = 2
    answerVerify(rig)
    #expect(rig.deletes.first?.1 == ["A"])
    // B is re-manifested (move jobs allow it once), then verified again…
    _ = rig.need(want: [])
    answerVerify(rig)
    // …and still differs at the pre-delete check: dropped, never deleted.
    #expect(rig.deletes.count == 1)
    let b = try! rig.journal.assets(job: rig.spec.jobID)["B"]
    #expect(b?.droppedReason == "changed_during_move" && b?.reverifyCount == 1)
}

@Test func cancelledDeletePromptIsDeclinedAndOfferedAgain() throws {
    let rig = moveRig(["A"])
    rig.autoDelete = .userCancelled
    answerVerify(rig)
    #expect(rig.needsUser == [.confirmDeleteAgain(count: 1)])
    #expect(try! rig.journal.assets(job: rig.spec.jobID)["A"]?.state == .declined)
    rig.autoDelete = .success
    rig.run(.userReply(.deleteAgain(true), now: rig.now))
    #expect(rig.deletes.count == 2 && rig.finished?.deleted == 1)
}

@Test func deleteBatchRecoveredAfterCrash() throws {
    // Crash matrix S5: batch requested, result never seen. "A" is gone, "B" still exists.
    let journal = InMemoryJournal()
    let job = UUID()
    let spec = JobSpec(jobID: job, mode: .move, section: .photos, label: "t", rulesJSON: Data())
    _ = try journal.createOrResume(spec, wallMs: 1)
    try journal.record([.state(job: job, asset: "A", .verified, reason: nil),
                        .state(job: job, asset: "B", .verified, reason: nil),
                        .deleteBatch(job: job, batch: UUID(), assets: ["A", "B"], atMs: 1)])
    let rig = Rig([asset("B", [("photo#0", "photo", 100)])], mode: .move, journal: journal, jobID: job)
    rig.run(.startJob(rig.spec, now: rig.now))
    let rows = try journal.assets(job: job)
    #expect(rows["A"]?.state == .deleted, "missing after the crash → it was deleted")
    #expect(rows["B"]?.state == .acked, "still present → verify again")
}

@Test func verifiedStateNeverSurvivesARestart() throws {
    let journal = InMemoryJournal()
    let spec = JobSpec(jobID: UUID(), mode: .move, section: .photos, label: "t", rulesJSON: Data())
    _ = try journal.createOrResume(spec, wallMs: 1)
    try journal.record([.verified(job: spec.jobID, asset: "A", fp: [1], modifiedMs: 1, atMs: 1)])
    _ = try journal.createOrResume(spec, wallMs: 2)
    #expect(try journal.assets(job: spec.jobID)["A"]?.state == .acked)
}

@Test func reconnectDuringVerifyReestablishesTheJob() throws {
    let rig = moveRig(["A"])
    _ = rig.take(.verify, Verify.self)
    rig.run(.transportDown(.closed, now: rig.now))
    rig.mono += 2000
    rig.run(.tick(now: rig.now))
    rig.gotPreface = false
    rig.decoder = FrameDecoder()
    rig.frames = []
    rig.run(.transportUp(isTLS: true, now: rig.now))
    rig.run(.received(Wire.preface, now: rig.now))
    let hello: Hello = rig.take(.hello)
    guard case let .secret(s) = hello.auth else { return }
    let r = [UInt8](repeating: 9, count: 32)
    rig.feed(.challenge, Challenge(proto: 1, r_nonce: r.hexString,
                                   r_proof: IOSTCrypto.rProof(secret: secret, sNonce: [UInt8](hexBytes: s)!, rNonce: r).hexString))
    rig.feed(.welcome, rig.welcome())
    #expect(rig.has(.manifest) && !rig.has(.verify), "MANIFEST first: the PC's job state is per session")
}

// The sender (phone) state machine: deterministic, synchronous, no I/O (TRANSFERCORE §1).
// Every input is an Event; every side effect is an Action the driver performs.
import Foundation
import IOSTWire

public final class SenderCore {
    // MARK: Configuration

    private var creds: Credentials
    private let journal: JournalStore
    private var random: RandomSource
    private let config: CoreConfig

    public init(credentials: Credentials, journal: JournalStore, random: RandomSource = SystemRandom(),
                config: CoreConfig = CoreConfig()) {
        creds = credentials
        self.journal = journal
        self.random = random
        self.config = config
    }

    // MARK: State

    private enum Conn: Equatable {
        case idle
        case backoff(until: UInt64, attempt: Int)
        case connecting(attempt: Int)
        /// Transport up: waiting for preface / CHALLENGE / WELCOME / PAIRED round trip.
        case handshaking(deadline: UInt64)
        /// Pairing: WELCOME carried the secret; waiting for the Keychain write.
        case storingSecret(deadline: UInt64)
        case ready
        case blocked
    }

    private enum JobPhase: Equatable {
        case recoveringDeletes
        case transfer
        case verify
        case gate
        case delete
        case reverify
        case done
    }

    private struct ResSend {
        var key: ResKey
        var size: UInt64
        /// Offset the receiver asked for; bytes before it are only hashed.
        var start: UInt64
        var pos: UInt64 = 0
        var hasher = SHA256Stream()
        var readToken: UInt64?
    }

    private struct Work {
        var desc: AssetDescriptor
        var queue: [ResOffset]
        var current: ResSend?
        var sizes: [ResKey: UInt64] = [:]
        var exportRequested: Set<ResKey> = []
        var ended = false
        var slot: UInt16?
        var attempts: [ResKey: Int] = [:]
        var failedWhy: String?
        var bytes: UInt64 = 0
    }

    private var conn: Conn = .idle
    private var spec: JobSpec?
    private var phase: JobPhase = .transfer
    private var progress = JobProgress()
    private var summary = JobSummary()
    private var lastProgressMono: UInt64 = 0
    private var now = Now(mono: 0, wallMs: 0)

    // Session (reset on every reconnect)
    private var decoder = FrameDecoder()
    private var preface: [UInt8] = []
    private var sNonce: [UInt8] = []
    private var welcome: Welcome?
    private var pendingSecret: [UInt8]?
    private var nextToken: UInt64 = 1
    private var sendBytes: [UInt64: Int] = [:]
    private var outstandingSend = 0
    private var lastIn: UInt64 = 0
    private var lastOut: UInt64 = 0
    private var pingN: UInt64 = 0
    private var pausedByPC = false
    private var diskFull = false

    // Transfer
    private var nextPage: UInt32 = 0
    private var pages: [UInt32: [AssetDescriptor]] = [:]
    private var loading = false
    private var exhausted = false
    private var work: [AssetID: Work] = [:]
    private var laneQueue: [Lane: [AssetID]] = [.photo: [], .video: []]
    private var slots: [UInt16: AssetID] = [:]
    private var readOwner: [UInt64: AssetID] = [:]
    private var thermal: ThermalLevel = .nominal
    private var freeSpace: UInt64 = .max
    private var reManifest: [AssetDescriptor] = []
    /// Assets whose ACK failed for a reason a fresh attempt can fix (hash/size/offset, missing).
    private var retryable: Set<AssetID> = []
    private var retryPasses = 0
    private let maxRetryPasses = 2

    // Move
    private var verifySeq: UInt64 = 0
    private var verifyPending: [AssetID: [UInt8]] = [:]
    private var verifyQueue: [AssetID] = []
    private var awaitingInspect: InspectPurpose?
    private var pendingDelete: (batch: UUID, ids: [AssetID])?
    private var declinedIDs: [AssetID] = []
    private var reverifyIDs: [AssetID] = []
    private var journalBuffer: [JournalUpdate] = []

    private enum InspectPurpose { case verify, delete, recovery }

    public var snapshot: JobProgress { progress }

    // MARK: Entry point

    public func handle(_ event: Event) -> [Action] {
        var out: [Action] = []
        switch event {
        case let .startJob(s, n): now = n; start(s, &out)
        case let .cancelJob(n): now = n; cancel(&out)
        case let .tick(n): now = n; tick(&out)
        case let .transportUp(isTLS, n): now = n; transportUp(isTLS: isTLS, &out)
        case let .received(bytes, n): now = n; received(bytes, &out)
        case let .sendCompleted(token, n):
            now = n
            if let b = sendBytes.removeValue(forKey: token) { outstandingSend -= b }
            pump(&out)
        case let .transportDown(reason, n): now = n; transportDown(reason, &out)
        case let .secretStored(n): now = n; secretStored(&out)
        case let .assetsLoaded(list, ex, n): now = n; assetsLoaded(list, exhausted: ex, &out)
        case let .assetsDescribed(list, n): now = n; manifestReverify(list, &out)
        case let .exported(ref, size, n): now = n; exported(ref, size: size, &out)
        case let .exportFailed(ref, why, n): now = n; exportFailed(ref, why, &out)
        case let .readDone(token, data, n): now = n; readDone(token, data, &out)
        case let .readFailed(token, n): now = n; readFailed(token, &out)
        case let .currentState(states, n): now = n; currentState(states, &out)
        case let .deleteFinished(batch, outcome, n): now = n; deleteFinished(batch, outcome, &out)
        case let .userReply(reply, n): now = n; userReply(reply, &out)
        case let .freeSpaceChanged(b, n): now = n; freeSpace = b; pump(&out)
        case let .thermal(t, n): now = n; thermal = t; pump(&out)
        }
        flushJournal(&out)
        return out
    }

    // MARK: Job lifecycle

    private func start(_ s: JobSpec, _ out: inout [Action]) {
        guard spec == nil else { return }
        spec = s
        do {
            _ = try journal.createOrResume(s, wallMs: now.wallMs)
            let rows = try journal.assets(job: s.jobID)
            let terminal = Set(rows.keys.map(SpoolRef.dir(for:)))
            out.append(.sweepSpool(keepJob: s.jobID, dropAssetDirs: terminal))
            // Crash matrix S5: a delete batch was requested but we never saw the result.
            let open = try journal.deleteBatches(job: s.jobID, state: "requested")
            if s.mode == .move, !open.isEmpty {
                phase = .recoveringDeletes
                pendingDelete = (open[0].batch, open.flatMap(\.assets))
                awaitingInspect = .recovery
                out.append(.inspectAssets(pendingDelete!.ids, wantFingerprint: []))
            }
        } catch {
            return journalFailed(error, &out)
        }
        connect(attempt: 0, &out)
    }

    private func cancel(_ out: inout [Action]) {
        guard spec != nil else { return }
        out.append(.closeTransport(after: frame(.bye, Bye(code: "user_cancel"))))
        conn = .idle
        resetSession()
        finish(&out, sendBye: false)
    }

    private func finish(_ out: inout [Action], sendBye: Bool) {
        guard let s = spec, phase != .done else { return }
        if sendBye, conn == .ready {
            out.append(.closeTransport(after: frame(.bye, Bye(code: "done"))))
        }
        phase = .done
        progress.phase = .done
        conn = .idle
        journalBuffer.append(.jobState(job: s.jobID, "done"))
        out.append(.progress(progress))
        out.append(.jobFinished(summary))
    }

    private func journalFailed(_ error: Error, _ out: inout [Action]) {
        // Move safety relies on the journal: never continue without it.
        conn = .blocked
        progress.phase = .blocked
        out.append(.needsUser(.journalError("\(error)")))
    }

    private func flushJournal(_ out: inout [Action]) {
        guard !journalBuffer.isEmpty else { return }
        do {
            try journal.record(journalBuffer)
            journalBuffer.removeAll()
        } catch {
            journalBuffer.removeAll()
            journalFailed(error, &out)
        }
    }

    // MARK: Connection

    private func connect(attempt: Int, _ out: inout [Action]) {
        conn = .connecting(attempt: attempt)
        progress.phase = .connecting
        out.append(.connect(attempt: attempt))
    }

    private func resetSession() {
        decoder = FrameDecoder()
        preface = []
        welcome = nil
        pendingSecret = nil
        sendBytes = [:]
        outstandingSend = 0
        pausedByPC = false
        diskFull = false
        nextPage = 0
        pages = [:]
        loading = false
        exhausted = false
        work = [:]
        laneQueue = [.photo: [], .video: []]
        slots = [:]
        readOwner = [:]
        verifyPending = [:]
        verifyQueue = []
    }

    private func transportDown(_ reason: TransportDownReason, _ out: inout [Action]) {
        guard spec != nil, phase != .done, conn != .blocked else { return }
        let attempt: Int
        if case let .connecting(a) = conn { attempt = a + 1 } else { attempt = 0 }
        resetSession()
        let delay = config.backoffMs[min(attempt, config.backoffMs.count - 1)]
        conn = .backoff(until: now.mono + delay, attempt: attempt)
        progress.phase = .connecting
        if case let .error(msg) = reason { out.append(.log(.w, "connection lost: \(msg)")) }
    }

    private func transportUp(isTLS: Bool, _ out: inout [Action]) {
        guard case .connecting = conn else { return }
        if case .pair = creds.auth, !isTLS {
            out.append(.closeTransport(after: nil))
            return
        }
        lastIn = now.mono
        sNonce = random.bytes(32)
        let auth: HelloAuth
        switch creds.auth {
        case .pair(let token): auth = .pair(token: token)
        case .secret: auth = .secret(sNonce: sNonce.hexString)
        }
        let hello = Hello(proto: ProtoRange(min: 1, max: 1), device_id: creds.deviceID.uuidString.lowercased(),
                          device_name: creds.deviceName, app_version: creds.appVersion, os: creds.os, auth: auth)
        let limit = { if case .pair = self.creds.auth { return self.config.pairingMs } else { return self.config.handshakeMs } }()
        conn = .handshaking(deadline: now.mono + limit)
        send(Wire.preface + frame(.hello, hello), &out)
    }

    private func secretStored(_ out: inout [Action]) {
        guard case .storingSecret = conn, let secret = pendingSecret, let w = welcome else { return }
        // Two-phase pairing: only now may the PC commit (Δ3).
        creds.auth = .secret(secret)
        creds.expectedPCID = w.pc_id
        pendingSecret = nil
        send(frame(.paired, Empty()), &out)
        becomeReady(&out)
    }

    private func tick(_ out: inout [Action]) {
        switch conn {
        case let .backoff(until, attempt) where now.mono >= until:
            connect(attempt: attempt, &out)
        case let .handshaking(deadline) where now.mono >= deadline,
             let .storingSecret(deadline) where now.mono >= deadline:
            out.append(.closeTransport(after: frame(.bye, Bye(code: "timeout"))))
            transportDown(.error("handshake timeout"), &out)
        case .ready:
            if now.mono - lastIn >= config.peerSilenceMs {
                out.append(.closeTransport(after: frame(.bye, Bye(code: "timeout"))))
                transportDown(.error("peer silent"), &out)
            } else if now.mono - lastOut >= config.pingAfterMs {
                pingN += 1
                send(frame(.ping, Ping(n: pingN)), &out)
            }
        default:
            break
        }
        if now.mono - lastProgressMono >= 250 {
            lastProgressMono = now.mono
            out.append(.progress(progress))
        }
    }

    // MARK: Receiving

    private func received(_ bytes: [UInt8], _ out: inout [Action]) {
        guard conn != .idle, conn != .blocked else { return }
        lastIn = now.mono
        var rest = bytes[...]
        if preface.count < Wire.preface.count {
            let need = Wire.preface.count - preface.count
            preface += rest.prefix(need)
            rest = rest.dropFirst(need)
            if preface.count == Wire.preface.count, checkPreface(preface) != .ok {
                out.append(.closeTransport(after: nil))
                return transportDown(.error("bad preface"), &out)
            }
        }
        decoder.append(rest)
        while true {
            let f: Frame
            do {
                guard let next = try decoder.next() else { return }
                f = next
            } catch {
                return protocolError("\(error)", &out)
            }
            handleFrame(f, &out)
            if conn == .idle || conn == .blocked { return }
            if case .backoff = conn { return }
        }
    }

    private func decode<T: Decodable>(_ t: T.Type, _ f: Frame, _ out: inout [Action]) -> T? {
        do {
            return try ControlJSON.decode(t, from: f.payload)
        } catch {
            protocolError("bad \(f.type): \(error)", &out)
            return nil
        }
    }

    private func protocolError(_ msg: String, _ out: inout [Action]) {
        out.append(.log(.e, "protocol error: \(msg)"))
        out.append(.closeTransport(after: frame(.bye, Bye(code: "protocol_error", msg: String(msg.prefix(200))))))
        transportDown(.error(msg), &out)
    }

    private func handleFrame(_ f: Frame, _ out: inout [Action]) {
        switch f.type {
        case .ping:
            send(Frame(type: .pong, payload: f.payload), &out)
        case .pong:
            break
        case .bye:
            guard let b = decode(Bye.self, f, &out) else { return }
            peerBye(b, &out)
        case .challenge:
            guard case .handshaking = conn, case .secret(let secret) = creds.auth,
                  let c = decode(Challenge.self, f, &out) else { return protocolError("unexpected CHALLENGE", &out) }
            let rNonce = Array(hexBytes: c.r_nonce) ?? []
            let expect = IOSTCrypto.rProof(secret: secret, sNonce: sNonce, rNonce: rNonce)
            // The PC proves it knows the secret before we prove anything (§4.2).
            guard rNonce.count == 32, IOSTCrypto.constantTimeEqual(Array(hexBytes: c.r_proof) ?? [], expect) else {
                out.append(.closeTransport(after: frame(.bye, Bye(code: "auth_failed"))))
                return block(.pairAgain(reason: "This PC failed authentication"), &out)
            }
            let proof = IOSTCrypto.sProof(secret: secret, sNonce: sNonce, rNonce: rNonce)
            send(frame(.auth, AuthMsg(s_proof: proof.hexString)), &out)
        case .welcome:
            guard case let .handshaking(deadline) = conn, let w = decode(Welcome.self, f, &out) else {
                return protocolError("unexpected WELCOME", &out)
            }
            if let expected = creds.expectedPCID, expected != w.pc_id {
                out.append(.closeTransport(after: frame(.bye, Bye(code: "auth_failed"))))
                return block(.wrongPC, &out)
            }
            welcome = w
            if case .pair = creds.auth {
                guard let secret = w.device_secret.flatMap({ Array(hexBytes: $0) }), secret.count == 32 else {
                    return protocolError("pairing WELCOME without secret", &out)
                }
                pendingSecret = secret
                conn = .storingSecret(deadline: deadline)
                out.append(.storeSecret(secret, pcID: w.pc_id, pcName: w.pc_name))
            } else {
                becomeReady(&out)
            }
        case .need:
            guard conn == .ready, let n = decode(Need.self, f, &out) else { return }
            need(n, &out)
        case .needMore:
            guard conn == .ready, let n = decode(NeedMore.self, f, &out) else { return }
            needMore(n, &out)
        case .ack:
            guard conn == .ready, let a = decode(Ack.self, f, &out) else { return }
            ack(a, &out)
        case .resNack:
            guard conn == .ready, let n = decode(ResNack.self, f, &out) else { return }
            nack(n, &out)
        case .verified:
            guard conn == .ready, let v = decode(Verified.self, f, &out) else { return }
            verified(v, &out)
        case .pause:
            pausedByPC = true
            progress.paused = (try? ControlJSON.decode(Pause.self, from: f.payload))?.why ?? "pc"
        case .resume:
            pausedByPC = false
            diskFull = false
            progress.paused = nil
            pump(&out)
        default:
            protocolError("unexpected \(f.type)", &out)
        }
    }

    private func peerBye(_ b: Bye, _ out: inout [Action]) {
        out.append(.closeTransport(after: nil))
        switch b.code {
        case "auth_failed", "unknown_device": block(.pairAgain(reason: b.code), &out)
        case "token_invalid": block(.pairAgain(reason: "The pairing QR code expired; scan a fresh one"), &out)
        case "version_unsupported": block(.updateApp(olderSide: (b.max ?? 1) < 1 ? "PC" : "iPhone"), &out)
        case "disk_full": block(.pcDiskFull, &out)
        default: transportDown(.error("PC closed: \(b.code)"), &out)
        }
    }

    private func block(_ why: UserAction, _ out: inout [Action]) {
        resetSession()
        conn = .blocked
        progress.phase = .blocked
        out.append(.needsUser(why))
    }

    private func becomeReady(_ out: inout [Action]) {
        guard let s = spec, let w = welcome else { return }
        conn = .ready
        flushJournal(&out)
        // Δ16: acked marks are only valid for the same PC index.
        var skip = Set<AssetID>()
        do {
            let rec = try journal.createOrResume(s, wallMs: now.wallMs)
            if rec.pcID != w.pc_id || rec.storeID != w.store_id {
                journalBuffer.append(.clearAcked(job: s.jobID))
                journalBuffer.append(.binding(job: s.jobID, pcID: w.pc_id, storeID: w.store_id))
            } else if phase == .transfer {
                skip = Set(try journal.assets(job: s.jobID).filter { $0.value.state == .acked }.keys)
            }
        } catch {
            return journalFailed(error, &out)
        }
        switch phase {
        case .transfer:
            startTransfer(skip: skip, &out)
        case .verify:
            // The PC's job state is per session: re-establish it with a MANIFEST pass (every asset
            // is `have` by now, so this is cheap), and VERIFY runs again when the transfer completes.
            phase = .transfer
            startTransfer(skip: [], &out)
        case .reverify:
            if !reManifest.isEmpty { sendManifest(reManifest, last: true, &out) }
        default:
            break
        }
    }

    private func startTransfer(skip: Set<AssetID>, _ out: inout [Action]) {
        progress.phase = .transferring
        out.append(.beginAssetSource(skip: skip))
        requestPage(&out)
    }

    // MARK: Sending helpers

    private func frame<T: Encodable>(_ t: FrameType, _ msg: T) -> [UInt8] {
        // Encoding our own message types can't fail.
        (try? ControlJSON.frame(t, msg).encoded()) ?? []
    }

    private func send(_ bytes: [UInt8], _ out: inout [Action]) {
        let token = nextToken
        nextToken += 1
        sendBytes[token] = bytes.count
        outstandingSend += bytes.count
        lastOut = now.mono
        out.append(.send(bytes, token: token))
    }

    private func send(_ f: Frame, _ out: inout [Action]) {
        send((try? f.encoded()) ?? [], &out)
    }

    // MARK: Paging (§6.1)

    private func requestPage(_ out: inout [Action]) {
        guard conn == .ready, phase == .transfer, !loading, !exhausted, pages.count < 2 else { return }
        loading = true
        out.append(.loadAssets(max: config.pageSize))
    }

    private func assetsLoaded(_ list: [AssetDescriptor], exhausted ex: Bool, _ out: inout [Action]) {
        guard conn == .ready, phase == .transfer else { return }
        loading = false
        exhausted = ex
        progress.assetsKnown += list.count
        if !list.isEmpty || (ex && nextPage == 0) {
            sendManifest(list, last: ex, &out)
        }
        requestPage(&out)
        checkTransferDone(&out)
    }

    private func sendManifest(_ list: [AssetDescriptor], last: Bool, _ out: inout [Action]) {
        guard let s = spec else { return }
        let m = Manifest(job: JobMsg(job_id: s.jobID.uuidString.lowercased(), label: s.label, section: s.section.rawValue,
                                     mode: s.mode.rawValue),
                         page: nextPage, last: last, assets: list.map(Self.wire))
        pages[nextPage] = list
        nextPage += 1
        send(frame(.manifest, m), &out)
    }

    static func wire(_ a: AssetDescriptor) -> AssetMsg {
        AssetMsg(id: a.id, kind: a.kind == .videos ? "video" : "photo", created_ms: a.meta.createdMs, tz_min: a.meta.tzMin,
                 modified_ms: a.modifiedMs, w: UInt32(max(a.w, 0)), h: UInt32(max(a.h, 0)), dur_ms: a.durMs, fav: a.meta.fav,
                 loc: a.meta.loc.map { LocMsg(lat: $0.lat, lon: $0.lon, alt: $0.alt) }, burst_id: a.burstID,
                 subtypes: a.subtypes,
                 res: a.resources.map { ResDescMsg(key: $0.key, type: $0.type, uti: $0.uti, name: $0.name, size: $0.sizeHint) })
    }

    private func need(_ n: Need, _ out: inout [Action]) {
        guard let s = spec, let list = pages.removeValue(forKey: n.page) else {
            return protocolError("NEED for unknown page \(n.page)", &out)
        }
        let byID = Dictionary(list.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        for id in n.have where byID[id] != nil {
            journalBuffer.append(.state(job: s.jobID, asset: id, .acked, reason: nil))
            progress.assetsSkipped += 1
            summary.alreadyOnPC += 1
            out.append(.deleteSpool(jobID: s.jobID, assetDir: SpoolRef.dir(for: id)))
        }
        for w in n.want {
            guard let desc = byID[w.id] else { return protocolError("NEED wants unknown asset", &out) }
            // adjustment_data first so a NEED_MORE arrives early (§6.1).
            let order = Dictionary(desc.resources.enumerated().map { ($1.key, $0) }, uniquingKeysWith: { a, _ in a })
            let queue = w.res.sorted {
                let a = desc.resources[order[$0.key] ?? 0].type == "adjustment_data"
                let b = desc.resources[order[$1.key] ?? 0].type == "adjustment_data"
                return a != b ? a : (order[$0.key] ?? 0) < (order[$1.key] ?? 0)
            }
            work[w.id] = Work(desc: desc, queue: queue)
            laneQueue[desc.kind == .videos ? .video : .photo, default: []].append(w.id)
        }
        if phase == .reverify { phase = .transfer }
        requestPage(&out)
        pump(&out)
        checkTransferDone(&out)
    }

    private func needMore(_ n: NeedMore, _ out: inout [Action]) {
        guard var w = work[n.id] else { return protocolError("NEED_MORE for unknown asset", &out) }
        w.queue.append(contentsOf: n.res)
        if w.ended {
            // Reopen the asset: another ASSET_END follows these resources.
            w.ended = false
            laneQueue[w.desc.kind == .videos ? .video : .photo, default: []].insert(n.id, at: 0)
        }
        work[n.id] = w
        pump(&out)
    }

    // MARK: Scheduling (TRANSFERCORE §6.3)

    private var unackedEnded: Int { work.values.filter(\.ended).count }
    private var unackedBytes: UInt64 { work.values.reduce(0) { $0 + $1.sizes.values.reduce(0, +) } }

    private func slotLimit(_ lane: Lane) -> Int {
        let total = Int(welcome?.max_slots ?? 4)
        var photo = config.photoSlots, video = config.videoSlots
        if thermal == .serious { photo = 1; video = 1 }
        // An idle lane lends its slots.
        if laneQueue[.video, default: []].isEmpty && !slots.values.contains(where: { work[$0]?.desc.kind == .videos }) {
            photo += video
        }
        if laneQueue[.photo, default: []].isEmpty && !slots.values.contains(where: { work[$0]?.desc.kind == .photos }) {
            video += photo
        }
        return min(lane == .photo ? photo : video, total)
    }

    private func windowOpen() -> Bool {
        guard let w = welcome else { return false }
        let spoolBudget = min(2 << 30, freeSpace / 10)
        let maxBytes = min(w.max_unacked_bytes, spoolBudget)
        return work.values.filter { $0.ended || $0.slot != nil }.count < Int(w.max_unacked_assets)
            && (unackedBytes < maxBytes || work.values.allSatisfy { $0.slot == nil })
    }

    private func pump(_ out: inout [Action]) {
        guard conn == .ready, let s = spec, phase == .transfer || phase == .reverify else { return }
        let stopped = pausedByPC || diskFull || thermal == .critical
        // Assign assets to free slots.
        if !stopped {
            for lane in [Lane.video, .photo] {
                while let next = laneQueue[lane]?.first,
                      slots.values.filter({ work[$0]?.desc.kind == (lane == .video ? .videos : .photos) }).count < slotLimit(lane),
                      windowOpen(), let slot = freeSlot() {
                    laneQueue[lane]?.removeFirst()
                    guard var w = work[next] else { continue }
                    w.slot = slot
                    slots[slot] = next
                    for r in w.queue where !w.exportRequested.contains(r.key) {
                        guard let d = w.desc.resources.first(where: { $0.key == r.key }) else { continue }
                        w.exportRequested.insert(r.key)
                        out.append(.export(next, d, to: SpoolRef(jobID: s.jobID, assetDir: SpoolRef.dir(for: next), key: r.key)))
                    }
                    work[next] = w
                }
            }
        }
        // Advance every slot (round robin by slot number).
        for slot in slots.keys.sorted() {
            guard let id = slots[slot] else { continue }
            advance(slot: slot, id: id, stopped: stopped, &out)
        }
    }

    private func freeSlot() -> UInt16? {
        let total = UInt16(welcome?.max_slots ?? 4)
        return (0..<total).first { slots[$0] == nil }
    }

    /// Move one slot forward: RES_BEGIN, reads, RES_END, ASSET_END. A loop with explicit
    /// write-backs (no `defer`): finishing a resource continues with the next one in the same call.
    private func advance(slot: UInt16, id: AssetID, stopped: Bool, _ out: inout [Action]) {
        while true {
            guard var w = work[id], let s = spec else { return }
            if w.current == nil {
                guard !stopped else { return }
                guard let next = w.queue.first else {
                    // Every wanted resource has RES_END: close the asset and free the slot.
                    let keys = w.desc.resources.map(\.key)
                    send(frame(.assetEnd, AssetEnd(id: id, res_keys: keys, complete: w.failedWhy == nil, why: w.failedWhy)), &out)
                    w.ended = true
                    w.slot = nil
                    slots[slot] = nil
                    work[id] = w
                    return
                }
                guard let size = w.sizes[next.key] else { return } // still exporting
                w.queue.removeFirst()
                let start = next.offset <= size ? next.offset : 0
                send(frame(.resBegin, ResBegin(slot: slot, id: id, key: next.key, offset: start, size: size)), &out)
                w.current = ResSend(key: next.key, size: size, start: start)
            }
            guard var cur = w.current, cur.readToken == nil else {
                work[id] = w
                return
            }
            if cur.pos >= cur.size {
                send(frame(.resEnd, ResEnd(slot: slot, size: cur.size, sha256: cur.hasher.finalize().hexString)), &out)
                w.current = nil
                work[id] = w
                continue
            }
            // Hash-only reads of the resumed prefix are not gated by the send watermark.
            let hashing = cur.pos < cur.start
            guard hashing || (!stopped && outstandingSend < config.sendWatermark) else {
                work[id] = w
                return
            }
            let end = hashing ? cur.start : cur.size
            let len = Int(min(UInt64(config.chunk), end - cur.pos))
            let token = nextToken
            nextToken += 1
            cur.readToken = token
            readOwner[token] = id
            w.current = cur
            work[id] = w
            out.append(.read(SpoolRef(jobID: s.jobID, assetDir: SpoolRef.dir(for: id), key: cur.key), offset: cur.pos,
                             length: len, token: token))
            return
        }
    }

    private func exported(_ ref: SpoolRef, size: UInt64, _ out: inout [Action]) {
        guard let id = work.first(where: { SpoolRef.dir(for: $0.key) == ref.assetDir })?.key else { return }
        work[id]?.sizes[ref.key] = size
        pump(&out)
    }

    private func exportFailed(_ ref: SpoolRef, _ why: ExportFailure, _ out: inout [Action]) {
        guard let id = work.first(where: { SpoolRef.dir(for: $0.key) == ref.assetDir })?.key, var w = work[id] else { return }
        if why == .noSpace { out.append(.needsUser(.freeSpace(bytes: w.desc.resources.first { $0.key == ref.key }?.sizeHint ?? 0))) }
        failAsset(&w, why: why.rawValue, &out)
        work[id] = w
        pump(&out)
    }

    /// Give up on an asset for this session: abort its resource and close it with complete:false.
    private func failAsset(_ w: inout Work, why: String, _ out: inout [Action]) {
        if let cur = w.current, let slot = w.slot {
            if let t = cur.readToken { readOwner[t] = nil }
            send(frame(.resAbort, ResAbort(slot: slot, why: why)), &out)
        }
        w.current = nil
        w.queue = []
        w.failedWhy = w.failedWhy ?? why
        if w.slot == nil, !w.ended {
            // Not started yet: it still needs its one ASSET_END (Δ9).
            send(frame(.assetEnd, AssetEnd(id: w.desc.id, res_keys: w.desc.resources.map(\.key), complete: false, why: why)), &out)
            w.ended = true
            laneQueue = laneQueue.mapValues { $0.filter { $0 != w.desc.id } }
        }
    }

    private func readDone(_ token: UInt64, _ data: [UInt8], _ out: inout [Action]) {
        guard let id = readOwner.removeValue(forKey: token), var w = work[id], var cur = w.current, cur.readToken == token,
              let slot = w.slot else { return }
        cur.readToken = nil
        if data.isEmpty {
            // The spool file is shorter than exported: treat as a read error.
            w.current = cur
            failAsset(&w, why: "read_error", &out)
            work[id] = w
            return pump(&out)
        }
        cur.hasher.update(data)
        if cur.pos >= cur.start {
            send(DataChunk(slot: slot, offset: cur.pos, bytes: data).frame, &out)
            progress.bytesSent += UInt64(data.count)
            summary.bytes += UInt64(data.count)
        }
        cur.pos += UInt64(data.count)
        w.current = cur
        work[id] = w
        pump(&out)
    }

    private func readFailed(_ token: UInt64, _ out: inout [Action]) {
        guard let id = readOwner.removeValue(forKey: token), var w = work[id] else { return }
        w.current?.readToken = nil
        failAsset(&w, why: "read_error", &out)
        work[id] = w
        pump(&out)
    }

    // MARK: ACK / NACK

    private func ack(_ a: Ack, _ out: inout [Action]) {
        guard let s = spec, let w = work.removeValue(forKey: a.id) else { return protocolError("ACK for unknown asset", &out) }
        if let slot = w.slot { slots[slot] = nil }
        if a.status == "durable" {
            journalBuffer.append(.state(job: s.jobID, asset: a.id, .acked, reason: nil))
            out.append(.deleteSpool(jobID: s.jobID, assetDir: SpoolRef.dir(for: a.id)))
            progress.assetsDone += 1
            summary.copied += 1
        } else {
            let why = w.failedWhy ?? a.failed?.first?.why ?? "failed"
            if w.failedWhy == nil || ["io", "read_error"].contains(why) {
                // A NACK after our ASSET_END (e.g. hash mismatch on the last resource): another
                // pass re-sends it, resuming whatever is durable on the PC.
                retryable.insert(a.id)
            } else {
                journalBuffer.append(.state(job: s.jobID, asset: a.id, .failed, reason: why))
                progress.assetsFailed += 1
                summary.failed[why, default: 0] += 1
            }
            if ["not_local", "asset_gone"].contains(why) {
                out.append(.deleteSpool(jobID: s.jobID, assetDir: SpoolRef.dir(for: a.id)))
            }
        }
        pump(&out)
        checkTransferDone(&out)
    }

    private func nack(_ n: ResNack, _ out: inout [Action]) {
        guard var w = work[n.id] else { return }
        defer { work[n.id] = w }
        if n.why == "disk_full" {
            // Retried from where the PC is after RESUME.
            diskFull = true
            if let cur = w.current, cur.key == n.key {
                if let t = cur.readToken { readOwner[t] = nil }
                w.current = nil
            }
            if !w.queue.contains(where: { $0.key == n.key }) { w.queue.insert(ResOffset(key: n.key, offset: 0), at: 0) }
            return
        }
        let attempts = (w.attempts[n.key] ?? 0) + 1
        w.attempts[n.key] = attempts
        guard attempts < config.maxAttempts else {
            if w.current?.key == n.key, let slot = w.slot {
                if let t = w.current?.readToken { readOwner[t] = nil }
                w.current = nil
                _ = slot
            }
            w.failedWhy = "retries_exhausted"
            w.queue.removeAll { $0.key == n.key }
            return pump(&out)
        }
        // Retry from 0: the PC dropped its .part.
        if let cur = w.current, cur.key == n.key {
            if let t = cur.readToken { readOwner[t] = nil }
            w.current = nil
        }
        w.queue.removeAll { $0.key == n.key }
        w.queue.insert(ResOffset(key: n.key, offset: 0), at: 0)
        if w.ended {
            // NACK after our ASSET_END: the PC will ACK failed; retried next session.
            return
        }
        if w.slot == nil {
            laneQueue[w.desc.kind == .videos ? .video : .photo, default: []].insert(n.id, at: 0)
        }
        out.append(.log(.w, "retrying \(n.key) of \(n.id): \(n.why)"))
        work[n.id] = w
        pump(&out)
    }

    private func checkTransferDone(_ out: inout [Action]) {
        guard phase == .transfer, conn == .ready, exhausted, !loading, pages.isEmpty, work.isEmpty else { return }
        if !retryable.isEmpty {
            guard let s = spec else { return }
            if retryPasses < maxRetryPasses {
                // Reconnect: a new session re-manifests everything not yet acked.
                retryPasses += 1
                retryable = []
                out.append(.log(.i, "retry pass \(retryPasses)"))
                out.append(.closeTransport(after: frame(.bye, Bye(code: "done"))))
                resetSession()
                conn = .backoff(until: now.mono, attempt: 0)
                return
            }
            for id in retryable {
                journalBuffer.append(.state(job: s.jobID, asset: id, .failed, reason: "retries_exhausted"))
                summary.failed["retries_exhausted", default: 0] += 1
                progress.assetsFailed += 1
            }
            retryable = []
        }
        if spec?.mode == .move {
            startVerify(&out)
        } else {
            finish(&out, sendBye: true)
        }
    }

    // MARK: Move: VERIFY (§6.4)

    private func startVerify(_ out: inout [Action]) {
        guard let s = spec else { return }
        // Decisions read the journal: buffered updates (e.g. the last ACK) must be in it first.
        flushJournal(&out)
        phase = .verify
        progress.phase = .verifying
        do {
            verifyQueue = try journal.assets(job: s.jobID).filter { $0.value.state == .acked }.keys.sorted()
        } catch {
            return journalFailed(error, &out)
        }
        nextVerifyBatch(&out)
    }

    private func nextVerifyBatch(_ out: inout [Action]) {
        guard conn == .ready else { return }
        guard !verifyQueue.isEmpty else { return startDeletePhase(&out) }
        let batch = Array(verifyQueue.prefix(config.verifyBatch))
        verifyQueue.removeFirst(batch.count)
        awaitingInspect = .verify
        out.append(.inspectAssets(batch, wantFingerprint: Set(batch)))
    }

    private func sendVerify(_ states: [AssetCurrentState], _ out: inout [Action]) {
        guard let s = spec else { return }
        var assets: [VerifyAsset] = []
        verifyPending = [:]
        for st in states {
            guard st.exists, let fp = st.fingerprint else {
                journalBuffer.append(.state(job: s.jobID, asset: st.id, .dropped, reason: "gone"))
                summary.dropped["gone", default: 0] += 1
                continue
            }
            verifyPending[st.id] = fp.fingerprint
            let res = fp.resources.map { r in
                VerifyRes(key: r.key, size: r.size, sha256: fp.adjustmentSHA256[r.key]?.hexString)
            }
            let loc = fp.loc.map { LocMsg(lat: $0.lat, lon: $0.lon, alt: $0.alt) }
            assets.append(VerifyAsset(id: st.id, meta: VerifyMeta(created_ms: fp.createdMs, fav: fp.fav, loc: loc), res: res))
            modifiedAtVerify[st.id] = st.modifiedMs
        }
        if assets.isEmpty { return nextVerifyBatch(&out) }
        verifySeq += 1
        send(frame(.verify, Verify(seq: verifySeq, assets: assets)), &out)
    }

    private var modifiedAtVerify: [AssetID: Int64] = [:]

    private func verified(_ v: Verified, _ out: inout [Action]) {
        guard let s = spec, phase == .verify else { return }
        for id in v.ok {
            guard let fp = verifyPending[id] else { continue }
            journalBuffer.append(.verified(job: s.jobID, asset: id, fp: fp, modifiedMs: modifiedAtVerify[id] ?? 0,
                                           atMs: now.wallMs))
        }
        for b in v.bad {
            journalBuffer.append(.state(job: s.jobID, asset: b.id, .failed, reason: "verify_failed:\(b.why)"))
            summary.failed["verify_failed", default: 0] += 1
        }
        verifyPending = [:]
        nextVerifyBatch(&out)
    }

    // MARK: Move: delete (§8.4)

    private func startDeletePhase(_ out: inout [Action]) {
        guard let s = spec else { return }
        flushJournal(&out)
        let ids: [AssetID]
        do {
            ids = try journal.assets(job: s.jobID).filter { $0.value.state == .verified }.keys.sorted()
        } catch {
            return journalFailed(error, &out)
        }
        guard !ids.isEmpty else { return afterDeletes(&out) }
        if creds.firstMoveToPC {
            phase = .gate
            out.append(.needsUser(.confirmFirstMove(pcName: welcome?.pc_name ?? creds.pcName)))
            return
        }
        phase = .delete
        progress.phase = .deleting
        awaitingInspect = .delete
        out.append(.inspectAssets(Array(ids.prefix(config.deleteBatch)), wantFingerprint: Set(ids.prefix(config.deleteBatch))))
    }

    private func userReply(_ r: UserReply, _ out: inout [Action]) {
        switch r {
        case .confirmFirstMove(true) where phase == .gate:
            creds.firstMoveToPC = false
            startDeletePhase(&out)
        case .confirmFirstMove(false) where phase == .gate:
            finish(&out, sendBye: true)
        case .deleteAgain(true) where !declinedIDs.isEmpty:
            phase = .delete
            awaitingInspect = .delete
            let ids = declinedIDs
            declinedIDs = []
            out.append(.inspectAssets(ids, wantFingerprint: Set(ids)))
        case .deleteAgain(false):
            declinedIDs = []
            afterDeletes(&out)
        default:
            break
        }
    }

    private func currentState(_ states: [AssetCurrentState], _ out: inout [Action]) {
        guard let purpose = awaitingInspect else { return }
        awaitingInspect = nil
        switch purpose {
        case .verify: sendVerify(states, &out)
        case .delete: guardAndDelete(states, &out)
        case .recovery: recoverDeletes(states, &out)
        }
    }

    private func guardAndDelete(_ states: [AssetCurrentState], _ out: inout [Action]) {
        guard let s = spec else { return }
        flushJournal(&out)
        let rows = (try? journal.assets(job: s.jobID)) ?? [:]
        var ok: [AssetID] = []
        for st in states {
            guard let row = rows[st.id] else { continue }
            func drop(_ why: String) {
                journalBuffer.append(.state(job: s.jobID, asset: st.id, .dropped, reason: why))
                summary.dropped[why, default: 0] += 1
            }
            if !st.exists { drop("gone"); continue }
            if !st.canDelete { drop("not_deletable"); continue }
            if !st.isLocal { drop("not_local"); continue }
            let fresh = row.verifiedAtMs.map { now.wallMs - $0 <= config.verifyFreshMs } ?? false
            let sameFP = st.fingerprint.map { $0.fingerprint } == row.verifiedFP
            if !sameFP || !fresh {
                if row.reverifyCount == 0 || !fresh {
                    // Changed during the move (or VERIFY went stale): re-manifest and verify once more.
                    journalBuffer.append(.reverify(job: s.jobID, asset: st.id))
                    reverifyIDs.append(st.id)
                } else {
                    drop("changed_during_move")
                }
                continue
            }
            ok.append(st.id)
        }
        guard !ok.isEmpty else { return afterDeletes(&out) }
        let batch = UUID(uuid: uuidBytes())
        journalBuffer.append(.deleteBatch(job: s.jobID, batch: batch, assets: ok, atMs: now.wallMs))
        flushJournal(&out)
        pendingDelete = (batch, ok)
        out.append(.performDelete(batchID: batch, ok))
    }

    private func uuidBytes() -> uuid_t {
        let b = random.bytes(16)
        return (b[0], b[1], b[2], b[3], b[4], b[5], b[6] & 0x0F | 0x40, b[7], b[8] & 0x3F | 0x80, b[9], b[10], b[11], b[12],
                b[13], b[14], b[15])
    }

    private func deleteFinished(_ batch: UUID, _ outcome: DeleteOutcome, _ out: inout [Action]) {
        guard let s = spec, let p = pendingDelete, p.batch == batch else { return }
        pendingDelete = nil
        switch outcome {
        case .success:
            for id in p.ids { journalBuffer.append(.state(job: s.jobID, asset: id, .deleted, reason: nil)) }
            journalBuffer.append(.batchState(batch: batch, "done"))
            summary.deleted += p.ids.count
            // More verified assets than one batch holds?
            startDeletePhase(&out)
        case .userCancelled, .error:
            for id in p.ids { journalBuffer.append(.state(job: s.jobID, asset: id, .declined, reason: nil)) }
            journalBuffer.append(.batchState(batch: batch, "declined"))
            summary.declined += p.ids.count
            declinedIDs = p.ids
            if case let .error(msg) = outcome { out.append(.log(.e, "delete failed: \(msg)")) }
            out.append(.needsUser(.confirmDeleteAgain(count: p.ids.count)))
        }
    }

    private func recoverDeletes(_ states: [AssetCurrentState], _ out: inout [Action]) {
        guard let s = spec, let p = pendingDelete else { return }
        pendingDelete = nil
        let present = Set(states.filter(\.exists).map(\.id))
        for id in p.ids where !present.contains(id) {
            journalBuffer.append(.state(job: s.jobID, asset: id, .deleted, reason: nil))
            summary.deleted += 1
        }
        // Still present: back to acked (createOrResume demoted verified) and verified again later.
        journalBuffer.append(.batchState(batch: p.batch, "declined"))
        phase = .transfer
        if conn == .ready {
            flushJournal(&out)
            let acked = (try? journal.assets(job: s.jobID).filter { $0.value.state == .acked }.keys).map(Set.init) ?? []
            startTransfer(skip: acked, &out)
        }
    }

    private func afterDeletes(_ out: inout [Action]) {
        guard !reverifyIDs.isEmpty else { return finish(&out, sendBye: true) }
        phase = .reverify
        let ids = reverifyIDs
        reverifyIDs = []
        out.append(.describeAssets(ids))
    }

    private func manifestReverify(_ list: [AssetDescriptor], _ out: inout [Action]) {
        guard phase == .reverify else { return }
        guard !list.isEmpty else { return finish(&out, sendBye: true) }
        reManifest = list
        exhausted = true
        phase = .transfer
        sendManifest(list, last: true, &out)
    }
}

extension Array where Element == UInt8 {
    init?(hexBytes s: String) {
        guard s.count % 2 == 0 else { return nil }
        var out = [UInt8]()
        out.reserveCapacity(s.count / 2)
        var it = s.utf8.makeIterator()
        while let a = it.next(), let b = it.next() {
            guard let v = UInt8(String(decoding: [a, b], as: UTF8.self), radix: 16) else { return nil }
            out.append(v)
        }
        self = out
    }
}

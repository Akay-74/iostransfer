// The driver (TRANSFERCORE §10): owns a SenderCore on one serial queue and performs its Actions
// with Network.framework, PhotoKit and the spool. The core itself does no I/O.
import Foundation
import IOSTCore
import IOSTSelection
import UIKit

@MainActor
final class TransferModel: ObservableObject {
    @Published var progress = JobProgress()
    @Published var prompt: UserAction?
    @Published var summary: JobSummary?
    @Published var running = false
    @Published var status = ""
    @Published var pairingDone: PairedPC?
    @Published var pairingError: String?
    var driver: SessionDriver?

    func reply(_ r: UserReply) {
        prompt = nil
        driver?.post { .userReply(r, now: $0) }
    }

    func cancel() {
        driver?.post { .cancelJob(now: $0) }
    }
}

final class SessionDriver {
    enum Purpose {
        case transfer(selection: Selection, section: Section, mode: JobMode)
        case pairing(PairingInfo)
    }

    private let q = DispatchQueue(label: "iostransfer.session", qos: .userInitiated)
    private let purpose: Purpose
    private var core: SenderCore!
    private var transport: Transport!
    private let spool = Spool()
    private var timer: DispatchSourceTimer?
    private weak var model: TransferModel?
    private let hosts: [String]
    private let port: UInt16
    private let pin: [UInt8]
    private let pcID: String?
    private var ids: [AssetID] = []
    private var cursor = 0
    private var lastFreeCheck = Date.distantPast
    private let started = DispatchTime.now().uptimeNanoseconds
    private var bgTask: UIBackgroundTaskIdentifier = .invalid
    private var observers: [NSObjectProtocol] = []

    init?(purpose: Purpose, model: TransferModel) {
        self.purpose = purpose
        self.model = model
        let auth: Credentials.Auth
        switch purpose {
        case .pairing(let info):
            hosts = info.hosts
            port = info.port
            pin = info.pin
            pcID = nil
            auth = .pair(token: info.token)
        case .transfer:
            guard let pc = Store.shared.pc, let secret = Keychain.secret(pcID: pc.pcID) else { return nil }
            hosts = pc.hosts
            port = pc.port
            pin = pc.pin
            pcID = pc.pcID
            auth = .secret(secret)
        }
        let journalPath = spool.root.deletingLastPathComponent().appendingPathComponent("journal.sqlite").path
        guard let journal = try? SQLiteJournal(path: journalPath) else { return nil }
        let creds = Credentials(deviceID: Keychain.deviceID, deviceName: UIDevice.current.name,
                                appVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0",
                                os: "iOS \(UIDevice.current.systemVersion)", auth: auth, expectedPCID: pcID,
                                pcName: Store.shared.pc?.name ?? "PC", firstMoveToPC: !(Store.shared.pc?.movedBefore ?? false))
        core = SenderCore(credentials: creds, journal: journal)
        transport = Transport(queue: q) { [weak self] in self?.signal($0) }
    }

    private var now: Now {
        Now(mono: (DispatchTime.now().uptimeNanoseconds - started) / 1_000_000, wallMs: Int64(Date().timeIntervalSince1970 * 1000))
    }

    // MARK: Lifecycle

    func start() {
        let spec: JobSpec
        switch purpose {
        case let .transfer(sel, section, mode):
            spec = JobSpec(jobID: UUID(), mode: mode, section: section, label: section == .videos ? "Videos" : "Photos",
                           rulesJSON: (try? JSONEncoder().encode(sel)) ?? Data())
        case .pairing:
            spec = JobSpec(jobID: UUID(), mode: .copy, section: .photos, label: "pairing", rulesJSON: Data())
        }
        if let id = pcID { transport.startBrowsing(pcID: id) }
        Task { @MainActor in
            UIApplication.shared.isIdleTimerDisabled = true
            model?.running = true
            if Store.shared.backgroundKeepAlive, case .transfer = purpose { KeepAlive.shared.start() }
        }
        observers.append(NotificationCenter.default.addObserver(forName: ProcessInfo.thermalStateDidChangeNotification, object: nil, queue: nil) { [weak self] _ in
            self?.post { .thermal(Self.thermal(), now: $0) }
        })
        observers.append(NotificationCenter.default.addObserver(forName: UIApplication.willResignActiveNotification, object: nil, queue: .main) { [weak self] _ in
            self?.beginBackgroundTime()
        })
        q.async { [self] in
            handle(.startJob(spec, now: now))
            handle(.thermal(Self.thermal(), now: now))
            let t = DispatchSource.makeTimerSource(queue: q)
            t.schedule(deadline: .now() + 0.25, repeating: 0.25)
            t.setEventHandler { [weak self] in self?.tick() }
            t.resume()
            timer = t
        }
    }

    /// Thread-safe entry for UI and system callbacks.
    func post(_ make: @escaping (Now) -> Event) {
        q.async { [self] in handle(make(now)) }
    }

    private func stop() {
        observers.forEach(NotificationCenter.default.removeObserver)
        observers = []
        timer?.cancel()
        timer = nil
        transport.stopBrowsing()
        transport.cancel()
        Task { @MainActor in
            UIApplication.shared.isIdleTimerDisabled = false
            KeepAlive.shared.stop()
            model?.running = false
        }
        endBackgroundTime()
    }

    private func tick() {
        let n = now
        if Date().timeIntervalSince(lastFreeCheck) > 10 {
            lastFreeCheck = Date()
            handle(.freeSpaceChanged(bytes: spool.freeBytes, now: n))
        }
        handle(.tick(now: n))
    }

    private func beginBackgroundTime() {
        guard bgTask == .invalid else { return }
        bgTask = UIApplication.shared.beginBackgroundTask(withName: "transfer") { [weak self] in self?.endBackgroundTime() }
    }

    private func endBackgroundTime() {
        Task { @MainActor [self] in
            if bgTask != .invalid {
                UIApplication.shared.endBackgroundTask(bgTask)
                bgTask = .invalid
            }
        }
    }

    static func thermal() -> ThermalLevel {
        switch ProcessInfo.processInfo.thermalState {
        case .fair: .fair
        case .serious: .serious
        case .critical: .critical
        default: .nominal
        }
    }

    // MARK: Core plumbing

    private func handle(_ e: Event) {
        dispatchPrecondition(condition: .onQueue(q))
        for a in core.handle(e) { perform(a) }
    }

    private func signal(_ s: Transport.Signal) {
        switch s {
        case .up: handle(.transportUp(isTLS: true, now: now))
        case .received(let b): handle(.received(b, now: now))
        case .sent(let t): handle(.sendCompleted(token: t, now: now))
        case .down(let why): handle(.transportDown(.error(why), now: now))
        }
    }

    private func ui(_ f: @escaping @MainActor (TransferModel) -> Void) {
        Task { @MainActor [weak model] in if let model { f(model) } }
    }

    private func perform(_ a: Action) {
        switch a {
        case .connect:
            transport.connect(hosts: hosts, port: port, pin: pin)
        case let .send(bytes, token):
            transport.send(bytes, token: token)
        case let .closeTransport(after):
            transport.close(after: after)
        case let .storeSecret(secret, pcID, pcName):
            guard case let .pairing(info) = purpose else { return }
            guard Keychain.setSecret(secret, pcID: pcID) else {
                return ui { $0.pairingError = "Couldn't save the pairing in the Keychain." }
            }
            handle(.secretStored(now: now))
            // PAIRED is sent: pairing is complete. The PC's `pair` command exits now.
            let pc = PairedPC(pcID: pcID, name: pcName, hosts: info.hosts, port: info.receivePort, pin: info.pin)
            handle(.cancelJob(now: now))
            stop()
            ui { $0.pairingDone = pc }
        case let .beginAssetSource(skip):
            resolveSelection(skip: skip)
        case let .loadAssets(max):
            let page = Array(ids[cursor..<min(cursor + max, ids.count)])
            cursor += page.count
            let found = PhotoLibrary.assets(page)
            let descriptors = page.compactMap { found[$0].map(PhotoLibrary.descriptor) }
            handle(.assetsLoaded(descriptors, exhausted: cursor >= ids.count, now: now))
        case let .describeAssets(list):
            let found = PhotoLibrary.assets(list)
            handle(.assetsDescribed(list.compactMap { found[$0].map(PhotoLibrary.descriptor) }, now: now))
        case let .export(id, res, ref):
            PhotoLibrary.export(id, key: res.key, to: spool.url(ref)) { [weak self] result in
                self?.post { n in
                    switch result {
                    case .success(let size): .exported(ref, size: size, now: n)
                    case .failure(let why): .exportFailed(ref, why, now: n)
                    }
                }
            }
        case let .read(ref, offset, length, token):
            if let data = spool.read(ref, offset: offset, length: length) {
                handle(.readDone(token: token, data, now: now))
            } else {
                handle(.readFailed(token: token, now: now))
            }
        case let .deleteSpool(jobID, dir):
            spool.delete(jobID: jobID, assetDir: dir)
        case let .sweepSpool(keepJob, drop):
            spool.sweep(keepJob: keepJob, drop: drop)
        case let .inspectAssets(list, want):
            let scratch = spool.root
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                PhotoLibrary.inspect(list, wantFingerprint: want, scratch: scratch) { states in
                    self?.post { .currentState(states, now: $0) }
                }
            }
        case let .performDelete(batch, list):
            PhotoLibrary.delete(list) { [weak self] outcome in
                self?.post { .deleteFinished(batchID: batch, outcome, now: $0) }
            }
        case let .progress(p):
            ui { $0.progress = p }
        case let .log(level, msg):
            if level == .e || level == .w { ui { $0.status = msg } }
        case let .needsUser(u):
            if case .confirmFirstMove = u {} else if case .confirmDeleteAgain = u {} else { stop() }
            ui { $0.prompt = u }
        case let .jobFinished(summary):
            if case .transfer(_, _, .move) = purpose, summary.deleted > 0, var pc = Store.shared.pc {
                pc.movedBefore = true
                Store.shared.pc = pc
            }
            stop()
            ui { $0.summary = summary }
        }
    }

    /// Selection rules → ordered, de-duplicated asset IDs (ARCHITECTURE §2.3).
    private func resolveSelection(skip: Set<AssetID>) {
        cursor = 0
        ids = []
        guard case let .transfer(sel, section, _) = purpose else { return }
        var seen = skip
        for c in sel.collections {
            let idx = FetchIndex(PhotoLibrary.fetch(c, section))
            for id in sel.resolve(in: c, idx) where seen.insert(id).inserted {
                ids.append(id)
            }
        }
    }
}

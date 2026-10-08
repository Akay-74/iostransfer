// InteropSender: SenderCore driven by POSIX sockets and a folder "library", for end-to-end tests
// against the real Rust receiver (`iostransfer receive --insecure-dev`). TRANSFERCORE §9.4.
import Foundation
import IOSTCore
#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif

// MARK: Arguments

struct Args {
    var host = "127.0.0.1"
    var port: UInt16 = 0
    var deviceID = UUID()
    var secret: [UInt8] = []
    var folder = ""
    var spool = ""
    var journal = ""
    var mode = JobMode.copy
    var jobID = UUID()
    var deleteForReal = false
    var yes = false
    var timeoutS = 120.0
}

func parseArgs() -> Args {
    var a = Args()
    var it = CommandLine.arguments.dropFirst().makeIterator()
    while let k = it.next() {
        let v = { it.next() ?? { fatalError("missing value for \(k)") }() }
        switch k {
        case "--host": a.host = v()
        case "--port": a.port = UInt16(v())!
        case "--device":
            let parts = v().split(separator: ":")
            a.deviceID = UUID(uuidString: String(parts[0]))!
            a.secret = stride(from: 0, to: parts[1].count, by: 2).map {
                let s = parts[1].index(parts[1].startIndex, offsetBy: $0)
                return UInt8(parts[1][s..<parts[1].index(s, offsetBy: 2)], radix: 16)!
            }
        case "--folder": a.folder = v()
        case "--spool": a.spool = v()
        case "--journal": a.journal = v()
        case "--mode": a.mode = JobMode(rawValue: v())!
        case "--job": a.jobID = UUID(uuidString: v())!
        case "--delete-for-real": a.deleteForReal = true
        case "--yes": a.yes = true
        case "--timeout": a.timeoutS = Double(v())!
        default: fatalError("unknown argument \(k)")
        }
    }
    return a
}

// MARK: Folder library

func uti(_ ext: String) -> String {
    switch ext.lowercased() {
    case "heic": "public.heic"
    case "jpg", "jpeg": "public.jpeg"
    case "png": "public.png"
    case "dng": "com.adobe.raw-image"
    case "mov": "com.apple.quicktime-movie"
    case "mp4": "public.mpeg-4"
    case "aae": "com.apple.photos.adjustment"
    default: "public.data"
    }
}

/// Files grouped into assets by stem: `X.HEIC` + `X.MOV` is a Live Photo; a lone `.MOV` is a video.
func scan(_ folder: String, only: Set<AssetID>? = nil) -> [AssetDescriptor] {
    let fm = FileManager.default
    let files = (fm.enumerator(atPath: folder)?.allObjects as? [String] ?? [])
        .filter { var d: ObjCBool = false; return fm.fileExists(atPath: folder + "/" + $0, isDirectory: &d) && !d.boolValue }
        .sorted()
    var groups: [String: [String]] = [:]
    for f in files { groups[(f as NSString).deletingPathExtension, default: []].append(f) }
    return groups.keys.sorted().compactMap { stem -> AssetDescriptor? in
        guard only == nil || only!.contains(stem) else { return nil }
        let members = groups[stem]!.sorted()
        let stills = members.filter { !["mov", "mp4"].contains(($0 as NSString).pathExtension.lowercased()) }
        let isVideo = stills.isEmpty
        var resources: [ResourceDescriptor] = []
        var mtime: Int64 = 0
        for f in members {
            let ext = (f as NSString).pathExtension
            let attrs = try? fm.attributesOfItem(atPath: folder + "/" + f)
            let size = (attrs?[.size] as? NSNumber)?.uint64Value
            mtime = max(mtime, Int64(((attrs?[.modificationDate] as? Date) ?? Date()).timeIntervalSince1970 * 1000))
            let movie = ["mov", "mp4"].contains(ext.lowercased())
            let type = isVideo ? "video" : (movie ? "paired_video" : (ext.lowercased() == "aae" ? "adjustment_data" : "photo"))
            let n = resources.filter { $0.type == type }.count
            resources.append(ResourceDescriptor(key: "\(type)#\(n)", type: type, uti: uti(ext),
                                                name: (f as NSString).lastPathComponent, sizeHint: size))
        }
        let meta = AssetMeta(createdMs: mtime, tzMin: 0, fav: false, loc: nil)
        return AssetDescriptor(id: stem, kind: isVideo ? .videos : .photos, meta: meta, modifiedMs: mtime, w: 1, h: 1,
                               durMs: nil, burstID: nil, subtypes: [], resources: resources)
    }
}

func filePath(_ args: Args, _ desc: AssetDescriptor, _ key: ResKey) -> String? {
    guard let r = desc.resources.first(where: { $0.key == key }) else { return nil }
    let dir = (desc.id as NSString).deletingLastPathComponent
    return args.folder + "/" + (dir.isEmpty ? r.name : dir + "/" + r.name)
}

// MARK: Socket

final class Socket {
    var fd: Int32 = -1

    func connect(host: String, port: UInt16) -> Bool {
        fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        inet_pton(AF_INET, host, &addr.sin_addr)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Glibc.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        if rc != 0 { close(); return false }
        var one: Int32 = 1
        setsockopt(fd, Int32(IPPROTO_TCP), TCP_NODELAY, &one, socklen_t(MemoryLayout<Int32>.size))
        return true
    }

    func write(_ bytes: [UInt8]) -> Bool {
        var off = 0
        while off < bytes.count {
            let n = bytes[off...].withUnsafeBytes { Glibc.send(fd, $0.baseAddress, $0.count, Int32(MSG_NOSIGNAL)) }
            if n <= 0 { return false }
            off += n
        }
        return true
    }

    /// nil = nothing within the timeout; [] = closed.
    func read(timeoutMs: Int32) -> [UInt8]? {
        var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        guard poll(&p, 1, timeoutMs) > 0 else { return nil }
        var buf = [UInt8](repeating: 0, count: 256 * 1024)
        let n = recv(fd, &buf, buf.count, 0)
        return n <= 0 ? [] : Array(buf[..<n])
    }

    func close() {
        if fd >= 0 { Glibc.close(fd) }
        fd = -1
    }

    var isOpen: Bool { fd >= 0 }
}

// MARK: Driver

let args = parseArgs()
let start = DispatchTime.now().uptimeNanoseconds
func now() -> Now {
    Now(mono: (DispatchTime.now().uptimeNanoseconds - start) / 1_000_000, wallMs: Int64(Date().timeIntervalSince1970 * 1000))
}
func log(_ s: String) {
    FileHandle.standardError.write(Data("[sender] \(s)\n".utf8))
}

let creds = Credentials(deviceID: args.deviceID, deviceName: "Interop iPhone", appVersion: "interop", os: "Linux",
                        auth: .secret(args.secret), expectedPCID: nil, pcName: "interop-pc", firstMoveToPC: false)
let journal: JournalStore = args.journal.isEmpty ? InMemoryJournal() : try! SQLiteJournal(path: args.journal)
let core = SenderCore(credentials: creds, journal: journal)
let sock = Socket()
let fm = FileManager.default
var queue: [Event] = []
var source: [AssetDescriptor] = []
var sourcePos = 0
var allAssets: [AssetID: AssetDescriptor] = [:]
var finished: JobSummary?
var exitCode: Int32 = 0

func spoolPath(_ ref: SpoolRef) -> String {
    "\(args.spool)/\(ref.jobID.uuidString)/\(ref.assetDir)/\(ref.key.replacingOccurrences(of: "#", with: "_"))"
}

func perform(_ a: Action) {
    switch a {
    case let .connect(attempt):
        log("connect attempt \(attempt)")
        if sock.connect(host: args.host, port: args.port) {
            queue.append(.transportUp(isTLS: false, now: now()))
        } else {
            queue.append(.transportDown(.error("connect failed"), now: now()))
        }
    case let .send(bytes, token):
        if sock.isOpen, sock.write(bytes) {
            queue.append(.sendCompleted(token: token, now: now()))
        } else if sock.isOpen {
            sock.close()
            queue.append(.transportDown(.error("write failed"), now: now()))
        }
    case let .closeTransport(after):
        if let after, sock.isOpen { _ = sock.write(after) }
        sock.close()
    case .storeSecret:
        queue.append(.secretStored(now: now()))
    case let .beginAssetSource(skip):
        source = scan(args.folder).filter { !skip.contains($0.id) }
        for d in source { allAssets[d.id] = d }
        sourcePos = 0
    case let .loadAssets(max):
        let page = Array(source[sourcePos..<min(sourcePos + max, source.count)])
        sourcePos += page.count
        queue.append(.assetsLoaded(page, exhausted: sourcePos >= source.count, now: now()))
    case let .describeAssets(ids):
        let found = scan(args.folder, only: Set(ids))
        for d in found { allAssets[d.id] = d }
        queue.append(.assetsDescribed(found, now: now()))
    case let .export(id, res, ref):
        guard let desc = allAssets[id], let src = filePath(args, desc, res.key), fm.fileExists(atPath: src) else {
            queue.append(.exportFailed(ref, .assetGone, now: now()))
            return
        }
        let dst = spoolPath(ref)
        try? fm.createDirectory(atPath: (dst as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try? fm.removeItem(atPath: dst + ".tmp")
        do {
            if !fm.fileExists(atPath: dst) {
                try fm.copyItem(atPath: src, toPath: dst + ".tmp")
                try fm.moveItem(atPath: dst + ".tmp", toPath: dst)
            }
            let size = (try fm.attributesOfItem(atPath: dst)[.size] as? NSNumber)?.uint64Value ?? 0
            queue.append(.exported(ref, size: size, now: now()))
        } catch {
            queue.append(.exportFailed(ref, .readError, now: now()))
        }
    case let .read(ref, offset, length, token):
        guard let h = FileHandle(forReadingAtPath: spoolPath(ref)) else {
            queue.append(.readFailed(token: token, now: now()))
            return
        }
        h.seek(toFileOffset: offset)
        let data = h.readData(ofLength: length)
        h.closeFile()
        queue.append(.readDone(token: token, Array(data), now: now()))
    case let .deleteSpool(jobID, dir):
        try? fm.removeItem(atPath: "\(args.spool)/\(jobID.uuidString)" + (dir.map { "/" + $0 } ?? ""))
    case let .sweepSpool(keepJob, drop):
        let root = args.spool
        for job in (try? fm.contentsOfDirectory(atPath: root)) ?? [] where job != keepJob.uuidString {
            try? fm.removeItem(atPath: root + "/" + job)
        }
        for d in drop { try? fm.removeItem(atPath: "\(root)/\(keepJob.uuidString)/\(d)") }
    case let .inspectAssets(ids, want):
        let current = Dictionary(scan(args.folder, only: Set(ids)).map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        let states = ids.map { id -> AssetCurrentState in
            guard let d = current[id] else {
                return AssetCurrentState(id: id, exists: false, canDelete: false, isLocal: false, modifiedMs: 0, fingerprint: nil)
            }
            var fp: FingerprintInput?
            if want.contains(id) {
                var adj: [String: [UInt8]] = [:]
                for r in d.resources where r.type == "adjustment_data" {
                    adj[r.key] = (filePath(args, d, r.key)).flatMap { fm.contents(atPath: $0) }.map { IOSTCrypto.sha256($0) }
                }
                fp = FingerprintInput(createdMs: d.meta.createdMs, fav: d.meta.fav, loc: nil,
                                      resources: d.resources.map { (key: $0.key, size: $0.sizeHint ?? 0) },
                                      adjustmentSHA256: adj)
            }
            return AssetCurrentState(id: id, exists: true, canDelete: true, isLocal: true, modifiedMs: d.modifiedMs, fingerprint: fp)
        }
        queue.append(.currentState(states, now: now()))
    case let .performDelete(batch, ids):
        for id in ids {
            guard let d = allAssets[id] ?? scan(args.folder, only: [id]).first else { continue }
            for r in d.resources {
                guard let p = filePath(args, d, r.key) else { continue }
                if args.deleteForReal { try? fm.removeItem(atPath: p) } else { log("would delete \(p)") }
            }
        }
        queue.append(.deleteFinished(batchID: batch, .success, now: now()))
    case .progress:
        break
    case let .log(level, msg):
        log("\(level.rawValue) \(msg)")
    case let .needsUser(what):
        switch what {
        case .confirmFirstMove where args.yes:
            queue.append(.userReply(.confirmFirstMove(true), now: now()))
        default:
            log("needs user: \(what)")
            exitCode = 3
            finished = JobSummary()
        }
    case let .jobFinished(summary):
        finished = summary
    }
}

let spec = JobSpec(jobID: args.jobID, mode: args.mode, section: .photos, label: "interop", rulesJSON: Data("[]".utf8))
queue.append(.startJob(spec, now: now()))
var lastTick: UInt64 = 0
let deadline = DispatchTime.now().uptimeNanoseconds + UInt64(args.timeoutS * 1e9)
while finished == nil {
    if DispatchTime.now().uptimeNanoseconds > deadline {
        log("timed out")
        exitCode = 4
        break
    }
    while !queue.isEmpty {
        let ev = queue.removeFirst()
        for a in core.handle(ev) { perform(a) }
    }
    if finished != nil { break }
    if sock.isOpen, let bytes = sock.read(timeoutMs: 50) {
        if bytes.isEmpty {
            sock.close()
            queue.append(.transportDown(.closed, now: now()))
        } else {
            queue.append(.received(bytes, now: now()))
        }
    } else if !sock.isOpen {
        usleep(50_000)
    }
    let n = now()
    if n.mono - lastTick >= 200 {
        lastTick = n.mono
        queue.append(.tick(now: n))
    }
}
sock.close()
if let s = finished, exitCode == 0 {
    print("{\"copied\":\(s.copied),\"already\":\(s.alreadyOnPC),\"failed\":\(s.failed.values.reduce(0, +)),\"deleted\":\(s.deleted),\"bytes\":\(s.bytes)}")
}
exit(exitCode)

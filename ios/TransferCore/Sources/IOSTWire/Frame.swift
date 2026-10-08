// Framing (PROTOCOL §2): `u32 BE len | u8 type | payload`, len = 1 + payload length.

public enum Wire {
    /// PROTOCOL §1.2: sent by both sides right after the transport is ready.
    public static let preface: [UInt8] = Array("IOST".utf8) + [1, 0, 0, 0]
    /// PROTOCOL §2: 1 MiB + 16.
    public static let maxFrameLen = 1_048_592
    /// PROTOCOL §2: max bytes carried by one DATA frame.
    public static let maxChunk = 262_144
}

public enum FrameType: UInt8, Sendable {
    case hello = 0x01, welcome = 0x02, challenge = 0x03, auth = 0x04, paired = 0x05
    case manifest = 0x10, need = 0x11, needMore = 0x12
    case resBegin = 0x20, data = 0x21, resEnd = 0x22, resAbort = 0x23, assetEnd = 0x24
    case ack = 0x30, resNack = 0x31
    case verify = 0x40, verified = 0x41
    case pause = 0x50, resume = 0x51
    case log = 0x60
    case ping = 0x70, pong = 0x71
    case bye = 0x7F
}

public enum WireError: Error, Equatable, Sendable {
    case badLength(Int)
    case unknownType(UInt8)
    /// DATA payload too short, or chunk empty/oversized.
    case badData
    case badJSON(String)
}

public struct Frame: Equatable, Sendable {
    public var type: FrameType
    public var payload: [UInt8]

    public init(type: FrameType, payload: [UInt8]) {
        self.type = type
        self.payload = payload
    }

    /// Wire bytes of this frame.
    public func encoded() throws -> [UInt8] {
        let len = 1 + payload.count
        guard len <= Wire.maxFrameLen else { throw WireError.badLength(len) }
        var out = [UInt8]()
        out.reserveCapacity(4 + len)
        out.append(contentsOf: UInt32(len).bigEndianBytes)
        out.append(type.rawValue)
        out.append(contentsOf: payload)
        return out
    }
}

public struct DataChunk: Equatable, Sendable {
    public var slot: UInt16
    public var offset: UInt64
    public var bytes: [UInt8]

    public init(slot: UInt16, offset: UInt64, bytes: [UInt8]) {
        self.slot = slot
        self.offset = offset
        self.bytes = bytes
    }

    public init(frame: Frame) throws {
        guard frame.type == .data, frame.payload.count >= 11 else { throw WireError.badData }
        let p = frame.payload
        slot = UInt16(p[0]) << 8 | UInt16(p[1])
        offset = p[2..<10].reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        bytes = Array(p[10...])
        guard bytes.count <= Wire.maxChunk else { throw WireError.badData }
    }

    public var frame: Frame {
        var p = [UInt8]()
        p.reserveCapacity(10 + bytes.count)
        p.append(contentsOf: slot.bigEndianBytes)
        p.append(contentsOf: offset.bigEndianBytes)
        p.append(contentsOf: bytes)
        return Frame(type: .data, payload: p)
    }
}

/// Incremental frame decoder. Not reusable after it throws: the connection must be closed.
public struct FrameDecoder: Sendable {
    private var buf: [UInt8] = []
    private var head = 0

    public init() {}

    public var buffered: Int { buf.count - head }

    public mutating func append<C: Collection>(_ bytes: C) where C.Element == UInt8 {
        if head > 0 && head * 2 >= buf.count {
            buf.removeFirst(head)
            head = 0
        }
        buf.append(contentsOf: bytes)
    }

    /// The next complete frame, or nil if more bytes are needed.
    public mutating func next() throws -> Frame? {
        guard buffered >= 4 else { return nil }
        let len = buf[head..<head + 4].reduce(0) { $0 << 8 | Int($1) }
        // Checked from the header alone, before buffering any payload.
        guard len >= 1, len <= Wire.maxFrameLen else { throw WireError.badLength(len) }
        guard buffered >= 5 else { return nil }
        guard let type = FrameType(rawValue: buf[head + 4]) else { throw WireError.unknownType(buf[head + 4]) }
        guard buffered >= 4 + len else { return nil }
        let payload = Array(buf[head + 5..<head + 4 + len])
        head += 4 + len
        return Frame(type: type, payload: payload)
    }
}

public enum PrefaceCheck: Equatable, Sendable {
    case needMore, ok, bad
}

public func checkPreface<C: Collection>(_ bytes: C) -> PrefaceCheck where C.Element == UInt8 {
    guard bytes.count >= Wire.preface.count else { return .needMore }
    return bytes.prefix(Wire.preface.count).elementsEqual(Wire.preface) ? .ok : .bad
}

extension FixedWidthInteger {
    var bigEndianBytes: [UInt8] {
        withUnsafeBytes(of: self.bigEndian) { Array($0) }
    }
}

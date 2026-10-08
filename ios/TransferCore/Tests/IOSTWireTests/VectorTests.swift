// Shared vectors from testdata/protocol-vectors.json (the Rust receiver loads the same file).
import Foundation
import Testing
@testable import IOSTWire

private let vectors: [String: Any] = {
    let url = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("testdata/protocol-vectors.json")
    let data = try! Data(contentsOf: url)
    return try! JSONSerialization.jsonObject(with: data) as! [String: Any]
}()

private func unhex(_ s: String) -> [UInt8] {
    var out = [UInt8]()
    var it = s.utf8.makeIterator()
    while let a = it.next(), let b = it.next() {
        out.append(UInt8(String(decoding: [a, b], as: UTF8.self), radix: 16)!)
    }
    return out
}

private func list(_ key: String) -> [[String: Any]] {
    vectors[key] as! [[String: Any]]
}

private func int(_ v: Any?) -> Int {
    (v as! NSNumber).intValue
}

@Test func constants() {
    let c = vectors["constants"] as! [String: Any]
    #expect(int(c["max_frame_len"]) == Wire.maxFrameLen)
    #expect(int(c["max_chunk"]) == Wire.maxChunk)
    #expect(unhex(c["preface_hex"] as! String) == Wire.preface)
}

@Test func frames() throws {
    for v in list("frames") {
        let name = v["name"] as! String
        let wire = unhex(v["hex"] as! String)
        var d = FrameDecoder()
        d.append(wire)
        let f = try #require(try d.next(), "\(name)")
        #expect(d.buffered == 0, "\(name)")
        #expect(Int(f.type.rawValue) == int(v["type"]), "\(name)")
        if v["kind"] as! String == "data" {
            let chunk = DataChunk(slot: UInt16(int(v["slot"])), offset: (v["offset"] as! NSNumber).uint64Value,
                                  bytes: unhex(v["bytes_hex"] as! String))
            #expect(try DataChunk(frame: f) == chunk, "\(name)")
            #expect(try chunk.frame.encoded() == wire, "\(name): DATA encoding is byte-exact")
        } else {
            let expected = try JSONSerialization.jsonObject(with: Data((v["json_text"] as! String).utf8)) as! NSDictionary
            try ControlJSON.validate(f.payload)
            let got = try JSONSerialization.jsonObject(with: Data(f.payload)) as! NSDictionary
            #expect(got == expected, "\(name)")
        }
    }
}

@Test func streams() throws {
    for s in list("streams") {
        var wire = unhex(s["hex"] as! String)
        if checkPreface(wire) == .ok { wire.removeFirst(Wire.preface.count) }
        var d = FrameDecoder()
        var types = [Int]()
        for b in wire {
            d.append([b])
            while let f = try d.next() { types.append(Int(f.type.rawValue)) }
        }
        #expect(types == (s["expect_types"] as! [NSNumber]).map(\.intValue), "\(s["name"]!)")
    }
}

private func genInput(_ g: [String: Any]) -> [UInt8] {
    let type = UInt8(int(g["type"]))
    var out = UInt32(int(g["header_len"])).bigEndianBytes + [type]
    if type == FrameType.data.rawValue {
        out += UInt16(int(g["slot"])).bigEndianBytes + UInt64(int(g["offset"])).bigEndianBytes
    }
    out += [UInt8](repeating: unhex(g["payload_fill"] as! String)[0], count: int(g["payload_len"]))
    return out
}

private func result(stage: String, input: [UInt8]) -> String {
    if stage == "preface" {
        switch checkPreface(input) {
        case .needMore: return "need_more"
        case .ok: return "ok"
        case .bad: return "bad_preface"
        }
    }
    var d = FrameDecoder()
    d.append(input)
    let frame: Frame
    do {
        guard let f = try d.next() else { return "need_more" }
        frame = f
    } catch WireError.badLength { return "bad_length" }
    catch WireError.unknownType { return "unknown_type" }
    catch { return "other" }
    switch stage {
    case "data": return (try? DataChunk(frame: frame)) == nil ? "bad_data" : "ok"
    case "message": return (try? ControlJSON.validate(frame.payload)) == nil ? "bad_json" : "ok"
    default: return "ok"
    }
}

@Test func decodeErrors() {
    for v in list("decode_errors") {
        let input = (v["gen"] as? [String: Any]).map(genInput) ?? unhex(v["input"] as! String)
        #expect(result(stage: v["stage"] as! String, input: input) == v["expect"] as! String, "\(v["name"]!)")
    }
}

@Test func encodedRoundTrip() throws {
    let f = Frame(type: .ping, payload: Array(#"{"n":1}"#.utf8))
    #expect(try f.encoded() == unhex("00000008707b226e223a317d"))
    #expect(throws: WireError.badLength(Wire.maxFrameLen + 1)) {
        try Frame(type: .log, payload: [UInt8](repeating: 0, count: Wire.maxFrameLen)).encoded()
    }
}

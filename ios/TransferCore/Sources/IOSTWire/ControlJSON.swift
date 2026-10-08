// Control frame payloads: one UTF-8 JSON object, no BOM (PROTOCOL §2).
import Foundation

public enum ControlJSON {
    /// Strict decode. Foundation's JSONDecoder is lenient about a BOM and invalid UTF-8, so both
    /// are rejected first (vectors `control_bom`, `control_invalid_utf8`).
    public static func decode<T: Decodable>(_ type: T.Type, from payload: [UInt8]) throws -> T {
        try validate(payload)
        do {
            return try JSONDecoder().decode(T.self, from: Data(payload))
        } catch {
            throw WireError.badJSON("\(error)")
        }
    }

    /// Rejects anything that isn't a BOM-free, valid UTF-8 JSON object.
    public static func validate(_ payload: [UInt8]) throws {
        if payload.starts(with: [0xEF, 0xBB, 0xBF]) {
            throw WireError.badJSON("BOM")
        }
        // Valid UTF-8 survives a decode/encode round trip unchanged; invalid sequences become U+FFFD.
        guard Array(String(decoding: payload, as: UTF8.self).utf8) == payload else {
            throw WireError.badJSON("invalid UTF-8")
        }
        guard let first = payload.first(where: { ![0x20, 0x09, 0x0A, 0x0D].contains($0) }), first == UInt8(ascii: "{"),
              (try? JSONSerialization.jsonObject(with: Data(payload))) is [String: Any]
        else {
            throw WireError.badJSON("not a JSON object")
        }
    }

    public static func encode<T: Encodable>(_ value: T) throws -> [UInt8] {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return Array(try enc.encode(value))
    }

    public static func frame<T: Encodable>(_ type: FrameType, _ value: T) throws -> Frame {
        Frame(type: type, payload: try encode(value))
    }
}

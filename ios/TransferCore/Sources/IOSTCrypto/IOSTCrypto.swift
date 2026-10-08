// Hashing, HMAC proofs, SPKI pin, pairing code and the move fingerprint (PROTOCOL §1.1, §4, §6.4).
import Crypto
import Foundation

public enum IOSTCrypto {
    public static func sha256<D: DataProtocol>(_ data: D) -> [UInt8] {
        Array(SHA256.hash(data: data))
    }

    // MARK: HMAC challenge/response (PROTOCOL §4.2)

    /// Receiver (PC) proof: the phone checks it to authenticate the PC.
    public static func rProof(secret: [UInt8], sNonce: [UInt8], rNonce: [UInt8]) -> [UInt8] {
        proof(label: "IOST1-R", secret: secret, sNonce: sNonce, rNonce: rNonce)
    }

    /// Sender (phone) proof, sent in AUTH.
    public static func sProof(secret: [UInt8], sNonce: [UInt8], rNonce: [UInt8]) -> [UInt8] {
        proof(label: "IOST1-S", secret: secret, sNonce: sNonce, rNonce: rNonce)
    }

    private static func proof(label: String, secret: [UInt8], sNonce: [UInt8], rNonce: [UInt8]) -> [UInt8] {
        var mac = HMAC<SHA256>(key: SymmetricKey(data: secret))
        mac.update(data: Array(label.utf8))
        mac.update(data: sNonce)
        mac.update(data: rNonce)
        return Array(mac.finalize())
    }

    /// Constant-time equality for proofs and pins.
    public static func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        return zip(a, b).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }

    // MARK: SPKI pin (PROTOCOL §1.1)

    /// DER prefix of every P-256 SubjectPublicKeyInfo; the 65-byte uncompressed point follows.
    public static let p256SPKIPrefix: [UInt8] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ]

    /// Pin from the 65-byte point `SecKeyCopyExternalRepresentation` returns. Anything else fails
    /// closed (nil).
    public static func spkiPin(p256Point point: [UInt8]) -> [UInt8]? {
        guard point.count == 65, point.first == 0x04 else { return nil }
        return sha256(p256SPKIPrefix + point)
    }

    /// The QR `spki` parameter: base64url without padding (PROTOCOL Δ19).
    public static func base64url(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func fromBase64url(_ s: String) -> [UInt8]? {
        var b64 = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        b64 += String(repeating: "=", count: (4 - b64.count % 4) % 4)
        return Data(base64Encoded: b64).map(Array.init)
    }

    /// First 40 bits of the pin in Crockford base32, `XXXX-XXXX` (THREAT_MODEL N11).
    public static func pairingCode(pin: [UInt8]) -> String {
        let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        let bits = pin.prefix(5).reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        let chars = (0..<8).reversed().map { alphabet[Int((bits >> (UInt64($0) * 5)) & 31)] }
        return String(chars[0..<4]) + "-" + String(chars[4..<8])
    }
}

// MARK: Move fingerprint (PROTOCOL §6.4, phone-local)

public struct FingerprintLocation: Equatable, Sendable {
    public var lat: Double
    public var lon: Double
    public var alt: Double?

    public init(lat: Double, lon: Double, alt: Double? = nil) {
        self.lat = lat
        self.lon = lon
        self.alt = alt
    }
}

public struct FingerprintInput: Equatable, Sendable {
    public var createdMs: Int64
    public var fav: Bool
    public var loc: FingerprintLocation?
    /// (key, size), any order.
    public var resources: [(key: String, size: UInt64)]
    /// sha256 for every adjustment_data key.
    public var adjustmentSHA256: [String: [UInt8]]

    public init(createdMs: Int64, fav: Bool, loc: FingerprintLocation?, resources: [(key: String, size: UInt64)],
                adjustmentSHA256: [String: [UInt8]]) {
        self.createdMs = createdMs
        self.fav = fav
        self.loc = loc
        self.resources = resources
        self.adjustmentSHA256 = adjustmentSHA256
    }

    public static func == (a: Self, b: Self) -> Bool {
        a.canonical == b.canonical
    }

    /// The exact bytes that get hashed.
    public var canonical: String {
        func fixed(_ v: Double, _ digits: Int) -> String {
            String(format: "%.\(digits)f", locale: Locale(identifier: "en_US_POSIX"), v)
        }
        let lat = loc.map { fixed($0.lat, 7) } ?? "-"
        let lon = loc.map { fixed($0.lon, 7) } ?? "-"
        let alt = loc?.alt.map { fixed($0, 2) } ?? "-"
        var s = "meta\t\(createdMs)\t\(fav ? 1 : 0)\t\(lat)\t\(lon)\t\(alt)\n"
        for r in resources.sorted(by: { Array($0.key.utf8).lexicographicallyPrecedes(Array($1.key.utf8)) }) {
            let h = adjustmentSHA256[r.key].map { $0.map { String(format: "%02x", $0) }.joined() } ?? "-"
            s += "\(r.key)\t\(r.size)\t\(h)\n"
        }
        return s
    }

    public var fingerprint: [UInt8] {
        IOSTCrypto.sha256(Array(canonical.utf8))
    }
}

/// Incremental SHA-256 (copyable value).
public struct SHA256Stream: Sendable {
    private var h = SHA256()

    public init() {}

    public mutating func update<D: DataProtocol>(_ data: D) {
        h.update(data: data)
    }

    public func finalize() -> [UInt8] {
        Array(h.finalize())
    }
}

public extension Array where Element == UInt8 {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}

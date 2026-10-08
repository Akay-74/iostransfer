// hmac, spki, pairing_code and fingerprint vectors from testdata/protocol-vectors.json.
import Foundation
import Testing
@testable import IOSTCrypto

private let vectors: [String: Any] = {
    let url = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("testdata/protocol-vectors.json")
    return try! JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
}()

private func unhex(_ s: String) -> [UInt8] {
    var out = [UInt8]()
    var it = s.utf8.makeIterator()
    while let a = it.next(), let b = it.next() {
        out.append(UInt8(String(decoding: [a, b], as: UTF8.self), radix: 16)!)
    }
    return out
}

private func hex(_ b: [UInt8]) -> String {
    b.map { String(format: "%02x", $0) }.joined()
}

private func list(_ key: String) -> [[String: Any]] {
    vectors[key] as! [[String: Any]]
}

@Test func hmacProofs() {
    for v in list("hmac") {
        let (sec, s, r) = (unhex(v["secret"] as! String), unhex(v["s_nonce"] as! String), unhex(v["r_nonce"] as! String))
        #expect(hex(IOSTCrypto.rProof(secret: sec, sNonce: s, rNonce: r)) == v["r_proof"] as! String)
        #expect(hex(IOSTCrypto.sProof(secret: sec, sNonce: s, rNonce: r)) == v["s_proof"] as! String)
    }
    #expect(IOSTCrypto.constantTimeEqual([1, 2], [1, 2]))
    #expect(!IOSTCrypto.constantTimeEqual([1, 2], [1, 3]))
    #expect(!IOSTCrypto.constantTimeEqual([1], [1, 2]))
}

@Test func spkiPin() throws {
    for v in list("spki") {
        let point = unhex(v["point_hex"] as! String)
        #expect(hex(IOSTCrypto.p256SPKIPrefix + point) == v["spki_der_hex"] as! String)
        let pin = try #require(IOSTCrypto.spkiPin(p256Point: point))
        #expect(hex(pin) == v["pin_sha256_hex"] as! String)
        #expect(IOSTCrypto.base64url(pin) == v["pin_b64url_nopad"] as! String)
        #expect(IOSTCrypto.fromBase64url(v["pin_b64url_nopad"] as! String) == pin)
        #expect(IOSTCrypto.pairingCode(pin: pin) == v["pairing_code"] as! String)
    }
    #expect(IOSTCrypto.spkiPin(p256Point: [0x04] + [UInt8](repeating: 1, count: 63)) == nil, "wrong length fails closed")
    #expect(IOSTCrypto.spkiPin(p256Point: [0x02] + [UInt8](repeating: 1, count: 64)) == nil, "compressed point fails closed")
}

@Test func pairingCodes() {
    for v in list("pairing_code") {
        #expect(IOSTCrypto.pairingCode(pin: unhex(v["pin_sha256_hex"] as! String)) == v["code"] as! String)
    }
}

@Test func fingerprints() {
    for v in list("fingerprint") {
        let meta = v["meta"] as! [String: Any]
        let loc = (meta["loc"] as? [String: Any]).map {
            FingerprintLocation(lat: ($0["lat"] as! NSNumber).doubleValue, lon: ($0["lon"] as! NSNumber).doubleValue,
                                alt: ($0["alt"] as? NSNumber)?.doubleValue)
        }
        let res = v["res"] as! [[String: Any]]
        var adj = [String: [UInt8]]()
        for r in res { if let h = r["sha256"] as? String { adj[r["key"] as! String] = unhex(h) } }
        let input = FingerprintInput(
            createdMs: (meta["created_ms"] as! NSNumber).int64Value,
            fav: meta["fav"] as! Bool,
            loc: loc,
            resources: res.map { (key: $0["key"] as! String, size: ($0["size"] as! NSNumber).uint64Value) },
            adjustmentSHA256: adj)
        #expect(input.canonical == v["canonical"] as! String, "\(v["name"]!)")
        #expect(hex(input.fingerprint) == v["fp"] as! String, "\(v["name"]!)")
    }
}

// The pairing QR (ARCHITECTURE §3.2): iost://pair?pcid=&h=&p=&spki=&t=&n=
// Hardened parsing (THREAT_MODEL N12): strict sizes, at most 8 hosts, IPv4 literals only.
import Foundation
import IOSTCore

struct PairingInfo: Equatable {
    var pcID: String
    var hosts: [String]
    var port: UInt16
    /// SHA-256 of the PC's SPKI.
    var pin: [UInt8]
    var token: String
    var pcName: String
    /// Any host outside private ranges (shown as a warning before pairing).
    var hasPublicHost: Bool

    var pairingCode: String { IOSTCrypto.pairingCode(pin: pin) }

    static func parse(_ text: String) -> PairingInfo? {
        guard text.utf8.count <= 1024, let c = URLComponents(string: text), c.scheme == "iost", c.host == "pair",
              let items = c.queryItems else { return nil }
        func v(_ k: String) -> String? { items.first { $0.name == k }?.value }
        guard let pcid = v("pcid"), UUID(uuidString: pcid) != nil,
              let hostList = v("h"), let portS = v("p"), let port = UInt16(portS), port > 0,
              let spki = v("spki"), spki.count == 43, let pin = IOSTCrypto.fromBase64url(spki), pin.count == 32,
              let token = v("t"), token.count == 32, token.allSatisfy({ $0.isHexDigit && !$0.isUppercase })
        else { return nil }
        let hosts = hostList.split(separator: ",").map(String.init).filter(isIPv4)
        guard !hosts.isEmpty, hosts.count <= 8 else { return nil }
        let name = String((v("n") ?? "PC").filter { !$0.isNewline && $0.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) } }.prefix(100))
        return PairingInfo(pcID: pcid.lowercased(), hosts: hosts, port: port, pin: pin, token: token, pcName: name,
                           hasPublicHost: hosts.contains { !isPrivate($0) })
    }

    private static func isIPv4(_ s: String) -> Bool {
        let p = s.split(separator: ".")
        return p.count == 4 && p.allSatisfy { UInt8($0) != nil }
    }

    private static func isPrivate(_ s: String) -> Bool {
        let p = s.split(separator: ".").compactMap { UInt8($0) }
        guard p.count == 4 else { return false }
        return p[0] == 10 || (p[0] == 172 && (16...31).contains(p[1])) || (p[0] == 192 && p[1] == 168)
    }
}

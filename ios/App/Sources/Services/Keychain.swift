// Device identity and per-PC secrets (PROTOCOL §4.1). Readable after the first unlock so a locked
// phone can reconnect; the service name is derived at runtime because SideStore re-signing may
// change the bundle ID.
import Foundation
import Security

enum Keychain {
    private static var service: String { (Bundle.main.bundleIdentifier ?? "iostransfer") + ".secrets" }

    private static func query(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    static func read(_ account: String) -> Data? {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        return SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess ? out as? Data : nil
    }

    @discardableResult
    static func write(_ account: String, _ data: Data) -> Bool {
        SecItemDelete(query(account) as CFDictionary)
        var q = query(account)
        q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        return SecItemAdd(q as CFDictionary, nil) == errSecSuccess
    }

    static func delete(_ account: String) {
        SecItemDelete(query(account) as CFDictionary)
    }

    /// Generated once; not identifierForVendor, which changes on reinstall.
    static var deviceID: UUID {
        if let d = read("device_id"), let s = String(data: d, encoding: .utf8), let id = UUID(uuidString: s) { return id }
        let id = UUID()
        write("device_id", Data(id.uuidString.utf8))
        return id
    }

    static func secret(pcID: String) -> [UInt8]? {
        read("secret." + pcID).map { [UInt8]($0) }
    }

    static func setSecret(_ s: [UInt8], pcID: String) -> Bool {
        write("secret." + pcID, Data(s))
    }
}

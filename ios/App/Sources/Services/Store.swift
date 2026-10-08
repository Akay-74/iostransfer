// The paired PC and app settings (UserDefaults; the secret lives in the Keychain).
import Foundation

struct PairedPC: Codable, Equatable {
    var pcID: String
    var name: String
    var hosts: [String]
    var port: UInt16
    var pin: [UInt8]
    /// Set after the first move to this PC was confirmed (THREAT_MODEL N13).
    var movedBefore = false
}

final class Store {
    static let shared = Store()
    private let d = UserDefaults.standard

    var pc: PairedPC? {
        get { d.data(forKey: "pairedPC").flatMap { try? JSONDecoder().decode(PairedPC.self, from: $0) } }
        set { d.set(newValue.flatMap { try? JSONEncoder().encode($0) }, forKey: "pairedPC") }
    }

    var onboardingDone: Bool {
        get { d.bool(forKey: "onboardingDone") }
        set { d.set(newValue, forKey: "onboardingDone") }
    }

    /// Experimental: keep transferring with the screen locked (silent audio).
    var backgroundKeepAlive: Bool {
        get { d.bool(forKey: "backgroundKeepAlive") }
        set { d.set(newValue, forKey: "backgroundKeepAlive") }
    }

    /// Persisted selection per section (rules only, never per-asset state).
    func selection(_ key: String) -> Data? { d.data(forKey: "selection." + key) }
    func setSelection(_ data: Data?, _ key: String) { d.set(data, forKey: "selection." + key) }
}

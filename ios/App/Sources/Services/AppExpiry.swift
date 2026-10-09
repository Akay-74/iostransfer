// When this sideloaded build stops opening: the ExpirationDate in embedded.mobileprovision (free
// Apple IDs sign for 7 days). The PC renews it; the banner says so when it hasn't.
import Foundation

enum AppExpiry {
    static let date: Date? = {
        guard let url = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision"),
              let data = try? Data(contentsOf: url)
        else { return nil }
        return parse(data)
    }()

    /// The profile is a CMS envelope with the XML plist stored verbatim inside.
    static func parse(_ data: Data) -> Date? {
        guard let start = data.range(of: Data("<?xml".utf8)),
              let end = data.range(of: Data("</plist>".utf8), in: start.lowerBound..<data.endIndex),
              let dict = try? PropertyListSerialization.propertyList(from: data[start.lowerBound..<end.upperBound], format: nil) as? [String: Any]
        else { return nil }
        return dict["ExpirationDate"] as? Date
    }

    /// Whole days left, or nil when unknown (unsigned or simulator builds).
    static var daysLeft: Int? {
        date.map { Int(($0.timeIntervalSinceNow / 86400).rounded(.down)) }
    }
}

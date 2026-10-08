// Rule-based selection (ARCHITECTURE §2.3). Selecting 50,000 photos costs a few rules, never a
// per-asset set: membership is computed from indices of the collection's fetch result.

public typealias AssetID = String

/// What the selection needs from a collection's fetch result (PHFetchResult on iOS), which is
/// ordered by creation date, oldest first.
public protocol AssetIndex {
    var count: Int { get }
    func id(at index: Int) -> AssetID
    /// nil when the asset is no longer in the collection.
    func index(of id: AssetID) -> Int?
    func createdMs(at index: Int) -> Int64
}

public enum SelectionRule: Codable, Equatable, Hashable, Sendable {
    /// Every asset of a collection.
    case all(collection: String)
    /// Tap start, tap end (either order). Boundaries carry their date so a deleted boundary asset
    /// still bounds the range.
    case range(collection: String, from: Boundary, to: Boundary)
    case dateRange(collection: String, fromMs: Int64, toMs: Int64)
    case assets(collection: String, ids: Set<AssetID>)

    public var collection: String {
        switch self {
        case let .all(c), let .range(c, _, _), let .dateRange(c, _, _), let .assets(c, _): c
        }
    }
}

public struct Boundary: Codable, Equatable, Hashable, Sendable {
    public var id: AssetID
    public var createdMs: Int64
    public init(id: AssetID, createdMs: Int64) {
        self.id = id
        self.createdMs = createdMs
    }
}

public struct Selection: Codable, Equatable, Sendable {
    public var rules: [SelectionRule] = []
    /// Assets unticked inside a selected range or collection.
    public var excluded: Set<AssetID> = []

    public init() {}

    public var isEmpty: Bool { rules.isEmpty }

    /// Index range a rule covers in `idx`, or nil for `.assets` rules.
    static func span(_ rule: SelectionRule, _ idx: AssetIndex) -> ClosedRange<Int>? {
        guard idx.count > 0 else { return nil }
        switch rule {
        case .all:
            return 0...(idx.count - 1)
        case let .range(_, a, b):
            let lo = locate(a, idx), hi = locate(b, idx)
            return min(lo.low, hi.low)...max(lo.high, hi.high)
        case let .dateRange(_, from, to):
            let lo = firstIndex(atOrAfter: min(from, to), idx)
            let hi = firstIndex(atOrAfter: max(from, to) + 1, idx) - 1
            return lo <= hi ? lo...hi : nil
        case .assets:
            return nil
        }
    }

    /// A boundary's index; if the asset vanished, the neighbours its date falls between.
    private static func locate(_ b: Boundary, _ idx: AssetIndex) -> (low: Int, high: Int) {
        if let i = idx.index(of: b.id) { return (i, i) }
        let i = firstIndex(atOrAfter: b.createdMs, idx)
        return (min(i, idx.count - 1), max(i - 1, 0))
    }

    /// Binary search on the creation-date order.
    static func firstIndex(atOrAfter ms: Int64, _ idx: AssetIndex) -> Int {
        var lo = 0, hi = idx.count
        while lo < hi {
            let mid = (lo + hi) / 2
            if idx.createdMs(at: mid) < ms { lo = mid + 1 } else { hi = mid }
        }
        return lo
    }

    /// O(rules) per cell: used for grid highlighting.
    public func contains(_ index: Int, in collection: String, _ idx: AssetIndex) -> Bool {
        let id = idx.id(at: index)
        if excluded.contains(id) { return false }
        for rule in rules where rule.collection == collection {
            if case let .assets(_, ids) = rule, ids.contains(id) { return true }
            if let s = Self.span(rule, idx), s.contains(index) { return true }
        }
        return false
    }

    /// Selected count within one collection, without enumerating ranges.
    public func count(in collection: String, _ idx: AssetIndex) -> Int {
        var spans: [ClosedRange<Int>] = []
        var singles = Set<Int>()
        for rule in rules where rule.collection == collection {
            if case let .assets(_, ids) = rule {
                singles.formUnion(ids.compactMap(idx.index(of:)))
            } else if let s = Self.span(rule, idx) {
                spans.append(s)
            }
        }
        let merged = Self.merge(spans)
        var n = merged.reduce(0) { $0 + $1.count }
        n += singles.filter { i in !merged.contains { $0.contains(i) } }.count
        let excludedInside = excluded.compactMap(idx.index(of:)).filter { i in
            merged.contains { $0.contains(i) } || singles.contains(i)
        }.count
        return n - excludedInside
    }

    static func merge(_ spans: [ClosedRange<Int>]) -> [ClosedRange<Int>] {
        var out: [ClosedRange<Int>] = []
        for s in spans.sorted(by: { $0.lowerBound < $1.lowerBound }) {
            if let last = out.last, s.lowerBound <= last.upperBound + 1 {
                out[out.count - 1] = last.lowerBound...max(last.upperBound, s.upperBound)
            } else {
                out.append(s)
            }
        }
        return out
    }

    // MARK: Editing

    /// Tap one asset: toggles it.
    public mutating func toggle(_ id: AssetID, at index: Int, in collection: String, _ idx: AssetIndex) {
        if contains(index, in: collection, idx) {
            if let r = rules.firstIndex(where: { if case let .assets(c, ids) = $0 { c == collection && ids.contains(id) } else { false } }),
               case let .assets(c, ids) = rules[r] {
                var ids = ids
                ids.remove(id)
                rules[r] = .assets(collection: c, ids: ids)
            }
            if contains(index, in: collection, idx) { excluded.insert(id) }
        } else if excluded.contains(id) {
            excluded.remove(id)
        } else {
            add(.assets(collection: collection, ids: [id]))
        }
        rules.removeAll { if case let .assets(_, ids) = $0 { ids.isEmpty } else { false } }
    }

    /// Range mode: select [a, b]; if the start was already selected, deselect the range instead.
    public mutating func applyRange(from a: Int, to b: Int, in collection: String, _ idx: AssetIndex) {
        let lo = min(a, b), hi = max(a, b)
        let ba = Boundary(id: idx.id(at: lo), createdMs: idx.createdMs(at: lo))
        let bb = Boundary(id: idx.id(at: hi), createdMs: idx.createdMs(at: hi))
        if contains(a, in: collection, idx) {
            for i in lo...hi { excluded.insert(idx.id(at: i)) }
        } else {
            for i in lo...hi { excluded.remove(idx.id(at: i)) }
            rules.append(.range(collection: collection, from: ba, to: bb))
        }
    }

    public mutating func add(_ rule: SelectionRule) {
        if case let .assets(c, ids) = rule,
           let r = rules.firstIndex(where: { if case let .assets(c2, _) = $0 { c2 == c } else { false } }),
           case let .assets(_, existing) = rules[r] {
            rules[r] = .assets(collection: c, ids: existing.union(ids))
        } else {
            rules.append(rule)
        }
    }

    public mutating func clear(collection: String) {
        rules.removeAll { $0.collection == collection }
    }

    // MARK: Resolution for transfer

    /// Every selected asset of one collection, in index (creation) order.
    public func resolve(in collection: String, _ idx: AssetIndex) -> [AssetID] {
        var spans: [ClosedRange<Int>] = []
        var singles = Set<Int>()
        for rule in rules where rule.collection == collection {
            if case let .assets(_, ids) = rule {
                singles.formUnion(ids.compactMap(idx.index(of:)))
            } else if let s = Self.span(rule, idx) {
                spans.append(s)
            }
        }
        let merged = Self.merge(spans + singles.map { $0...$0 })
        return merged.flatMap { $0.map(idx.id(at:)) }.filter { !excluded.contains($0) }
    }

    public var collections: [String] {
        var seen = Set<String>()
        return rules.map(\.collection).filter { seen.insert($0).inserted }
    }
}

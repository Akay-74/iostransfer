import Testing
import Foundation
@testable import IOSTSelection

/// 100 assets "a0"…"a99", one minute apart.
struct Fake: AssetIndex {
    var ids: [String] = (0..<100).map { "a\($0)" }
    var count: Int { ids.count }
    func id(at i: Int) -> String { ids[i] }
    func index(of id: String) -> Int? { ids.firstIndex(of: id) }
    func createdMs(at i: Int) -> Int64 { Int64(Int(ids[i].dropFirst())!) * 60_000 }
}

let C = "Recents"

@Test func rangeInEitherOrderWithExclusions() {
    let idx = Fake()
    var s = Selection()
    s.applyRange(from: 70, to: 10, in: C, idx)
    #expect(s.count(in: C, idx) == 61)
    s.toggle("a20", at: 20, in: C, idx)
    #expect(!s.contains(20, in: C, idx) && s.contains(21, in: C, idx))
    #expect(s.count(in: C, idx) == 60)
    #expect(s.resolve(in: C, idx).count == 60 && s.resolve(in: C, idx).first == "a10")
    s.toggle("a20", at: 20, in: C, idx)
    #expect(s.count(in: C, idx) == 61, "re-tick removes the exclusion")
}

@Test func rangeOverSelectedAreaDeselects() {
    let idx = Fake()
    var s = Selection()
    s.add(.all(collection: C))
    s.applyRange(from: 40, to: 49, in: C, idx)
    #expect(s.count(in: C, idx) == 90)
    #expect(!s.contains(45, in: C, idx))
}

@Test func deletedBoundaryFallsBackToItsDate() {
    var idx = Fake()
    var s = Selection()
    s.applyRange(from: 10, to: 20, in: C, idx)
    idx.ids.removeAll { $0 == "a20" }
    #expect(s.resolve(in: C, idx) == (10...19).map { "a\($0)" })
}

@Test func dateRangeAndSinglesAndOverlapsCountOnce() {
    let idx = Fake()
    var s = Selection()
    s.add(.dateRange(collection: C, fromMs: 5 * 60_000, toMs: 9 * 60_000))
    s.applyRange(from: 12, to: 8, in: C, idx) // starts on an unselected asset → selects
    s.toggle("a50", at: 50, in: C, idx)
    s.toggle("a11", at: 11, in: C, idx) // inside a range → excluded
    #expect(s.count(in: C, idx) == 8 + 1 - 1)
    #expect(s.resolve(in: C, idx) == ["a5", "a6", "a7", "a8", "a9", "a10", "a12", "a50"])
}

@Test func collectionsAreIndependentAndSerializable() throws {
    let idx = Fake()
    var s = Selection()
    s.add(.all(collection: "Screenshots"))
    s.toggle("a3", at: 3, in: C, idx)
    #expect(s.collections == ["Screenshots", C])
    #expect(s.count(in: C, idx) == 1 && s.count(in: "Screenshots", idx) == 100)
    let data = try JSONEncoder().encode(s)
    #expect(try JSONDecoder().decode(Selection.self, from: data) == s)
}

@Test func emptyCollection() {
    struct Empty: AssetIndex {
        var count: Int { 0 }
        func id(at: Int) -> String { "" }
        func index(of: String) -> Int? { nil }
        func createdMs(at: Int) -> Int64 { 0 }
    }
    var s = Selection()
    s.add(.all(collection: C))
    #expect(s.count(in: C, Empty()) == 0 && s.resolve(in: C, Empty()).isEmpty)
}

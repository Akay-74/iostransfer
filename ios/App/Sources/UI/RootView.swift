import IOSTCore
import IOSTSelection
import SwiftUI

/// Selection state for both sections, persisted as rules (never per-asset state).
@MainActor
final class LibraryModel: ObservableObject {
    @Published var pc: PairedPC? = Store.shared.pc
    @Published var selections: [MediaSection: Selection] = [:]
    @Published var collections: [MediaSection: [CollectionInfo]] = [:]

    init() {
        for s in [MediaSection.photos, .videos] {
            if let d = Store.shared.selection(s.rawValue), let sel = try? JSONDecoder().decode(Selection.self, from: d) {
                selections[s] = sel
            }
        }
    }

    func selection(_ s: MediaSection) -> Selection { selections[s] ?? Selection() }

    func update(_ s: MediaSection, _ change: (inout Selection) -> Void) {
        var sel = selection(s)
        change(&sel)
        selections[s] = sel
        Store.shared.setSelection(try? JSONEncoder().encode(sel), s.rawValue)
    }

    func reload() {
        guard PhotoLibrary.authorized || PhotoLibrary.limited else { return }
        Task.detached {
            let photos = PhotoLibrary.collections(.photos)
            let videos = PhotoLibrary.collections(.videos)
            await MainActor.run {
                self.collections[.photos] = photos
                self.collections[.videos] = videos
            }
        }
    }

    /// Selected counts, computed off the main thread: some rules over a large library need an
    /// id → index map.
    @Published var counts: [MediaSection: Int] = [:]
    @Published var collectionCounts: [MediaSection: [String: Int]] = [:]
    private var countTask: [MediaSection: Task<Void, Never>] = [:]

    func recount(_ s: MediaSection) {
        let sel = selection(s)
        countTask[s]?.cancel()
        countTask[s] = Task.detached(priority: .userInitiated) {
            var per: [String: Int] = [:]
            for c in sel.collections {
                if Task.isCancelled { return }
                per[c] = sel.count(in: c, FetchIndex(PhotoLibrary.fetch(c, s)))
            }
            let total = per.values.reduce(0, +)
            await MainActor.run {
                self.counts[s] = total
                self.collectionCounts[s] = per
            }
        }
    }

    func setPC(_ pc: PairedPC?) {
        Store.shared.pc = pc
        self.pc = pc
    }
}

struct RootView: View {
    @EnvironmentObject var library: LibraryModel
    @State private var onboarded = Store.shared.onboardingDone

    var body: some View {
        if !onboarded || library.pc == nil {
            OnboardingView(onboarded: $onboarded)
        } else {
            HomeView()
        }
    }
}

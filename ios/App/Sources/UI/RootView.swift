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

    /// Selected count across a section's collections.
    func count(_ s: MediaSection) -> Int {
        let sel = selection(s)
        return sel.collections.reduce(0) { $0 + sel.count(in: $1, FetchIndex(PhotoLibrary.fetch($1, s))) }
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

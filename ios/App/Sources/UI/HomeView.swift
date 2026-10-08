import IOSTCore
import IOSTSelection
import SwiftUI

struct JobRequest: Identifiable {
    let id = UUID()
    let section: MediaSection
    let mode: JobMode
}

struct HomeView: View {
    @EnvironmentObject var library: LibraryModel
    @State private var section: MediaSection = .photos
    @State private var job: JobRequest?
    @State private var settings = false
    @State private var selectedCount = 0

    var body: some View {
        NavigationStack {
            List(library.collections[section] ?? []) { c in
                NavigationLink(value: c) {
                    CollectionRow(collection: c, selected: selectedIn(c))
                }
            }
            .navigationDestination(for: CollectionInfo.self) { GridScreen(collection: $0, section: section) }
            .navigationTitle(section == .photos ? "Photos" : "Videos")
            .toolbar {
                ToolbarItem(placement: .principal) {
                    Picker("Section", selection: $section) {
                        Text("Photos").tag(MediaSection.photos)
                        Text("Videos").tag(MediaSection.videos)
                    }
                    .pickerStyle(.segmented)
                    .frame(width: 220)
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button { settings = true } label: { Image(systemName: "gear") }
                }
            }
            .safeAreaInset(edge: .bottom) {
                HStack {
                    Text(selectedCount == 0 ? "Nothing selected" : "\(selectedCount) selected")
                    Spacer()
                    Button("Copy") { job = JobRequest(section: section, mode: .copy) }
                        .buttonStyle(.borderedProminent).disabled(selectedCount == 0)
                    Button("Move") { job = JobRequest(section: section, mode: .move) }
                        .buttonStyle(.bordered).disabled(selectedCount == 0 || !PhotoLibrary.authorized)
                }
                .padding().background(.bar)
            }
            .onAppear { library.reload(); recount() }
            .onChange(of: section) { _ in recount() }
            .onReceive(library.$selections) { _ in recount() }
            .sheet(item: $job) { TransferView(request: $0) }
            .sheet(isPresented: $settings) { SettingsView() }
        }
    }

    private func selectedIn(_ c: CollectionInfo) -> Int {
        let sel = library.selection(section)
        guard sel.collections.contains(c.id) else { return 0 }
        return sel.count(in: c.id, FetchIndex(PhotoLibrary.fetch(c.id, section)))
    }

    private func recount() {
        selectedCount = library.count(section)
    }
}

struct GridScreen: View {
    @EnvironmentObject var library: LibraryModel
    let collection: CollectionInfo
    let section: MediaSection
    @State private var rangeMode = false
    @State private var rangeStart: Int?

    var body: some View {
        GridRepresentable(collection: collection.id, section: section, rangeMode: rangeMode, rangeStart: $rangeStart)
            .ignoresSafeArea(edges: .bottom)
            .navigationTitle(collection.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItemGroup(placement: .bottomBar) {
                    Picker("Mode", selection: $rangeMode) {
                        Text("Select").tag(false)
                        Text("Range").tag(true)
                    }
                    .pickerStyle(.segmented)
                    Spacer()
                    Button("All") { library.update(section) { $0.clear(collection: collection.id); $0.add(.all(collection: collection.id)) } }
                    Button("None") { library.update(section) { $0.clear(collection: collection.id) } }
                }
            }
            .safeAreaInset(edge: .top) {
                if rangeMode {
                    Text(rangeStart == nil ? "Tap the first photo of the range" : "Now tap the last photo")
                        .font(.callout).padding(8).frame(maxWidth: .infinity).background(.thinMaterial)
                }
            }
            .onChange(of: rangeMode) { _ in rangeStart = nil }
    }
}

struct CollectionRow: View {
    let collection: CollectionInfo
    let selected: Int

    var body: some View {
        HStack {
            Text(collection.title)
            Spacer()
            if selected > 0 {
                Text("\(selected) selected").foregroundStyle(.tint)
            }
            Text("\(collection.count)").foregroundStyle(.secondary)
        }
    }
}

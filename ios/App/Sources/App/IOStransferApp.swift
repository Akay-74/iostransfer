import SwiftUI

@main
struct IOStransferApp: App {
    @StateObject private var library = LibraryModel()

    var body: some Scene {
        WindowGroup {
            RootView().environmentObject(library)
        }
    }
}

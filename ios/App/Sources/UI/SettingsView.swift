import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var library: LibraryModel
    @Environment(\.dismiss) private var dismiss
    @State private var keepAlive = Store.shared.backgroundKeepAlive
    @State private var pairing = false

    var body: some View {
        NavigationStack {
            List {
                Section("PC") {
                    if let pc = library.pc {
                        LabeledContent("Paired with", value: pc.name)
                        LabeledContent("Addresses", value: pc.hosts.joined(separator: ", "))
                        Button("Unpair", role: .destructive) {
                            Keychain.delete("secret." + pc.pcID)
                            library.setPC(nil)
                        }
                    }
                    Button("Pair with a PC") { pairing = true }
                }
                Section {
                    Toggle("Keep transferring when locked", isOn: $keepAlive)
                        .onChange(of: keepAlive) { Store.shared.backgroundKeepAlive = $0 }
                } header: {
                    Text("Experimental")
                } footer: {
                    Text("Plays silence so iOS doesn't pause the transfer when the screen locks. Uses more battery.")
                }
                Section("About") {
                    LabeledContent("Version", value: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?")
                    if let until = AppExpiry.date {
                        LabeledContent("Signed until", value: until.formatted(date: .abbreviated, time: .shortened))
                    }
                    Text("iCloud Photos must stay off while you use Move.").font(.footnote)
                }
            }
            .navigationTitle("Settings")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
            .sheet(isPresented: $pairing) { PairingView() }
        }
    }
}

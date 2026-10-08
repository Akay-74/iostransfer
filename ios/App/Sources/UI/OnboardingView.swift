import Photos
import SwiftUI

/// ARCHITECTURE §2.9: iCloud Photos off, full photo access, Local Network, pairing.
struct OnboardingView: View {
    @EnvironmentObject var library: LibraryModel
    @Binding var onboarded: Bool
    @State private var icloudOff = false
    @State private var photoStatus = PHPhotoLibrary.authorizationStatus(for: .readWrite)
    @State private var pairing = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text("Copy or move thousands of photos and videos from this iPhone to your PC over Wi‑Fi.")
                        .foregroundStyle(.secondary)
                }
                Section("1. iCloud Photos must be off") {
                    Text("Settings → your name → iCloud → Photos → turn off “Sync this iPhone”. Choose “Download Photos & Videos” first if iOS offers it, so every original is on this iPhone.")
                        .font(.callout)
                    Toggle("iCloud Photos is off", isOn: $icloudOff)
                    Text("With iCloud Photos on, deleting here would delete from all your devices. Move stays disabled until this is confirmed.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Section("2. Photo access") {
                    switch photoStatus {
                    case .authorized:
                        Label("Full access granted", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                    case .limited:
                        Label("Limited access: albums and Move need Full Access", systemImage: "exclamationmark.triangle")
                        Button("Open Settings") { openSettings() }
                    case .denied, .restricted:
                        Label("Access denied", systemImage: "xmark.octagon").foregroundStyle(.red)
                        Button("Open Settings") { openSettings() }
                    default:
                        Button("Allow access to Photos") {
                            PhotoLibrary.requestAccess { photoStatus = $0; library.reload() }
                        }
                    }
                }
                Section("3. Pair with your PC") {
                    if let pc = library.pc {
                        Label("Paired with \(pc.name)", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                    } else {
                        Text("On the PC run:  iostransfer pair --dest <folder>").font(.callout.monospaced())
                        Button("Scan the pairing QR code") { pairing = true }
                            .disabled(photoStatus != .authorized && photoStatus != .limited)
                    }
                }
                Section {
                    Button("Done") {
                        Store.shared.onboardingDone = true
                        onboarded = true
                        library.reload()
                    }
                    .disabled(!icloudOff || library.pc == nil || (photoStatus != .authorized && photoStatus != .limited))
                }
            }
            .navigationTitle("Set up IOStransfer")
            .sheet(isPresented: $pairing) { PairingView() }
        }
    }

    private func openSettings() {
        if let u = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(u) }
    }
}

import IOSTCore
import SwiftUI

struct TransferView: View {
    @EnvironmentObject var library: LibraryModel
    @Environment(\.dismiss) private var dismiss
    let request: JobRequest
    @StateObject private var model = TransferModel()
    @State private var started = false
    @State private var confirmMove = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                if let s = model.summary {
                    summary(s)
                } else if started {
                    progress
                } else {
                    intro
                }
            }
            .padding()
            .navigationTitle(request.mode == .move ? "Move to PC" : "Copy to PC")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(model.running ? "Stop" : "Close") {
                        if model.running { model.cancel() } else { dismiss() }
                    }
                }
            }
            .alert(promptTitle, isPresented: Binding(get: { model.prompt != nil }, set: { if !$0 { model.prompt = nil } })) {
                promptButtons
            } message: {
                Text(promptMessage)
            }
            .interactiveDismissDisabled(model.running)
        }
    }

    private var intro: some View {
        VStack(spacing: 16) {
            Text("\(library.count(request.section)) items to \(request.mode == .move ? "move" : "copy") to \(library.pc?.name ?? "your PC").")
                .font(.headline).multilineTextAlignment(.center)
            if request.mode == .move {
                Text("Each item is deleted from this iPhone only after the PC has verified its copy. iOS asks you to confirm the delete. Deleted items stay in Recently Deleted for 30 days.")
                    .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
            }
            Text("Keep this screen open while transferring.").font(.callout)
            Button(request.mode == .move ? "Start move" : "Start copy") {
                if request.mode == .move { confirmMove = true } else { start() }
            }
            .buttonStyle(.borderedProminent)
            .confirmationDialog("iCloud Photos must be off", isPresented: $confirmMove) {
                Button("iCloud Photos is off: move") { start() }
            } message: {
                Text("With iCloud Photos on, deleting here deletes everywhere.")
            }
        }
    }

    private var progress: some View {
        VStack(spacing: 16) {
            Text(phaseText).font(.headline)
            let p = model.progress
            let done = p.assetsDone + p.assetsSkipped + p.assetsFailed
            ProgressView(value: Double(done), total: Double(max(p.assetsKnown, 1)))
            Text("\(done) of \(p.assetsKnown)  ·  \(ByteCountFormatter.string(fromByteCount: Int64(p.bytesSent), countStyle: .file)) sent")
                .font(.callout.monospacedDigit())
            if let paused = p.paused { Label("Paused by the PC: \(paused)", systemImage: "pause.circle") }
            if !model.status.isEmpty { Text(model.status).font(.footnote).foregroundStyle(.secondary) }
            Text("Keep this screen open.").font(.footnote).foregroundStyle(.secondary)
        }
    }

    private var phaseText: String {
        switch model.progress.phase {
        case .connecting: "Connecting to \(library.pc?.name ?? "PC")…"
        case .transferring: "Transferring"
        case .verifying: "Verifying copies on the PC"
        case .deleting: "Deleting from iPhone"
        case .done: "Done"
        case .blocked: "Stopped"
        }
    }

    private func summary(_ s: JobSummary) -> some View {
        VStack(spacing: 12) {
            Image(systemName: "checkmark.circle.fill").font(.system(size: 56)).foregroundStyle(.green)
            Text("Copied \(s.copied) · already on PC \(s.alreadyOnPC)")
            Text(ByteCountFormatter.string(fromByteCount: Int64(s.bytes), countStyle: .file) + " sent")
            if request.mode == .move {
                Text("Moved \(s.deleted) to Recently Deleted")
                if s.deleted > 0 {
                    Text("Space is freed after you empty Recently Deleted (Photos → Albums → Recently Deleted). Spot-check the PC first.")
                        .font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center)
                }
                ForEach(s.dropped.sorted(by: { $0.key < $1.key }), id: \.key) { k, v in
                    Text("\(v) kept on iPhone: \(k.replacingOccurrences(of: "_", with: " "))").font(.footnote)
                }
            }
            ForEach(s.failed.sorted(by: { $0.key < $1.key }), id: \.key) { k, v in
                Text("\(v) failed: \(k.replacingOccurrences(of: "_", with: " "))").font(.footnote).foregroundStyle(.red)
            }
            Button("Done") { dismiss() }.buttonStyle(.borderedProminent)
        }
    }

    private func start() {
        started = true
        let purpose = SessionDriver.Purpose.transfer(selection: library.selection(request.section), section: request.section,
                                                     mode: request.mode)
        guard let d = SessionDriver(purpose: purpose, model: model) else {
            model.status = "Not paired with a PC."
            return
        }
        model.driver = d
        d.start()
    }

    // MARK: Prompts

    private var promptTitle: String {
        switch model.prompt {
        case .confirmFirstMove: "First move to this PC"
        case .confirmDeleteAgain: "Nothing was deleted"
        case .pairAgain: "Pair again"
        case .wrongPC: "Different PC"
        case .pcDiskFull: "PC disk full"
        case .freeSpace: "iPhone storage full"
        case .updateApp: "Update needed"
        case .journalError: "Storage error"
        case nil: ""
        }
    }

    private var promptMessage: String {
        switch model.prompt {
        case let .confirmFirstMove(name): "Items will be deleted from this iPhone after \(name) verified its copies. Continue?"
        case let .confirmDeleteAgain(n): "You cancelled the delete prompt. \(n) items are safely on the PC. Delete them from the iPhone now?"
        case let .pairAgain(reason): "The PC didn't accept this iPhone (\(reason)). Pair again from Settings."
        case .wrongPC: "A different PC answered. Pair again from Settings."
        case .pcDiskFull: "Free space on the PC, then try again."
        case let .freeSpace(b): "Free about \(ByteCountFormatter.string(fromByteCount: Int64(b), countStyle: .file)) on this iPhone to send this item."
        case let .updateApp(side): "Update the \(side) app so both speak the same protocol."
        case let .journalError(e): "IOStransfer couldn't write its progress record (\(e)). Nothing was deleted."
        case nil: ""
        }
    }

    @ViewBuilder private var promptButtons: some View {
        switch model.prompt {
        case .confirmFirstMove:
            Button("Delete from iPhone", role: .destructive) { model.reply(.confirmFirstMove(true)) }
            Button("Keep on iPhone", role: .cancel) { model.reply(.confirmFirstMove(false)) }
        case .confirmDeleteAgain:
            Button("Delete", role: .destructive) { model.reply(.deleteAgain(true)) }
            Button("Not now", role: .cancel) { model.reply(.deleteAgain(false)) }
        default:
            Button("OK") { model.prompt = nil }
        }
    }
}

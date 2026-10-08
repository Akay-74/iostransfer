import AVFoundation
import IOSTCore
import SwiftUI

/// Scan the QR, show the pairing code to compare with the PC (THREAT_MODEL N11), then pair.
struct PairingView: View {
    @EnvironmentObject var library: LibraryModel
    @Environment(\.dismiss) private var dismiss
    @StateObject private var model = TransferModel()
    @State private var info: PairingInfo?
    @State private var badCode = false

    var body: some View {
        NavigationStack {
            Group {
                if let info {
                    VStack(spacing: 20) {
                        Text("Pair with \(info.pcName)").font(.title2.bold())
                        Text("Check that the PC shows the same code, then answer “y” on the PC.")
                            .multilineTextAlignment(.center).foregroundStyle(.secondary)
                        Text(info.pairingCode).font(.system(size: 40, weight: .bold, design: .monospaced))
                        if info.hasPublicHost {
                            Label("The QR code points to a non-private address. Only continue if this is your PC.",
                                  systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                        }
                        if model.running {
                            ProgressView("Waiting for the PC to confirm…")
                        } else if let err = model.pairingError ?? promptText {
                            Text(err).foregroundStyle(.red).multilineTextAlignment(.center)
                            Button("Scan again") { reset() }
                        } else {
                            Button("Pair") { pair(info) }.buttonStyle(.borderedProminent)
                        }
                    }
                    .padding()
                } else {
                    QRScanner { text in
                        if let p = PairingInfo.parse(text) { info = p } else { badCode = true }
                    }
                    .ignoresSafeArea()
                    .overlay(alignment: .bottom) {
                        Text(badCode ? "That isn't an IOStransfer pairing code." : "Point the camera at the QR code on your PC.")
                            .padding().background(.thinMaterial, in: Capsule()).padding(.bottom, 40)
                    }
                }
            }
            .navigationTitle("Pair")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { model.cancel(); dismiss() } } }
            .onChange(of: model.pairingDone) { pc in
                if let pc {
                    library.setPC(pc)
                    dismiss()
                }
            }
        }
    }

    private var promptText: String? {
        guard let p = model.prompt else { return nil }
        switch p {
        case .pairAgain(let reason): return "Pairing failed: \(reason). Run `iostransfer pair` again for a fresh code."
        case .updateApp(let side): return "Update the \(side) app."
        default: return "Pairing failed."
        }
    }

    private func pair(_ info: PairingInfo) {
        guard let d = SessionDriver(purpose: .pairing(info), model: model) else { return }
        model.driver = d
        d.start()
    }

    private func reset() {
        info = nil
        model.prompt = nil
        model.pairingError = nil
    }
}

/// Camera QR scanner (AVFoundation; no URL scheme is registered, THREAT_MODEL N10).
struct QRScanner: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerController {
        let c = ScannerController()
        c.onCode = onCode
        return c
    }

    func updateUIViewController(_: ScannerController, context: Context) {}

    final class ScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
        var onCode: ((String) -> Void)?
        private let session = AVCaptureSession()
        private var last = ""

        override func viewDidLoad() {
            super.viewDidLoad()
            view.backgroundColor = .black
            guard let device = AVCaptureDevice.default(for: .video), let input = try? AVCaptureDeviceInput(device: device),
                  session.canAddInput(input) else { return }
            session.addInput(input)
            let output = AVCaptureMetadataOutput()
            guard session.canAddOutput(output) else { return }
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]
            let preview = AVCaptureVideoPreviewLayer(session: session)
            preview.videoGravity = .resizeAspectFill
            preview.frame = view.bounds
            view.layer.addSublayer(preview)
        }

        override func viewWillAppear(_ animated: Bool) {
            super.viewWillAppear(animated)
            DispatchQueue.global(qos: .userInitiated).async { self.session.startRunning() }
        }

        override func viewWillDisappear(_ animated: Bool) {
            super.viewWillDisappear(animated)
            session.stopRunning()
        }

        override func viewDidLayoutSubviews() {
            super.viewDidLayoutSubviews()
            view.layer.sublayers?.first?.frame = view.bounds
        }

        func metadataOutput(_: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject], from _: AVCaptureConnection) {
            guard let s = (objects.first as? AVMetadataMachineReadableCodeObject)?.stringValue, s != last else { return }
            last = s
            onCode?(s)
        }
    }
}

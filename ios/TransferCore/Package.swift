// swift-tools-version: 5.10
// TransferCore: the phone-side engine (docs/TRANSFERCORE.md). Builds and tests on Linux.
import PackageDescription

let package = Package(
    name: "TransferCore",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "IOSTWire", targets: ["IOSTWire"]),
    ],
    targets: [
        .target(name: "IOSTWire"),
        .testTarget(name: "IOSTWireTests", dependencies: ["IOSTWire"]),
    ]
)

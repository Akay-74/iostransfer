// swift-tools-version: 5.10
// TransferCore: the phone-side engine (docs/TRANSFERCORE.md). Builds and tests on Linux.
import PackageDescription

let package = Package(
    name: "TransferCore",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "IOSTWire", targets: ["IOSTWire"]),
        .library(name: "IOSTCrypto", targets: ["IOSTCrypto"]),
    ],
    dependencies: [
        // The only dependency (TRANSFERCORE §2), pinned exactly (THREAT_MODEL N18).
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "5.0.0"),
    ],
    targets: [
        .target(name: "IOSTWire"),
        .target(name: "IOSTCrypto", dependencies: [.product(name: "Crypto", package: "swift-crypto")]),
        .testTarget(name: "IOSTWireTests", dependencies: ["IOSTWire"]),
        .testTarget(name: "IOSTCryptoTests", dependencies: ["IOSTCrypto"]),
    ]
)

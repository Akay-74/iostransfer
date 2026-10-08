// swift-tools-version: 5.10
// TransferCore: the phone-side engine (docs/TRANSFERCORE.md). Builds and tests on Linux.
import PackageDescription

let package = Package(
    name: "TransferCore",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "IOSTWire", targets: ["IOSTWire"]),
        .library(name: "IOSTCrypto", targets: ["IOSTCrypto"]),
        .library(name: "IOSTJournal", targets: ["IOSTJournal"]),
        .library(name: "IOSTCore", targets: ["IOSTCore"]),
        .library(name: "IOSTSelection", targets: ["IOSTSelection"]),
    ],
    dependencies: [
        // The only dependency (TRANSFERCORE §2), pinned exactly (THREAT_MODEL N18).
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "5.0.0"),
    ],
    targets: [
        .target(name: "IOSTWire"),
        .systemLibrary(name: "CSQLite", path: "Sources/CSQLite", providers: [.apt(["libsqlite3-dev"]), .yum(["sqlite-devel"])]),
        .target(name: "IOSTJournal", dependencies: ["CSQLite"]),
        .target(name: "IOSTCore", dependencies: ["IOSTWire", "IOSTCrypto", "IOSTJournal"]),
        .executableTarget(name: "iost-interop-sender", dependencies: ["IOSTCore"]),
        .target(name: "IOSTSelection"),
        .target(name: "IOSTCrypto", dependencies: [.product(name: "Crypto", package: "swift-crypto")]),
        .testTarget(name: "IOSTWireTests", dependencies: ["IOSTWire"]),
        .testTarget(name: "IOSTCryptoTests", dependencies: ["IOSTCrypto"]),
        .testTarget(name: "IOSTJournalTests", dependencies: ["IOSTJournal"]),
        .testTarget(name: "IOSTCoreTests", dependencies: ["IOSTCore"]),
        .testTarget(name: "IOSTSelectionTests", dependencies: ["IOSTSelection"]),
    ]
)

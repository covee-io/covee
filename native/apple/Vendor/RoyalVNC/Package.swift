// swift-tools-version: 6.0
import PackageDescription

// RoyalVNCKit from https://github.com/royalapplications/royalvnc at commit
// 92d4427c73817d8f849bb289ff190aa4b40c44ea (release 1.1.0; the repository is
// archived). Covee keeps this copy for iPhone and iPad screen sharing; see
// COVEE.md for what differs from upstream.
let package = Package(
    name: "RoyalVNCKit",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        // Static: a dynamic library made Xcode infer that the iPhone app
        // depends on the Mac app, which shares its name.
        .library(name: "RoyalVNCKit", targets: ["RoyalVNCKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/royalapplications/CryptoSwift.git", revision: "a59b4d91ebb22011656c830f874fe7152e183a57"),
    ],
    targets: [
        .target(name: "RoyalVNCKitC"),
        .target(name: "d3des"),
        .target(name: "Z", linkerSettings: [.linkedLibrary("z")]),
        .target(
            name: "RoyalVNCKit",
            dependencies: ["RoyalVNCKitC", "d3des", "Z", .product(name: "CryptoSwift", package: "CryptoSwift")],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)

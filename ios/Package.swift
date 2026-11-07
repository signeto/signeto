// swift-tools-version: 5.9
// SignetoSign: the approver-device side of the Signeto protocol (docs/protocol.md), for iOS and macOS.
// No third-party dependencies: CryptoKit, Foundation, Security and LocalAuthentication only.
import PackageDescription

let package = Package(
    name: "SignetoSign",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "SignetoSign", targets: ["SignetoSign"]),
    ],
    targets: [
        .target(
            name: "SignetoSign",
            resources: [.copy("Resources/builtin-registries.json")]
        ),
        .testTarget(
            name: "SignetoSignTests",
            dependencies: ["SignetoSign"],
            exclude: ["Fixtures"]
        ),
    ]
)

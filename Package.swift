// swift-tools-version:5.3

import PackageDescription

let package = Package(
    name: "CCSwift",
    platforms: [
        .iOS(.v12), .macOS(.v10_13)
    ],
    products: [
        .library(name: "CCSwift", targets: ["CCSwift"]),
    ],
    dependencies: [
        .package(url: "https://github.com/Craz1k0ek/CCWrapper.git", from: "1.0.0")
    ],
    targets: [
        .target(name: "CCSwift", dependencies: ["CCWrapper"]),
        .testTarget(name: "CCSwiftTests", dependencies: ["CCSwift"])
    ]
)

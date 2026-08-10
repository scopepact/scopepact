// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "ScopePact",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "ScopePact", targets: ["ScopePact"]),
    ],
    targets: [
        .target(name: "ScopePact"),
        .testTarget(name: "ScopePactTests", dependencies: ["ScopePact"]),
    ]
)

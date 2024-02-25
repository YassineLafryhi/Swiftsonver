// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Swiftsonver",
    platforms: [
        .macOS(.v13),
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "4.89.0"),
        .package(url: "https://github.com/vapor/jwt.git", .upToNextMajor(from: "4.2.2")),
        .package(url: "https://github.com/jpsim/Yams.git", .upToNextMajor(from: "5.0.6")),
        .package(url: "https://github.com/vapor/fluent.git", from: "4.0.0"),
        .package(url: "https://github.com/SwiftyJSON/SwiftyJSON.git", from: "5.0.0"),
        .package(url: "https://github.com/kylef/Commander.git", from: "0.9.1"),
    ],
    targets: [
        .executableTarget(
            name: "Swiftsonver",
            dependencies: [
                .product(name: "Vapor", package: "vapor"),
                .product(name: "JWT", package: "jwt"),
                .product(name: "Yams", package: "Yams"),
                .product(name: "Fluent", package: "fluent"),
                .product(name: "SwiftyJSON", package: "SwiftyJSON"),
                .product(name: "Commander", package: "Commander"),
            ]
        ),
    ]
)

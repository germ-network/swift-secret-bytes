// swift-tools-version: 6.2
import PackageDescription

let package = Package(
	name: "swift-secret-bytes",
	platforms: [.iOS(.v16), .macOS(.v13)],
	products: [
		.library(name: "SecretBytes", targets: ["SecretBytes"])
	],
	dependencies: [
		.package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0")
	],
	targets: [
		.target(name: "CSecretBytesZeroize"),
		.target(
			name: "SecretBytes",
			dependencies: [
				"CSecretBytesZeroize",
				.product(name: "Crypto", package: "swift-crypto"),
			]
		),
		.testTarget(
			name: "SecretBytesTests",
			dependencies: ["SecretBytes", "CSecretBytesZeroize"]
		),
	]
)

// swift-tools-version: 6.1
import PackageDescription

let package = Package(
	name: "swift-secret-bytes",
	platforms: [.iOS(.v16), .macOS(.v13)],
	products: [
		.library(name: "SecretBytes", targets: ["SecretBytes"])
	],
	dependencies: [
		.package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
		// Test-only oracle for cross-checking this package's hand-rolled CBOR
		// codec against an independent implementation. Pinned at 0.1.0 per the
		// org-wide standard (see autonomous-comm-protocol/Package.swift) — must
		// never be added to the SecretBytes library product.
		.package(url: "https://github.com/nnabeyang/swift-cbor.git", from: "0.1.0"),
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
			dependencies: [
				"SecretBytes", "CSecretBytesZeroize",
				.product(name: "SwiftCbor", package: "swift-cbor"),
			]
		),
	]
)

import Crypto
import Foundation
import XCTest

@testable import SecretBytes

/// Pins the interop the `ContiguousBytes` conformance exists to provide.
///
/// The conformance adds no capability — its only requirement is
/// `withUnsafeBytes`, already public. What it buys is that a secret reaches a
/// `some ContiguousBytes` parameter directly, with no intermediate `Data`.
/// If someone removes the conformance, these stop compiling, and the
/// ergonomic fallback (`withUnsafeBytes { Data($0) }`) mints an unscrubbed
/// copy per call on hot paths.
final class ContiguousBytesInteropTests: XCTestCase {
	func testSecretBytesConformsToContiguousBytes() {
		func requireContiguousBytes<T: ContiguousBytes>(_: T.Type) {}
		requireContiguousBytes(SecretBytes.self)
	}

	func testFeedsSymmetricKeyDirectly() throws {
		let raw = [UInt8](repeating: 0x5A, count: 32)
		let secret = try SecretBytes(bytes: raw)

		// No `Data($0)` hop — the secret is the ContiguousBytes argument.
		let key = SymmetricKey(data: secret)

		XCTAssertEqual(key.withUnsafeBytes { [UInt8]($0) }, raw)
	}

	func testFeedsHKDFDirectly() throws {
		let secret = try SecretBytes(bytes: [UInt8](repeating: 0xA5, count: 32))

		let derived = HKDF<SHA256>.expand(
			pseudoRandomKey: secret,
			info: Data("germ-secret-bytes-test".utf8),
			outputByteCount: 32
		)

		// Derivation is deterministic in the secret, so the same secret yields
		// the same output — and a different secret does not.
		let again = HKDF<SHA256>.expand(
			pseudoRandomKey: try SecretBytes(
				bytes: [UInt8](repeating: 0xA5, count: 32)),
			info: Data("germ-secret-bytes-test".utf8),
			outputByteCount: 32
		)
		let other = HKDF<SHA256>.expand(
			pseudoRandomKey: try SecretBytes(
				bytes: [UInt8](repeating: 0x5A, count: 32)),
			info: Data("germ-secret-bytes-test".utf8),
			outputByteCount: 32
		)

		XCTAssertEqual(derived, again)
		XCTAssertNotEqual(derived, other)
	}

	/// The conformance must not have widened byte access: `withUnsafeBytes`
	/// remains the only way through, and it still yields exactly the secret.
	func testConformanceExposesOnlyTheExistingHatch() throws {
		let raw: [UInt8] = [1, 2, 3, 4, 5]
		let secret = try SecretBytes(bytes: raw)

		func readViaProtocol<T: ContiguousBytes>(_ value: T) -> [UInt8] {
			value.withUnsafeBytes { [UInt8]($0) }
		}

		XCTAssertEqual(readViaProtocol(secret), raw)
		XCTAssertEqual(secret.byteCount, raw.count)
	}
}

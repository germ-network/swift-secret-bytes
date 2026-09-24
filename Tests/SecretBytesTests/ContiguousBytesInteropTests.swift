import Crypto
import Foundation
import Testing

@testable import SecretBytes

/// Pins the interop the `ContiguousBytes` conformance exists to provide.
///
/// The conformance adds no capability — its only requirement is
/// `withUnsafeBytes`, already public. What it buys is that a secret reaches a
/// `some ContiguousBytes` parameter directly, with no intermediate `Data`.
/// If someone removes the conformance, these stop compiling, and the
/// ergonomic fallback (`withUnsafeBytes { Data($0) }`) mints an unscrubbed
/// copy per call on hot paths.
@Suite struct ContiguousBytesInteropTests {
	@Test func secretBytesConformsToContiguousBytes() {
		func requireContiguousBytes<T: ContiguousBytes>(_: T.Type) {}
		requireContiguousBytes(SecretBytes.self)
	}

	@Test func feedsSymmetricKeyDirectly() throws {
		let raw = [UInt8](repeating: 0x5A, count: 32)
		let secret = try SecretBytes(bytes: raw)

		// No `Data($0)` hop — the secret is the ContiguousBytes argument.
		let key = SymmetricKey(data: secret)

		#expect(key.withUnsafeBytes { [UInt8]($0) } == raw)
	}

	@Test func feedsHKDFDirectly() throws {
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

		#expect(derived == again)
		#expect(derived != other)
	}

	/// The conformance must not have widened byte access: `withUnsafeBytes`
	/// remains the only way through, and it still yields exactly the secret.
	@Test func conformanceExposesOnlyTheExistingHatch() throws {
		let raw: [UInt8] = [1, 2, 3, 4, 5]
		let secret = try SecretBytes(bytes: raw)

		func readViaProtocol<T: ContiguousBytes>(_ value: T) -> [UInt8] {
			value.withUnsafeBytes { [UInt8]($0) }
		}

		#expect(readViaProtocol(secret) == raw)
		#expect(secret.byteCount == raw.count)
	}
}

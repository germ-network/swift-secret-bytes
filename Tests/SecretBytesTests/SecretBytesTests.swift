import Crypto
import Foundation
import Testing

@testable import SecretBytes

@Suite struct SecretBytesTests {
	@Test func descriptionRedactsBytesExactly() throws {
		let secret = try SecretBytes(bytes: [UInt8](repeating: 0xAB, count: 32))
		#expect(secret.description == "SecretBytes(32 bytes)")
		#expect(secret.debugDescription == "SecretBytes(32 bytes)")
	}

	@Test func descriptionTracksByteCount() throws {
		#expect(
			try SecretBytes(bytes: [1, 2, 3]).description == "SecretBytes(3 bytes)")
		#expect(
			SecretBytes(randomByteCount: 16).description == "SecretBytes(16 bytes)")
	}

	@Test func mirrorDoesNotExposeRawBytes() throws {
		let secret = try SecretBytes(bytes: [0xDE, 0xAD, 0xBE, 0xEF])
		let dumped = String(reflecting: secret)
		#expect(!dumped.contains("222"))  // 0xDE as a decimal byte
		#expect(!dumped.lowercased().contains("deadbeef"))
		#expect("\(Mirror(reflecting: secret).children.count)" == "1")
	}

	@Test func roundTripsThroughWithUnsafeBytes() throws {
		let bytes: [UInt8] = [0, 1, 2, 3, 250, 251, 252, 253]
		let secret = try SecretBytes(bytes: bytes)
		let recovered = secret.withUnsafeBytes { [UInt8]($0) }
		#expect(recovered == bytes)
		#expect(secret.byteCount == bytes.count)
	}

	/// The signed-bytes ingress reinterprets each `Int8` as its raw byte — the
	/// `jextract`/JNI arrival shape — and round-trips identically to
	/// `init(bytes:)`.
	@Test func signedBytesIngressReinterpretsAndRoundTrips() throws {
		let signed: [Int8] = [0, 1, -1, -2, 127, -128, 42]
		let viaSigned = try SecretBytes(signedBytes: signed)
		let viaUnsigned = try SecretBytes(bytes: signed.map { UInt8(bitPattern: $0) })
		#expect(viaSigned == viaUnsigned)
		#expect(viaSigned.byteCount == signed.count)
		let recovered = viaSigned.withUnsafeBytes { [Int8]($0.bindMemory(to: Int8.self)) }
		#expect(recovered == signed)
	}

	@Test func emptySignedBytesThrows() {
		#expect(throws: SecretBytesError.emptySecret) {
			try SecretBytes(signedBytes: [] as [Int8])
		}
	}

	/// A zero-byte secret is rejected — and rejected by *throwing*, because
	/// `bytes` is caller data that may be attacker-influenced. A decoder handing
	/// over a zero-length field must surface an error, not abort the process.
	@Test func emptySecretThrows() {
		#expect(throws: SecretBytesError.emptySecret) {
			try SecretBytes(bytes: [] as [UInt8])
		}
		#expect(throws: SecretBytesError.emptySecret) {
			try SecretBytes(bytes: Data())
		}
	}

	/// Defense in depth: an empty secret should be unconstructible through
	/// public API, but if one is reached through the internal initializer it
	/// must still compare reflexively — `SymmetricKey`'s constant-time compare
	/// returns false for zero-length input, and the failure would be silent.
	@Test func emptySecretViaInternalInitStillComparesReflexively() throws {
		let empty = SecretBytes(SymmetricKey(data: Data()))
		let alsoEmpty = SecretBytes(SymmetricKey(data: Data()))
		let one = try SecretBytes(bytes: [0])

		#expect(empty.byteCount == 0)
		#expect(empty == empty, "reflexivity must hold even for the unreachable case")
		#expect(empty == alsoEmpty)
		#expect(empty != one)
		#expect(one != empty)
	}

	@Test func equalityIsValueBased() throws {
		let a = try SecretBytes(bytes: [9, 9, 9])
		let b = try SecretBytes(bytes: [9, 9, 9])
		let c = try SecretBytes(bytes: [9, 9, 8])
		#expect(a == b)
		#expect(a == a)
		#expect(a != c)
	}

	@Test func secretBytesIsSendable() {
		func requireSendable<T: Sendable>(_: T.Type) {}
		requireSendable(SecretBytes.self)
	}
}

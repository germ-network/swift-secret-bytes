import XCTest

@testable import SecretBytes

final class SecretBytesTests: XCTestCase {
	func testDescriptionRedactsBytesExactly() {
		let secret = SecretBytes(bytes: [UInt8](repeating: 0xAB, count: 32))
		XCTAssertEqual(secret.description, "SecretBytes(32 bytes)")
		XCTAssertEqual(secret.debugDescription, "SecretBytes(32 bytes)")
	}

	func testDescriptionTracksByteCount() {
		XCTAssertEqual(SecretBytes(bytes: [1, 2, 3]).description, "SecretBytes(3 bytes)")
		XCTAssertEqual(
			SecretBytes(randomByteCount: 16).description, "SecretBytes(16 bytes)")
	}

	func testMirrorDoesNotExposeRawBytes() {
		let secret = SecretBytes(bytes: [0xDE, 0xAD, 0xBE, 0xEF])
		let dumped = String(reflecting: secret)
		XCTAssertFalse(dumped.contains("222"))  // 0xDE as a decimal byte
		XCTAssertFalse(dumped.lowercased().contains("deadbeef"))
		XCTAssertTrue("\(Mirror(reflecting: secret).children.count)" == "1")
	}

	func testRoundTripsThroughWithUnsafeBytes() {
		let bytes: [UInt8] = [0, 1, 2, 3, 250, 251, 252, 253]
		let secret = SecretBytes(bytes: bytes)
		let recovered = secret.withUnsafeBytes { [UInt8]($0) }
		XCTAssertEqual(recovered, bytes)
		XCTAssertEqual(secret.byteCount, bytes.count)
	}

	/// `SymmetricKey`'s constant-time compare returns false for zero-length
	/// input, which made an empty secret compare unequal to itself. Reachable
	/// via `init(bytes:)` and via `Reader.readSecret()` on a zero-length
	/// field, so `Equatable`'s reflexivity requirement was genuinely broken.
	func testEmptySecretIsEqualToItself() {
		let empty = SecretBytes(bytes: [] as [UInt8])
		let alsoEmpty = SecretBytes(bytes: [] as [UInt8])

		XCTAssertEqual(empty.byteCount, 0)
		XCTAssertEqual(empty, empty, "reflexivity: an empty secret must equal itself")
		XCTAssertEqual(empty, alsoEmpty, "two empty secrets must compare equal")
	}

	func testEmptySecretIsNotEqualToNonEmpty() {
		let empty = SecretBytes(bytes: [] as [UInt8])
		let nonEmpty = SecretBytes(bytes: [0])

		XCTAssertNotEqual(empty, nonEmpty)
		XCTAssertNotEqual(nonEmpty, empty)
	}

	/// An empty secret restored from an archive must behave like any other.
	func testEmptySecretFromReaderIsEqualToItself() throws {
		var writer = SecretArchive.Writer()
		writer.writeSecret(SecretBytes(bytes: [] as [UInt8]))
		var reader = SecretArchive.Reader(writer.finalize())

		let restored = try reader.readSecret()
		XCTAssertEqual(restored.byteCount, 0)
		XCTAssertEqual(restored, restored)
		XCTAssertEqual(restored, SecretBytes(bytes: [] as [UInt8]))
	}

	func testEqualityIsValueBased() {
		let a = SecretBytes(bytes: [9, 9, 9])
		let b = SecretBytes(bytes: [9, 9, 9])
		let c = SecretBytes(bytes: [9, 9, 8])
		XCTAssertEqual(a, b)
		XCTAssertEqual(a, a)
		XCTAssertNotEqual(a, c)
	}

	func testSecretBytesIsSendable() {
		func requireSendable<T: Sendable>(_: T.Type) {}
		requireSendable(SecretBytes.self)
	}
}

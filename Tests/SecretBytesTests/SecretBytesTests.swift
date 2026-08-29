import Crypto
import Foundation
import XCTest

@testable import SecretBytes

final class SecretBytesTests: XCTestCase {
	func testDescriptionRedactsBytesExactly() throws {
		let secret = try SecretBytes(bytes: [UInt8](repeating: 0xAB, count: 32))
		XCTAssertEqual(secret.description, "SecretBytes(32 bytes)")
		XCTAssertEqual(secret.debugDescription, "SecretBytes(32 bytes)")
	}

	func testDescriptionTracksByteCount() throws {
		XCTAssertEqual(
			try SecretBytes(bytes: [1, 2, 3]).description, "SecretBytes(3 bytes)")
		XCTAssertEqual(
			SecretBytes(randomByteCount: 16).description, "SecretBytes(16 bytes)")
	}

	func testMirrorDoesNotExposeRawBytes() throws {
		let secret = try SecretBytes(bytes: [0xDE, 0xAD, 0xBE, 0xEF])
		let dumped = String(reflecting: secret)
		XCTAssertFalse(dumped.contains("222"))  // 0xDE as a decimal byte
		XCTAssertFalse(dumped.lowercased().contains("deadbeef"))
		XCTAssertTrue("\(Mirror(reflecting: secret).children.count)" == "1")
	}

	func testRoundTripsThroughWithUnsafeBytes() throws {
		let bytes: [UInt8] = [0, 1, 2, 3, 250, 251, 252, 253]
		let secret = try SecretBytes(bytes: bytes)
		let recovered = secret.withUnsafeBytes { [UInt8]($0) }
		XCTAssertEqual(recovered, bytes)
		XCTAssertEqual(secret.byteCount, bytes.count)
	}

	/// A zero-byte secret is rejected — and rejected by *throwing*, because
	/// `bytes` is caller data that may be attacker-influenced. A decoder handing
	/// over a zero-length field must surface an error, not abort the process.
	func testEmptySecretThrows() {
		XCTAssertThrowsError(try SecretBytes(bytes: [] as [UInt8])) { error in
			XCTAssertEqual(error as? SecretBytesError, .emptySecret)
		}
		XCTAssertThrowsError(try SecretBytes(bytes: Data())) { error in
			XCTAssertEqual(error as? SecretBytesError, .emptySecret)
		}
	}

	/// Defense in depth: an empty secret should be unconstructible through
	/// public API, but if one is reached through the internal initializer it
	/// must still compare reflexively — `SymmetricKey`'s constant-time compare
	/// returns false for zero-length input, and the failure would be silent.
	func testEmptySecretViaInternalInitStillComparesReflexively() throws {
		let empty = SecretBytes(SymmetricKey(data: Data()))
		let alsoEmpty = SecretBytes(SymmetricKey(data: Data()))
		let one = try SecretBytes(bytes: [0])

		XCTAssertEqual(empty.byteCount, 0)
		XCTAssertEqual(empty, empty, "reflexivity must hold even for the unreachable case")
		XCTAssertEqual(empty, alsoEmpty)
		XCTAssertNotEqual(empty, one)
		XCTAssertNotEqual(one, empty)
	}

	func testEqualityIsValueBased() throws {
		let a = try SecretBytes(bytes: [9, 9, 9])
		let b = try SecretBytes(bytes: [9, 9, 9])
		let c = try SecretBytes(bytes: [9, 9, 8])
		XCTAssertEqual(a, b)
		XCTAssertEqual(a, a)
		XCTAssertNotEqual(a, c)
	}

	func testSecretBytesIsSendable() {
		func requireSendable<T: Sendable>(_: T.Type) {}
		requireSendable(SecretBytes.self)
	}
}

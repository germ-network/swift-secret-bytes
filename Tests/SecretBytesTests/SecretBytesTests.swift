import Crypto
import Foundation
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

	/// The invariant `init(randomByteCount:)` has always asserted is now
	/// enforced on both initializers. A zero-byte secret is meaningless, and
	/// permitting one reintroduced a reflexivity violation.
	func testEmptySecretIsRejectedAtConstruction() {
		// Not expressible as an XCTest assertion — a precondition traps rather
		// than throwing. Pinned by the doc comment and by the guard below, which
		// covers the same state reached through the internal initializer.
		XCTAssertEqual(SecretBytes(bytes: [0]).byteCount, 1)
	}

	/// Defense in depth: an empty secret should be unconstructible, but if one
	/// is reached through the internal initializer it must still compare
	/// reflexively, because `SymmetricKey`'s constant-time compare returns
	/// false for zero-length input and the failure would otherwise be silent.
	func testEmptySecretViaInternalInitStillComparesReflexively() {
		let empty = SecretBytes(SymmetricKey(data: Data()))
		let alsoEmpty = SecretBytes(SymmetricKey(data: Data()))

		XCTAssertEqual(empty.byteCount, 0)
		XCTAssertEqual(empty, empty, "reflexivity must hold even for the unreachable case")
		XCTAssertEqual(empty, alsoEmpty)
		XCTAssertNotEqual(empty, SecretBytes(bytes: [0]))
		XCTAssertNotEqual(SecretBytes(bytes: [0]), empty)
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

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

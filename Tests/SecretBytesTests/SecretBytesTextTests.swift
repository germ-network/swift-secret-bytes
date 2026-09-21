import Foundation
import XCTest

@testable import SecretBytes

final class SecretBytesTextTests: XCTestCase {
	func testTextRoundTripsLosslessly() throws {
		let text = "abc-123_XYZ.~+/="
		XCTAssertEqual(try SecretBytes(utf8: text).utf8String(), text)
	}

	func testTextRoundTripsMultiByteUTF8() throws {
		//not a credential shape, but the bridge is UTF-8, not ASCII-only
		let text = "tökén-💧"
		XCTAssertEqual(try SecretBytes(utf8: text).utf8String(), text)
	}

	func testEmptyTextIsRejected() throws {
		XCTAssertThrowsError(try SecretBytes(utf8: "")) { error in
			XCTAssertEqual(error as? SecretBytesError, .emptySecret)
		}
	}

	func testNonUTF8BytesRefuseMaterialization() throws {
		//0xFF is never a valid UTF-8 lead byte
		let secret = try SecretBytes(bytes: [0x41, 0xFF, 0x42])
		XCTAssertThrowsError(try secret.utf8String()) { error in
			XCTAssertEqual(error as? SecretBytesError, .notUTF8)
		}
	}

	func testMaterializingDoesNotExposeTheWrappedValue() throws {
		let secret = try SecretBytes(utf8: "super-secret-token")
		XCTAssertFalse("\(secret)".contains("super-secret-token"))
		XCTAssertEqual(secret.byteCount, 18)
	}
}

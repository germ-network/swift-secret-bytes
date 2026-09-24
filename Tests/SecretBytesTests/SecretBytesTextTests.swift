import Foundation
import Testing

@testable import SecretBytes

@Suite struct SecretBytesTextTests {
	@Test func textRoundTripsLosslessly() throws {
		let text = "abc-123_XYZ.~+/="
		#expect(try SecretBytes(utf8: text).utf8String() == text)
	}

	@Test func textRoundTripsMultiByteUTF8() throws {
		//not a credential shape, but the bridge is UTF-8, not ASCII-only
		let text = "tökén-💧"
		#expect(try SecretBytes(utf8: text).utf8String() == text)
	}

	@Test func emptyTextIsRejected() throws {
		#expect(throws: SecretBytesError.emptySecret) {
			try SecretBytes(utf8: "")
		}
	}

	@Test func nonUTF8BytesRefuseMaterialization() throws {
		//0xFF is never a valid UTF-8 lead byte
		let secret = try SecretBytes(bytes: [0x41, 0xFF, 0x42])
		#expect(throws: SecretBytesError.notUTF8) {
			try secret.utf8String()
		}
	}

	@Test func materializingDoesNotExposeTheWrappedValue() throws {
		let secret = try SecretBytes(utf8: "super-secret-token")
		#expect(!"\(secret)".contains("super-secret-token"))
		#expect(secret.byteCount == 18)
	}
}

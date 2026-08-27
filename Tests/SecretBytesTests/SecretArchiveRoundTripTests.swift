import XCTest

@testable import SecretBytes

final class SecretArchiveRoundTripTests: XCTestCase {
	private func sampleEpoch(labelLength: Int) -> Epoch {
		Epoch(
			index: 0x0102_0304_0506_0708,
			flags: 0xBEEF,
			key: SecretBytes(bytes: [UInt8](repeating: 0x5A, count: 32)),
			label: (0..<labelLength).map { UInt8($0 & 0xFF) },
			inner: Epoch.Inner(
				counter: 0xCAFE_BABE,
				secret: SecretBytes(bytes: [UInt8](repeating: 0xA5, count: 16))
			)
		)
	}

	func testArchiveRestoreRoundTrip() throws {
		let epoch = sampleEpoch(labelLength: 5)
		let archive = SecretArchive(archiving: epoch)
		let restored = try archive.restore(Epoch.self)
		XCTAssertEqual(restored, epoch)
	}

	func testRoundTripSurvivesBufferGrowth() throws {
		// A label large enough to force several capacity doublings past the
		// 64-byte initial reservation, proving append/realloc preserves bytes.
		let epoch = sampleEpoch(labelLength: 4096)
		let archive = SecretArchive(archiving: epoch)
		let restored = try archive.restore(Epoch.self)
		XCTAssertEqual(restored, epoch)
	}

	func testTrailingBytesRejected() throws {
		var writer = SecretArchive.Writer()
		writer.write(UInt64(1))
		writer.write(UInt16(2))
		writer.writeSecret(SecretBytes(bytes: [1, 2, 3]))
		writer.writeBytes([9, 9])
		writer.embed(
			SecretArchive(
				archiving: Epoch.Inner(counter: 1, secret: SecretBytes(bytes: [0])))
		)
		writer.write(UInt8(0xFF))  // one byte too many for Epoch's schema
		let archive = writer.finalize()
		XCTAssertThrowsError(try archive.restore(Epoch.self)) { error in
			XCTAssertEqual(error as? SecretArchiveError, .trailingBytes)
		}
	}

	func testTruncatedReadRejected() throws {
		var writer = SecretArchive.Writer()
		writer.write(UInt16(0x0102))  // only 2 bytes present
		let archive = writer.finalize()
		var reader = SecretArchive.Reader(archive)
		XCTAssertThrowsError(try reader.readUInt32()) { error in
			XCTAssertEqual(error as? SecretArchiveError, .truncated)
		}
	}

	func testSecretReadReconstructsExactLength() throws {
		var writer = SecretArchive.Writer()
		writer.write(UInt32(0x0102_0304))
		writer.writeSecret(SecretBytes(bytes: [0xAA, 0xBB, 0xCC]))
		writer.write(UInt8(0x7F))
		let archive = writer.finalize()
		var reader = SecretArchive.Reader(archive)
		XCTAssertEqual(try reader.readUInt32(), 0x0102_0304)
		let secret = try reader.readSecret()
		XCTAssertEqual(secret.byteCount, 3)  // exactly len, not the rest of the buffer
		XCTAssertEqual(secret.withUnsafeBytes { [UInt8]($0) }, [0xAA, 0xBB, 0xCC])
		XCTAssertEqual(try reader.readUInt8(), 0x7F)
		XCTAssertTrue(reader.isAtEnd)
	}
}

import XCTest

@testable import SecretBytes

final class WriterReaderFramingTests: XCTestCase {
	private func bytes(of archive: SecretArchive) -> [UInt8] {
		archive.withUnsafeBytes { [UInt8]($0) }
	}

	/// Locks the wire format: plain integers are fixed-width big-endian and
	/// unprefixed; secrets are varint-length-prefixed. This is what makes the
	/// secret/non-secret split visible at the call site.
	func testPlainIsUnprefixedSecretIsLengthPrefixed() throws {
		var writer = SecretArchive.Writer()
		writer.write(UInt32(0x0102_0304))
		writer.writeSecret(try SecretBytes(bytes: [0xAA, 0xBB]))
		let archive = writer.finalize()
		XCTAssertEqual(bytes(of: archive), [0x01, 0x02, 0x03, 0x04, 0x02, 0xAA, 0xBB])
	}

	func testMultiByteVarintLengthPrefix() {
		var writer = SecretArchive.Writer()
		writer.writeBytes([UInt8](repeating: 0x11, count: 200))
		let archive = writer.finalize()
		let raw = bytes(of: archive)
		// 200 = 0xC8 -> LEB128 [0xC8, 0x01], then 200 payload bytes.
		XCTAssertEqual(Array(raw.prefix(2)), [0xC8, 0x01])
		XCTAssertEqual(raw.count, 2 + 200)
	}

	func testPlainIntegerWidthsAndEndianness() throws {
		var writer = SecretArchive.Writer()
		writer.write(UInt8(0x7F))
		writer.write(UInt16(0x0102))
		writer.write(UInt32(0x0102_0304))
		writer.write(UInt64(0x0102_0304_0506_0708))
		let archive = writer.finalize()
		XCTAssertEqual(
			bytes(of: archive),
			[
				0x7F, 0x01, 0x02, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
				0x05, 0x06, 0x07, 0x08,
			]
		)

		var reader = SecretArchive.Reader(archive)
		XCTAssertEqual(try reader.readUInt8(), 0x7F)
		XCTAssertEqual(try reader.readUInt16(), 0x0102)
		XCTAssertEqual(try reader.readUInt32(), 0x0102_0304)
		XCTAssertEqual(try reader.readUInt64(), 0x0102_0304_0506_0708)
		XCTAssertTrue(reader.isAtEnd)
	}

	func testLengthPrefixBeyondRemainingRejected() throws {
		// Hand-built: a length prefix of 5 with only 1 byte following.
		let archive = SecretArchive(unsafeUninitializedCapacity: 2) { buffer, count in
			buffer[0] = 0x05
			buffer[1] = 0xAA
			count = 2
		}
		var reader = SecretArchive.Reader(archive)
		XCTAssertThrowsError(try reader.readSecret()) { error in
			XCTAssertEqual(error as? SecretArchiveError, .malformedLength)
		}
	}

	func testNonMinimalVarintRejected() throws {
		// 0x80 0x00 is a non-minimal encoding of 0.
		let archive = SecretArchive(unsafeUninitializedCapacity: 2) { buffer, count in
			buffer[0] = 0x80
			buffer[1] = 0x00
			count = 2
		}
		var reader = SecretArchive.Reader(archive)
		XCTAssertThrowsError(try reader.readBytes()) { error in
			XCTAssertEqual(error as? SecretArchiveError, .malformedLength)
		}
	}

	/// Zero-length *plain* byte fields remain legal and must round-trip — only
	/// zero-length *secrets* are prohibited (`SecretBytes` enforces a non-empty
	/// invariant at construction). The redesigned archive layer additionally
	/// rejects a zero-length secret field on decode, so the prohibition holds
	/// on the untrusted-input path without trapping.
	func testEmptyPlainBytesRoundTrips() throws {
		var writer = SecretArchive.Writer()
		writer.writeBytes([] as [UInt8])
		writer.write(UInt8(0x42))
		let archive = writer.finalize()
		var reader = SecretArchive.Reader(archive)
		XCTAssertEqual(try reader.readBytes(), [])
		XCTAssertEqual(try reader.readUInt8(), 0x42)
		XCTAssertTrue(reader.isAtEnd)
	}

}

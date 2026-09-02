import Crypto
import Foundation
import XCTest

@testable import SecretBytes

/// The decode path must **throw, never trap**, on any malformed input. These
/// build archives by hand, bypassing the encoder, so they can express bytes the
/// encoder would never emit.
final class ArchiveHostileInputTests: XCTestCase {
	private func archive(_ bytes: [UInt8]) throws -> SecretArchive {
		try SecretArchive(unsafeUninitializedCapacity: bytes.count) { buffer, count in
			bytes.withUnsafeBytes { buffer.copyMemory(from: $0) }
			count = bytes.count
		}
	}

	private func assertMalformed(
		_ bytes: [UInt8], _ message: String, file: StaticString = #filePath,
		line: UInt = #line
	) throws {
		XCTAssertThrowsError(
			try archive(bytes).decode(Probe.self), message, file: file, line: line
		) {
			let e = $0 as? SecretArchiveError
			XCTAssertTrue(
				e == .malformedArchive || e == .truncated || e == .trailingBytes,
				"expected a format error, got \(String(describing: $0))",
				file: file, line: line)
		}
	}

	private struct Probe: Codable { var a: Int }

	func testNonShortestHeadRejected() throws {
		// 0x18 0x05 encodes 5 in one argument byte; 5 fits inline, so it is
		// not the shortest form.
		try assertMalformed([0xA1, 0x61, 0x61, 0x18, 0x05], "non-shortest integer head")
	}

	func testIndefiniteLengthRejected() throws {
		try assertMalformed([0xBF, 0x61, 0x61, 0x01, 0xFF], "indefinite-length map")
	}

	func testTagRejected() throws {
		try assertMalformed([0xA1, 0x61, 0x61, 0xC0, 0x01], "tag")
	}

	func testUnsortedMapKeysRejected() throws {
		// {"b":1,"a":1} — "b" (0x6162) sorts after "a" (0x6161).
		try assertMalformed([0xA2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x01], "unsorted keys")
	}

	func testDuplicateMapKeysRejected() throws {
		try assertMalformed([0xA2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02], "duplicate keys")
	}

	func testInvalidUTF8Rejected() throws {
		// 0xFF is never valid UTF-8.
		try assertMalformed([0xA1, 0x61, 0xFF, 0x01], "invalid UTF-8 in a key")
	}

	func testFloat32Rejected() throws {
		try assertMalformed([0xA1, 0x61, 0x61, 0xFA, 0x3F, 0xC0, 0x00, 0x00], "float32")
	}

	func testNonCanonicalNaNRejected() throws {
		// NaN as float64 — must use the canonical 0xf97e00.
		try assertMalformed(
			[0xA1, 0x61, 0x61, 0xFB, 0x7F, 0xF8, 0, 0, 0, 0, 0, 0], "float64 NaN")
	}

	func testUndefinedRejected() throws {
		try assertMalformed([0xA1, 0x61, 0x61, 0xF7], "undefined simple value")
	}

	func testTrailingBytesRejected() throws {
		try assertMalformed(
			[0xA1, 0x61, 0x61, 0x01, 0x00], "trailing byte after the top-level item")
	}

	/// A length header claiming vastly more than the buffer holds must throw
	/// promptly, not allocate.
	func testLyingByteStringLengthRejected() throws {
		// 0x5B + 8-byte length of 2^60, with no payload.
		try assertMalformed(
			[0xA1, 0x61, 0x61, 0x5B, 0x10, 0, 0, 0, 0, 0, 0, 0],
			"byte string claiming 2^60")
	}

	func testLyingArrayCountRejected() throws {
		try assertMalformed(
			[0xA1, 0x61, 0x61, 0x9B, 0x10, 0, 0, 0, 0, 0, 0, 0],
			"array claiming 2^60 elements")
	}

	/// A map entry is a key *and* a value, so the tight bound is half the bytes
	/// remaining — not the full count an array may claim.
	func testLyingMapCountRejected() throws {
		try assertMalformed(
			[0xA1, 0x61, 0x61, 0xB8, 0xFF], "map claiming more entries than fit")
	}

	func testExcessiveNestingRejected() throws {
		// 65 nested arrays, one past the limit of 64.
		var bytes = [UInt8](repeating: 0x81, count: 65)
		bytes.append(0x01)
		try assertMalformed(bytes, "nesting past the depth limit")
	}

	/// Every proper prefix of a valid archive must throw rather than trap.
	func testTruncationSweep() throws {
		struct S: Codable {
			@SecretField var k: SecretBytes
			var n: Int
		}
		let full = try SecretArchive(
			encoding: S(
				k: try SecretBytes(bytes: [UInt8](repeating: 9, count: 32)), n: 1))
		let bytes = full.withUnsafeBytes { [UInt8]($0) }
		for cut in 1..<bytes.count {
			XCTAssertThrowsError(
				try archive(Array(bytes.prefix(cut))).decode(S.self),
				"prefix of length \(cut) should throw")
		}
	}
}

import Crypto
import Foundation
import XCTest

@testable import SecretBytes

/// Regressions for defects the stage-5 adversarial review found in the
/// initial Codable-archive implementation: each of these reproducibly failed
/// against the code as it landed, and each failure mode is distinct from what
/// the existing suites already cover.
final class ArchiveStage5RegressionTests: XCTestCase {
	/// Builds an archive directly from raw wire bytes, for hostile shapes the
	/// ordinary `Codable` funnel cannot produce (the encoder never emits an
	/// integer key outside `Int`'s range, or a non-canonical simple-value
	/// form).
	private func archive(_ bytes: [UInt8]) throws -> SecretArchive {
		try SecretArchive(unsafeUninitializedCapacity: bytes.count) { buffer, count in
			bytes.withUnsafeBytes { buffer.copyMemory(from: $0) }
			count = bytes.count
		}
	}

	// MARK: Float64 zero and subnormals (shortest-form wrongly applied to major 7)

	/// `CborHead.parse` used to apply the shortest-form rule to every major,
	/// including simple/float — but a float64 argument is a bit pattern, not
	/// a magnitude, so `0.0`'s all-zero pattern looked like it "should have"
	/// fit in the 0-byte immediate form and was rejected as non-shortest.
	/// The encoder always emits every non-NaN double as `0xFB` + 8 bytes (see
	/// `ArchiveSerializer.emit`), so this was encoder-produces,
	/// decoder-rejects — silent at seal time, discovered only on restore.
	func testZeroDoubleRoundTrips() throws {
		struct S: Codable, Equatable { var v: Double }
		let archive = try SecretArchive(encoding: S(v: 0.0))
		XCTAssertEqual(try archive.decode(S.self), S(v: 0.0))
	}

	func testZeroFloatRoundTrips() throws {
		struct S: Codable, Equatable { var v: Float }
		let archive = try SecretArchive(encoding: S(v: 0.0))
		XCTAssertEqual(try archive.decode(S.self), S(v: 0.0))
	}

	func testSubnormalDoubleRoundTrips() throws {
		struct S: Codable, Equatable { var v: Double }
		let archive = try SecretArchive(encoding: S(v: .leastNonzeroMagnitude))
		XCTAssertEqual(try archive.decode(S.self), S(v: .leastNonzeroMagnitude))
	}

	/// `Date` encodes as a single `Double` (seconds since the reference date),
	/// so the reference date itself — `0.0` — was exactly the value that
	/// couldn't be read back.
	func testDateAtReferenceEpochRoundTrips() throws {
		struct S: Codable { var d: Date }
		let a = try SecretArchive(encoding: S(d: Date(timeIntervalSinceReferenceDate: 0)))
		XCTAssertEqual(try a.decode(S.self).d.timeIntervalSinceReferenceDate, 0)
	}

	/// A non-canonical encoding of `false` — additional-info 24 (one-byte
	/// simple-value form) carrying 20, instead of the canonical inline form —
	/// must still be rejected now that the shortest-form check no longer
	/// covers major 7. Hand-built because the encoder never emits this form.
	func testNonCanonicalSimpleValueEncodingStillRejected() throws {
		struct S: Codable { var v: Bool }
		// a1 6176 f8 14   {"v": <one-byte-simple 0x14=20, i.e. non-canonical false>}
		let bytes: [UInt8] = [0xA1, 0x61, 0x76, 0xF8, 0x14]
		XCTAssertThrowsError(try archive(bytes).decode(S.self)) { error in
			XCTAssertEqual(error as? SecretArchiveError, .malformedArchive)
		}
	}

	// MARK: Large integers (Int64-narrowing traps instead of throwing)

	/// `UInt64` values above `Int64.max` — a hash fragment, a random nonce —
	/// used to be unreadable even into a field that could hold them, because
	/// decoding narrowed through `Int64` first.
	func testUInt64MaxRoundTrips() throws {
		struct S: Codable, Equatable { var v: UInt64 }
		let a = try SecretArchive(encoding: S(v: .max))
		XCTAssertEqual(try a.decode(S.self), S(v: .max))
	}

	/// A map key larger than `Int.max` used to abort the process inside
	/// `allKeys` (`Int(v)` traps on a `UInt64` that doesn't fit) — reachable
	/// through nothing more than stdlib `Dictionary.init(from:)`, which calls
	/// `allKeys` to enumerate every wire key regardless of `Key`'s type.
	/// Behind the AEAD, but the package's own hostile-input rule is
	/// throw-never-trap, and this is reachable from any counterparty who
	/// holds the sealing key (e.g. `SecretArchive.Embedded` from elsewhere).
	/// The key has no text representation, so it decodes to an empty
	/// dictionary rather than surfacing — the point is that it must not trap.
	func testOutOfRangeUnsignedMapKeyDoesNotTrapDictionaryDecode() throws {
		// a1 1b ffffffffffffffff 01   {18446744073709551615: 1}
		let bytes: [UInt8] = [
			0xA1, 0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
		]
		XCTAssertEqual(try archive(bytes).decode([String: Int].self), [:])
	}

	/// Same hazard on the negative side: a wire key of `-1 - UInt64.max`,
	/// which has no `Int64` representation at all.
	func testOutOfRangeNegativeMapKeyDoesNotTrapDictionaryDecode() throws {
		// a1 3b ffffffffffffffff 01   {-18446744073709551616: 1}
		let bytes: [UInt8] = [
			0xA1, 0x3B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
		]
		XCTAssertEqual(try archive(bytes).decode([String: Int].self), [:])
	}

	// MARK: superEncoder / superDecoder (used to silently drop fields)

	private class Base: Codable {
		var a: Int
		enum CodingKeys: CodingKey { case a }
		init(a: Int) { self.a = a }
		required init(from decoder: Decoder) throws {
			let c = try decoder.container(keyedBy: CodingKeys.self)
			a = try c.decode(Int.self, forKey: .a)
		}
		func encode(to encoder: Encoder) throws {
			var c = encoder.container(keyedBy: CodingKeys.self)
			try c.encode(a, forKey: .a)
		}
	}

	private final class Derived: Base {
		var b: Int
		enum CodingKeys: CodingKey { case b }
		init(a: Int, b: Int) {
			self.b = b
			super.init(a: a)
		}
		required init(from decoder: Decoder) throws {
			let c = try decoder.container(keyedBy: CodingKeys.self)
			b = try c.decode(Int.self, forKey: .b)
			try super.init(from: c.superDecoder())
		}
		override func encode(to encoder: Encoder) throws {
			var c = encoder.container(keyedBy: CodingKeys.self)
			try c.encode(b, forKey: .b)
			try super.encode(to: c.superEncoder())
		}
	}

	/// `superEncoder()` used to return the parent encoder itself; the parent
	/// container's own `container(keyedBy:)` call then *replaced* the
	/// subclass's map node instead of nesting under a `"super"` key, so
	/// `encode` succeeded and silently produced `{"a": 11}` — `b` vanished
	/// with no error raised anywhere.
	func testClassInheritanceEncodesBothLevelsThroughKeyedSuper() throws {
		let a = try SecretArchive(encoding: Derived(a: 11, b: 22))
		let restored = try a.decode(Derived.self)
		XCTAssertEqual(restored.a, 11)
		XCTAssertEqual(restored.b, 22)
	}

	private struct UnkeyedSuperCarrier: Codable, Equatable {
		var a: Int
		var b: Int
		var superValue: Int

		func encode(to encoder: Encoder) throws {
			var c = encoder.unkeyedContainer()
			try c.encode(a)
			try c.encode(b)
			var superContainer = c.superEncoder().singleValueContainer()
			try superContainer.encode(superValue)
		}

		init(a: Int, b: Int, superValue: Int) {
			self.a = a
			self.b = b
			self.superValue = superValue
		}

		init(from decoder: Decoder) throws {
			var c = try decoder.unkeyedContainer()
			a = try c.decode(Int.self)
			b = try c.decode(Int.self)
			let superContainer = try c.superDecoder().singleValueContainer()
			superValue = try superContainer.decode(Int.self)
		}
	}

	/// Same defect, unkeyed-container variant: `ArchiveUnkeyedContainer
	/// .superEncoder()` appended nothing to the array. Also exercises that
	/// `ArchiveSingleValueContainer` writes into a preset node in place
	/// rather than replacing it — `superEncoder` hands back an encoder
	/// pre-bound to a node it already inserted, and a single-value container
	/// is the shape most likely to orphan that reference by reassigning
	/// rather than mutating it.
	func testUnkeyedSuperEncoderRoundTrips() throws {
		let value = UnkeyedSuperCarrier(a: 1, b: 2, superValue: 99)
		let a = try SecretArchive(encoding: value)
		XCTAssertEqual(try a.decode(UnkeyedSuperCarrier.self), value)
	}

	// MARK: Encode-side duplicate key (was reported as a decode-side error)

	private struct DuplicateKeyWriter: Encodable {
		enum Keys: String, CodingKey { case a }
		func encode(to encoder: Encoder) throws {
			var c = encoder.container(keyedBy: Keys.self)
			try c.encode(1, forKey: .a)
			try c.encode(2, forKey: .a)
		}
	}

	/// A schema encoding the same key twice is a caller bug, not a wire-format
	/// defect — `.malformedArchive` is documented as describing untrusted
	/// bytes on parse, so this used to report the wrong case.
	func testEncodeSideDuplicateKeyReportsInternalFailure() throws {
		XCTAssertThrowsError(try SecretArchive(encoding: DuplicateKeyWriter())) { error in
			XCTAssertEqual(error as? SecretArchiveError, .internalEncodingFailure)
		}
	}
}

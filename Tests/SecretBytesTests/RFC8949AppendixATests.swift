import Foundation
import XCTest

@testable import SecretBytes

/// RFC 8949 Appendix A ("Examples of Encoded CBOR Data Items", Table 6)
/// against this package's own decoder — the one external check this suite had
/// been missing entirely. Every other vector file was hand-computed by the
/// same author as the encoder and asserted against that encoder's own output,
/// so a self-consistently wrong codec would pass all of it. These vectors
/// come from the standard, not from this codebase.
///
/// The table mixes items squarely inside the archive's deterministic-CBOR
/// subset with items the profile deliberately excludes (tags, indefinite
/// lengths, float16/float32 other than the canonical NaN, `undefined`, other
/// simple values). Both halves are pinned here: in-profile vectors must
/// decode to the exact value the RFC gives, and out-of-profile vectors must
/// be rejected — against the standard's own examples, not hand-built bytes.
///
/// Every hex string below was transcribed from the RFC 8949 text
/// (rfc-editor.org/rfc/rfc8949) and cross-checked against `ArchiveIndex`
/// before being sorted into these two buckets, so the split itself is a
/// verified fact about this implementation, not an assumption baked into the
/// test.
final class RFC8949AppendixATests: XCTestCase {
	private func bytes(_ hex: String) -> [UInt8] {
		var result = [UInt8]()
		result.reserveCapacity(hex.count / 2)
		var idx = hex.startIndex
		while idx < hex.endIndex {
			let next = hex.index(idx, offsetBy: 2)
			result.append(UInt8(hex[idx..<next], radix: 16)!)
			idx = next
		}
		return result
	}

	private func archive(_ hex: String) throws -> SecretArchive {
		let raw = bytes(hex)
		return try SecretArchive(unsafeUninitializedCapacity: raw.count) { buffer, count in
			raw.withUnsafeBytes { buffer.copyMemory(from: $0) }
			count = raw.count
		}
	}

	private func hex(_ archive: SecretArchive) -> String {
		archive.withUnsafeBytes { $0.map { String(format: "%02x", $0) }.joined() }
	}

	/// Every out-of-profile vector must fail the same way a hand-built
	/// hostile input does — `ArchiveIndex.build` throws before any target
	/// type is consulted, so the decode target here is arbitrary.
	private func assertRejected(
		_ hex: String, _ diagnostic: String, file: StaticString = #filePath,
		line: UInt = #line
	) throws {
		XCTAssertThrowsError(
			try archive(hex).decode(Int.self), diagnostic, file: file, line: line
		) {
			let e = $0 as? SecretArchiveError
			XCTAssertTrue(
				e == .malformedArchive || e == .truncated || e == .trailingBytes,
				"expected a format error for \(diagnostic), got \(String(describing: $0))",
				file: file, line: line)
		}
	}

	// MARK: - In-profile: integers

	/// Table 6's plain unsigned-integer rows, one per shortest-form width:
	/// inline (0, 1, 10, 23), one byte (24, 25, 100), two bytes (1000), four
	/// bytes (1000000), and eight bytes (1000000000000, and UInt64.max).
	func testAppendixAUnsignedIntegers() throws {
		let vectors: [(hex: String, value: UInt64)] = [
			("00", 0),
			("01", 1),
			("0a", 10),
			("17", 23),
			("1818", 24),
			("1819", 25),
			("1864", 100),
			("1903e8", 1000),
			("1a000f4240", 1_000_000),
			("1b000000e8d4a51000", 1_000_000_000_000),
			("1bffffffffffffffff", .max),
		]
		for (hex, value) in vectors {
			XCTAssertEqual(try archive(hex).decode(UInt64.self), value, hex)
		}
	}

	/// The negative-integer rows that fit `Int64` — CBOR's negative encoding
	/// (`-1-n`) is exercised across widths the same way the unsigned table is.
	func testAppendixANegativeIntegers() throws {
		let vectors: [(hex: String, value: Int64)] = [
			("20", -1),
			("29", -10),
			("3863", -100),
			("3903e7", -1000),
		]
		for (hex, value) in vectors {
			XCTAssertEqual(try archive(hex).decode(Int64.self), value, hex)
		}
	}

	/// `-18446744073709551616` (`0x3bffffffffffffffff`) is a shortest-form,
	/// untagged negative integer — structurally inside the profile, so
	/// `ArchiveIndex` accepts it — but its magnitude (2^64) exceeds every
	/// fixed-width integer type this package can decode into (`Int64.min` is
	/// only -2^63). The failure therefore surfaces one layer up, as a
	/// schema-level `DecodingError`, not a `SecretArchiveError`: exactly the
	/// split `SecretArchiveError`'s doc comment draws between format failures
	/// and "a missing key, a type mismatch, an out-of-range integer." This
	/// vector has no Decodable target in this package, so only rejection is
	/// asserted, never a decoded value.
	func testAppendixANegativeIntegerOverflowsEveryIntegerType() throws {
		let a = try archive("3bffffffffffffffff")
		XCTAssertThrowsError(try a.decode(Int64.self)) {
			XCTAssertTrue($0 is DecodingError)
		}
		XCTAssertThrowsError(try a.decode(UInt64.self)) {
			XCTAssertTrue($0 is DecodingError)
		}
	}

	/// Bignums (tag 2/3) are how the table represents integers beyond
	/// `UInt64`/`Int64` range, and every date/epoch/URI example is also
	/// tagged. Major type 6 is outside the profile unconditionally (see
	/// `CborMajor`'s doc comment), so all of these are rejected before their
	/// payload — a valid byte string, timestamp, or URI on its own — is even
	/// inspected.
	func testAppendixATagsRejected() throws {
		let vectors: [(hex: String, diagnostic: String)] = [
			("c249010000000000000000", "2(18446744073709551616) — bignum"),
			("c349010000000000000000", "3(-18446744073709551617) — negative bignum"),
			(
				"c074323031332d30332d32315432303a30343a30305a",
				"0(\"2013-03-21T20:04:00Z\")"
			),
			("c11a514b67b0", "1(1363896240)"),
			("c1fb41d452d9ec200000", "1(1363896240.5)"),
			("d74401020304", "23(h'01020304')"),
			("d818456449455446", "24(h'6449455446')"),
			(
				"d82076687474703a2f2f7777772e6578616d706c652e636f6d",
				"32(\"http://www.example.com\")"
			),
		]
		for (hex, diagnostic) in vectors {
			try assertRejected(hex, diagnostic)
		}
	}

	// MARK: - Floats

	/// The float profile is float64 for every value plus the single canonical
	/// NaN short form (`ArchiveIndex.parseFloat`'s doc comment). Every other
	/// float16 encoding in the table — including zero, negative zero, and
	/// values that fit float16 exactly like `1.0` — is a different wire form
	/// for a representable value, and every float32 encoding, is rejected:
	/// one value has exactly one accepted wire form. The non-canonical
	/// float64 NaN (`0xfb7ff8000000000000`) duplicates the byte pattern
	/// `ArchiveHostileInputTests.testNonCanonicalNaNRejected` already covers
	/// nested in a map; here it is asserted as the RFC's own bare top-level
	/// example.
	func testAppendixANonCanonicalFloatsRejected() throws {
		let vectors: [(hex: String, diagnostic: String)] = [
			("f90000", "0.0 (float16)"),
			("f98000", "-0.0 (float16)"),
			("f93c00", "1.0 (float16)"),
			("f93e00", "1.5 (float16)"),
			("f97bff", "65504.0 (float16)"),
			("fa47c35000", "100000.0 (float32)"),
			("fa7f7fffff", "3.4028234663852886e+38 (float32)"),
			("f90001", "5.960464477539063e-8 (float16)"),
			("f90400", "0.00006103515625 (float16)"),
			("f9c400", "-4.0 (float16)"),
			("f97c00", "Infinity (float16)"),
			("f9fc00", "-Infinity (float16)"),
			("fa7f800000", "Infinity (float32)"),
			("fa7fc00000", "NaN (float32)"),
			("faff800000", "-Infinity (float32)"),
			("fb7ff8000000000000", "NaN (float64, non-canonical)"),
		]
		for (hex, diagnostic) in vectors {
			try assertRejected(hex, diagnostic)
		}
	}

	/// Every non-NaN float64 head in the table decodes, infinities included —
	/// the profile only special-cases NaN (which must arrive as the canonical
	/// float16 form); `Double.infinity`/`-Double.infinity` are ordinary
	/// float64 values like any other.
	func testAppendixAFloat64() throws {
		let vectors: [(hex: String, value: Double)] = [
			("fb3ff199999999999a", 1.1),
			("fb7e37e43c8800759c", 1.0e+300),
			("fbc010666666666666", -4.1),
		]
		for (hex, value) in vectors {
			XCTAssertEqual(try archive(hex).decode(Double.self), value, hex)
		}
		XCTAssertEqual(try archive("fb7ff0000000000000").decode(Double.self), .infinity)
		XCTAssertEqual(try archive("fbfff0000000000000").decode(Double.self), -.infinity)
	}

	/// The one float16 wire form the profile accepts.
	func testAppendixACanonicalNaN() throws {
		XCTAssertTrue(try archive("f97e00").decode(Double.self).isNaN)
	}

	// MARK: - Bool, null, and the other simple values

	func testAppendixABoolAndNull() throws {
		XCTAssertEqual(try archive("f4").decode(Bool.self), false)
		XCTAssertEqual(try archive("f5").decode(Bool.self), true)
		XCTAssertNil(try archive("f6").decode(Int?.self))
	}

	/// `undefined` and every simple value other than false/true/null are
	/// outside the profile — `ArchiveIndex.parse`'s simple-value dispatch only
	/// recognizes additional-info 20/21/22; everything else, including the
	/// one-byte-argument form `simple(255)`, falls through to
	/// `parseFloat`'s rejection.
	func testAppendixAUndefinedAndSimpleValuesRejected() throws {
		try assertRejected("f7", "undefined")
		try assertRejected("f0", "simple(16)")
		try assertRejected("f8ff", "simple(255)")
	}

	// MARK: - Byte and text strings

	/// Includes both empty-string cases (`h''`, `""`) — structural minimums
	/// the rest of the suite never exercised on the decode side — and the
	/// three non-ASCII rows, which cover a two-, three-, and four-byte UTF-8
	/// sequence respectively.
	func testAppendixAByteAndTextStrings() throws {
		XCTAssertEqual(try archive("40").decode(Data.self), Data())
		XCTAssertEqual(try archive("4401020304").decode(Data.self), Data([1, 2, 3, 4]))
		XCTAssertEqual(try archive("60").decode(String.self), "")
		XCTAssertEqual(try archive("6161").decode(String.self), "a")
		XCTAssertEqual(try archive("6449455446").decode(String.self), "IETF")
		XCTAssertEqual(try archive("62225c").decode(String.self), "\"\\")
		XCTAssertEqual(try archive("62c3bc").decode(String.self), "\u{FC}")
		XCTAssertEqual(try archive("63e6b0b4").decode(String.self), "\u{6C34}")
		XCTAssertEqual(try archive("64f0908591").decode(String.self), "\u{10151}")
	}

	// MARK: - Arrays

	/// Includes the empty-array case (`[]`) the rest of the suite never
	/// exercised on the decode side.
	func testAppendixAArrays() throws {
		XCTAssertEqual(try archive("80").decode([Int].self), [])
		XCTAssertEqual(try archive("83010203").decode([Int].self), [1, 2, 3])
		XCTAssertEqual(
			try archive("98190102030405060708090a0b0c0d0e0f101112131415161718181819")
				.decode([Int].self),
			Array(1...25))
	}

	/// `[1, [2, 3], [4, 5]]` mixes integers and arrays with no single static
	/// Swift type — `Decodable` requires one, so `JSONish` stands in. This is
	/// the "wrapper" case the task allowance covers: the point is asserting
	/// the *value*, not merely that decoding succeeds, so a throwaway sum type
	/// is used rather than skipping the assertion.
	func testAppendixANestedHeterogeneousArray() throws {
		XCTAssertEqual(
			try archive("8301820203820405").decode(JSONish.self),
			.array([.int(1), .array([.int(2), .int(3)]), .array([.int(4), .int(5)])]))
	}

	// MARK: - Maps

	/// Includes the empty-map case (`{}`) the rest of the suite never
	/// exercised on the decode side, plus one map per key shape the format
	/// distinguishes: an opted-in integer-keyed struct, a text-keyed struct
	/// with a nested array value, and a five-entry text-keyed struct (the
	/// table's widest map). `{1: 2, 3: 4}` cannot decode into a bare
	/// `[Int: Int]`: the stdlib's own dictionary coding key never conforms to
	/// `ArchiveIntegerCodingKey` (integer wire keys are opt-in and never
	/// inferred — see that protocol's doc comment), so it would look for text
	/// keys "1" and "3" against a map that has none.
	func testAppendixAMaps() throws {
		XCTAssertEqual(try archive("a0").decode([String: Int].self), [:])

		struct OneThree: Decodable, Equatable {
			var one: Int
			var three: Int
			enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
				case one = 1
				case three = 3
			}
		}
		XCTAssertEqual(
			try archive("a201020304").decode(OneThree.self), OneThree(one: 2, three: 4))

		struct AB: Decodable, Equatable {
			var a: Int
			var b: [Int]
		}
		XCTAssertEqual(
			try archive("a26161016162820203").decode(AB.self), AB(a: 1, b: [2, 3]))

		struct FiveLetters: Decodable, Equatable {
			var a: String
			var b: String
			var c: String
			var d: String
			var e: String
		}
		XCTAssertEqual(
			try archive("a56161614161626142616361436164614461656145").decode(
				FiveLetters.self),
			FiveLetters(a: "A", b: "B", c: "C", d: "D", e: "E"))
	}

	/// `["a", {"b": "c"}]` — an array containing a map — round out the
	/// structural nesting cases the table offers beyond the pure-array one
	/// above.
	func testAppendixAArrayContainingMap() throws {
		struct BC: Decodable, Equatable { var b: String }
		XCTAssertEqual(
			try archive("826161a161626163").decode(JSONArrayOfStringOrMap.self),
			.init([.string("a"), .map(BC(b: "c"))]))
	}

	// MARK: - Indefinite length (out of profile)

	/// Every indefinite-length example in the table — byte string, text
	/// string, array, and map, nested at every position (outer indefinite
	/// with definite children, definite with indefinite children, and both) —
	/// is rejected. `CborHead.parse` rejects additional-info 31 uniformly
	/// regardless of major type, so this is one rule catching eleven
	/// syntactically different shapes.
	func testAppendixAIndefiniteLengthRejected() throws {
		let vectors: [(hex: String, diagnostic: String)] = [
			("5f42010243030405ff", "(_ h'0102', h'030405')"),
			("7f657374726561646d696e67ff", "(_ \"strea\", \"ming\")"),
			("9fff", "[_ ]"),
			("9f018202039f0405ffff", "[_ 1, [2, 3], [_ 4, 5]]"),
			("9f01820203820405ff", "[_ 1, [2, 3], [4, 5]]"),
			("83018202039f0405ff", "[1, [2, 3], [_ 4, 5]]"),
			("83019f0203ff820405", "[1, [_ 2, 3], [4, 5]]"),
			(
				"9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff",
				"[_ 1, 2, ..., 25]"
			),
			("bf61610161629f0203ffff", "{_ \"a\": 1, \"b\": [_ 2, 3]}"),
			("826161bf61626163ff", "[\"a\", {_ \"b\": \"c\"}]"),
			("bf6346756ef563416d7421ff", "{_ \"Fun\": true, \"Amt\": -2}"),
		]
		for (hex, diagnostic) in vectors {
			try assertRejected(hex, diagnostic)
		}
	}

	// MARK: - Encode-side: structural minimums

	/// The decode-side empty cases above (`{}`, `[]`, `h''`, `""`) confirm
	/// this codec's decoder agrees with the RFC's own minimal examples; these
	/// confirm the encoder does too, for every one of them the encoder can
	/// actually produce at the top level.
	func testEmptyContainersAndStringsEncodeToRFCBytes() throws {
		struct Empty: Codable {}
		XCTAssertEqual(hex(try SecretArchive(encoding: Empty())), "a0")
		XCTAssertEqual(hex(try SecretArchive(encoding: [Int]())), "80")
		XCTAssertEqual(hex(try SecretArchive(encoding: Data())), "40")
		XCTAssertEqual(hex(try SecretArchive(encoding: "")), "60")
	}
}

/// Stand-in for table rows whose value has no single Swift `Decodable`
/// mapping: RFC 8949 places integers and arrays in the same JSON-like array
/// with no static element type, and `Decodable` requires one.
private indirect enum JSONish: Decodable, Equatable {
	case int(Int64)
	case array([JSONish])

	init(from decoder: Decoder) throws {
		if let single = try? decoder.singleValueContainer(),
			let value = try? single.decode(Int64.self)
		{
			self = .int(value)
			return
		}
		self = .array(try [JSONish](from: decoder))
	}
}

/// Narrower stand-in for `["a", {"b": "c"}]`: an array whose elements are
/// either a string or a small fixed-shape map, rather than the fully general
/// `JSONish`.
private struct JSONArrayOfStringOrMap<Map: Decodable & Equatable>: Decodable, Equatable {
	enum Element: Decodable, Equatable {
		case string(String)
		case map(Map)

		init(from decoder: Decoder) throws {
			if let single = try? decoder.singleValueContainer(),
				let value = try? single.decode(String.self)
			{
				self = .string(value)
				return
			}
			self = .map(try Map(from: decoder))
		}
	}

	let elements: [Element]
	init(_ elements: [Element]) { self.elements = elements }
	init(from decoder: Decoder) throws { elements = try [Element](from: decoder) }
}

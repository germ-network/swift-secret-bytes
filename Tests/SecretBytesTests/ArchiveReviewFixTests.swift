import Crypto
import Foundation
import XCTest

@testable import SecretBytes

/// Regressions for the pre-freeze review pass. Each of these reproducibly
/// misbehaved before the fix, and each failure was *silent* — wrong output or
/// lost data with no error raised, which is the worst way a wire format can
/// fail.
final class ArchiveReviewFixTests: XCTestCase {
	private func archive(_ bytes: [UInt8]) throws -> SecretArchive {
		try SecretArchive(unsafeUninitializedCapacity: bytes.count) { buffer, count in
			bytes.withUnsafeBytes { buffer.copyMemory(from: $0) }
			count = bytes.count
		}
	}
	private func hex(_ archive: SecretArchive) -> String {
		archive.withUnsafeBytes { $0.map { String(format: "%02x", $0) }.joined() }
	}

	// MARK: Container-shape conflict (was: silent whole-field loss)

	private struct TwoContainerKinds: Encodable {
		enum Keys: String, CodingKey { case a, b }
		func encode(to encoder: Encoder) throws {
			var keyed = encoder.container(keyedBy: Keys.self)
			try keyed.encode(1, forKey: .a)
			var unkeyed = encoder.unkeyedContainer()
			try unkeyed.encode(2)
			try keyed.encode(3, forKey: .b)
		}
	}

	/// Asking one encoder for two container kinds used to produce `8102` —
	/// the array `[2]`. Both keyed fields vanished and the map silently became
	/// an array, with `encode` reporting success. `JSONEncoder` traps here;
	/// this package throws, because an aborting process is a worse answer than
	/// an error.
	func testConflictingContainerKindsThrowsRatherThanDroppingFields() throws {
		XCTAssertThrowsError(try SecretArchive(encoding: TwoContainerKinds())) { error in
			XCTAssertEqual(error as? SecretArchiveError, .internalEncodingFailure)
		}
	}

	private struct KeyedTwice: Encodable, Equatable {
		enum Keys: String, CodingKey { case a, b }
		func encode(to encoder: Encoder) throws {
			var first = encoder.container(keyedBy: Keys.self)
			try first.encode(1, forKey: .a)
			var second = encoder.container(keyedBy: Keys.self)
			try second.encode(2, forKey: .b)
		}
	}

	/// The legitimate neighbour of the case above, which must keep working:
	/// `Codable` permits requesting the *same* container kind twice, and both
	/// handles write into one map. Re-shaping the node on the second request
	/// would silently discard the first container's fields.
	func testRepeatedSameKindContainerKeepsBothFields() throws {
		//  a2  6161 01  6162 02   {"a": 1, "b": 2}
		XCTAssertEqual(
			hex(try SecretArchive(encoding: KeyedTwice())),
			"a2" + "6161" + "01" + "6162" + "02")
	}

	private struct KeyedThenSingleValue: Encodable {
		enum Keys: String, CodingKey { case a }
		func encode(to encoder: Encoder) throws {
			var keyed = encoder.container(keyedBy: Keys.self)
			try keyed.encode(1, forKey: .a)
			var single = encoder.singleValueContainer()
			try single.encode("clobber")
		}
	}

	/// The third route into the same defect, and the one that bypasses
	/// `box(shapedAs:)`: a single-value write onto an encoder that already
	/// handed out a map used to overwrite the entire container in place,
	/// producing `67636c6f62626572` — just the string — with the keyed field
	/// gone and no error.
	func testSingleValueAfterKeyedContainerThrows() throws {
		XCTAssertThrowsError(try SecretArchive(encoding: KeyedThenSingleValue())) { error in
			XCTAssertEqual(error as? SecretArchiveError, .internalEncodingFailure)
		}
	}

	private struct AbandonedContainer: Encodable {
		enum Keys: String, CodingKey { case a }
		func encode(to encoder: Encoder) throws {
			var keyed = encoder.container(keyedBy: Keys.self)
			try keyed.encode(1, forKey: .a)
			var unkeyed = encoder.unkeyedContainer()
			try unkeyed.encode(2)
		}
	}

	/// The conflict must be caught when the second container is *requested*,
	/// not merely when a later write lands on a re-shaped node. Without this
	/// the request-time check was unpinned: reverting it entirely still left
	/// the whole suite green, because the only conflict test in it happened to
	/// fail through a redundant guard on a third write that this shape never
	/// makes.
	func testAbandonedConflictingContainerStillThrows() throws {
		XCTAssertThrowsError(try SecretArchive(encoding: AbandonedContainer())) { error in
			XCTAssertEqual(error as? SecretArchiveError, .internalEncodingFailure)
		}
	}

	// MARK: An encoded nil is a value, not an empty slot

	private struct NilThenKeyed: Encodable {
		enum Keys: String, CodingKey { case a }
		func encode(to encoder: Encoder) throws {
			var single = encoder.singleValueContainer()
			try single.encodeNil()
			var keyed = encoder.container(keyedBy: Keys.self)
			try keyed.encode(1, forKey: .a)
		}
	}

	private struct NilThenValue: Encodable {
		func encode(to encoder: Encoder) throws {
			var single = encoder.singleValueContainer()
			try single.encodeNil()
			try single.encode(true)
		}
	}

	/// `superEncoder`'s unwritten placeholder and an explicitly encoded nil
	/// were the same node state, so an encoded nil looked like an empty slot
	/// and was silently overwritten: this produced `a1616101` — the map alone,
	/// the nil gone, no error.
	func testEncodedNilThenContainerThrows() throws {
		XCTAssertThrowsError(try SecretArchive(encoding: NilThenKeyed())) { error in
			XCTAssertEqual(error as? SecretArchiveError, .internalEncodingFailure)
		}
	}

	/// The same conflation made the single-value guard order-dependent:
	/// `encode(true); encode(false)` was caught while `encodeNil(); encode(true)`
	/// was not.
	func testEncodedNilThenValueThrows() throws {
		XCTAssertThrowsError(try SecretArchive(encoding: NilThenValue())) { error in
			XCTAssertEqual(error as? SecretArchiveError, .internalEncodingFailure)
		}
	}

	// MARK: superEncoder(forKey:) — the untested sibling

	private final class Base: Codable {
		var a: Int
		enum CodingKeys: CodingKey { case a }
		init(a: Int) { self.a = a }
		init(from decoder: Decoder) throws {
			a = try decoder.container(keyedBy: CodingKeys.self).decode(
				Int.self, forKey: .a)
		}
		func encode(to encoder: Encoder) throws {
			var c = encoder.container(keyedBy: CodingKeys.self)
			try c.encode(a, forKey: .a)
		}
	}

	private struct KeyedSuper: Codable, Equatable {
		var b: Int
		var inner: Int
		enum CodingKeys: String, CodingKey { case b, sub }

		init(b: Int, inner: Int) {
			self.b = b
			self.inner = inner
		}

		func encode(to encoder: Encoder) throws {
			var c = encoder.container(keyedBy: CodingKeys.self)
			try c.encode(b, forKey: .b)
			try Base(a: inner).encode(to: c.superEncoder(forKey: .sub))
		}

		init(from decoder: Decoder) throws {
			let c = try decoder.container(keyedBy: CodingKeys.self)
			b = try c.decode(Int.self, forKey: .b)
			inner = try Base(from: try c.superDecoder(forKey: .sub)).a
		}
	}

	/// `superEncoder(forKey:)` had no coverage at all: disconnecting its child
	/// node entirely — whole-object loss, the sibling of a defect an earlier
	/// review already fixed in the no-argument overload — left the suite green.
	func testSuperEncoderForKeyDeliversItsPayload() throws {
		let value = KeyedSuper(b: 7, inner: 42)
		let encoded = try SecretArchive(encoding: value)
		//  a2  6162 07  6373756201 …  {"b": 7, "sub": {"a": 42}}
		XCTAssertEqual(
			hex(encoded), "a2" + "6162" + "07" + "63737562" + "a1" + "6161" + "182a")
		XCTAssertEqual(try encoded.decode(KeyedSuper.self), value)
	}

	private struct ConflictInsideSuper: Encodable {
		enum Keys: String, CodingKey { case sub }
		struct Inner: Encodable {
			enum K: String, CodingKey { case a }
			func encode(to encoder: Encoder) throws {
				var keyed = encoder.container(keyedBy: K.self)
				try keyed.encode(1, forKey: .a)
				var unkeyed = encoder.unkeyedContainer()
				try unkeyed.encode(2)
			}
		}
		func encode(to encoder: Encoder) throws {
			var c = encoder.container(keyedBy: Keys.self)
			try Inner().encode(to: c.superEncoder(forKey: .sub))
		}
	}

	/// A violation inside a `superEncoder` child must reach the top: the
	/// failure box is shared by reference precisely so a child cannot record
	/// one where nobody looks.
	func testConflictInsideSuperEncoderSurfaces() throws {
		XCTAssertThrowsError(try SecretArchive(encoding: ConflictInsideSuper())) { error in
			XCTAssertEqual(error as? SecretArchiveError, .internalEncodingFailure)
		}
	}

	// MARK: Integer-keyed schemas no longer answer to text keys

	private struct IntKeyed: Codable, Equatable {
		var kty: Int
		enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey { case kty = 1 }
	}

	/// An integer-keyed schema used to *also* match the case name Swift
	/// synthesises for it, so `{"kty": 9}` decoded as `IntKeyed(kty: 9)` even
	/// though the encoder emits only `a10109`. Two wire forms for one value,
	/// and a shadowing channel into exactly the COSE_Key shape integer keying
	/// exists to serve.
	func testIntegerKeyedSchemaRejectsTextAlias() throws {
		//  a1 63 6b7479 09   {"kty": 9}
		let bytes: [UInt8] = [0xA1, 0x63, 0x6B, 0x74, 0x79, 0x09]
		XCTAssertThrowsError(try archive(bytes).decode(IntKeyed.self)) { error in
			guard case DecodingError.keyNotFound = error else {
				return XCTFail("expected keyNotFound, got \(error)")
			}
		}
	}

	/// The integer form still decodes, and round-trips byte-stably — the
	/// property the fix exists to protect, not merely a rejection.
	func testIntegerKeyedSchemaRoundTripsByteStably() throws {
		let value = IntKeyed(kty: 9)
		let encoded = try SecretArchive(encoding: value)
		XCTAssertEqual(hex(encoded), "a1" + "01" + "09")
		XCTAssertEqual(try encoded.decode(IntKeyed.self), value)
	}

	/// A key with no `intValue` inside an opted-in schema still rides text, so
	/// the decoder must mirror the encoder rather than assume every key in an
	/// integer-keyed type is an integer.
	func testOptedInSchemaStillMatchesItsTextKeys() throws {
		struct Mixed: Codable, Equatable {
			var numbered: Int
			var named: Int
			enum CodingKeys: String, CodingKey, ArchiveIntegerCodingKey {
				case numbered, named
				var intValue: Int? { self == .numbered ? 1 : nil }
				init?(intValue: Int) { self = .numbered }
			}
		}
		let value = Mixed(numbered: 4, named: 5)
		let encoded = try SecretArchive(encoding: value)
		XCTAssertEqual(try encoded.decode(Mixed.self), value)
	}

	// MARK: Canonically-equivalent text keys (was: silent entry loss)

	/// `String ==` is canonical equivalence, so "é" as U+00E9 and as
	/// U+0065 U+0301 are byte-distinct, sort correctly, and are the same
	/// `String`. A map holding both decoded into a `[String: Int]` of **one**
	/// entry — two keys in, one out, no error. The encoder cannot produce
	/// such a map, so rejecting it costs nothing real.
	func testCanonicallyEquivalentTextKeysRejected() throws {
		//  a2  62 c3a9 01  63 65cc81 02   {"é"(NFC): 1, "é"(NFD): 2}
		let bytes: [UInt8] = [
			0xA2, 0x62, 0xC3, 0xA9, 0x01, 0x63, 0x65, 0xCC, 0x81, 0x02,
		]
		XCTAssertThrowsError(try archive(bytes).decode([String: Int].self)) { error in
			XCTAssertEqual(error as? SecretArchiveError, .malformedArchive)
		}
	}

	/// The guard must not fire on ordinary distinct keys, including non-ASCII
	/// ones that merely share a prefix.
	func testDistinctNonASCIIKeysStillDecode() throws {
		let value = ["é": 1, "e": 2, "水": 3]
		let encoded = try SecretArchive(encoding: value)
		XCTAssertEqual(try encoded.decode([String: Int].self), value)
	}

	// MARK: A leading BOM is a character, not whitespace to strip

	/// `String(bytes:encoding:.utf8)` (Foundation) silently drops a leading
	/// U+FEFF; `String(validating:as:)` (stdlib), used for every other text
	/// decode in this file, does not. Used to decode `{"\u{FEFF}x": 1}` as
	/// `["x": 1]` — a key rename with no error.
	func testBOMPrefixedKeyIsNotStripped() throws {
		//  a1  64 efbbbf78  01     {"\u{FEFF}x": 1}
		let bytes: [UInt8] = [0xA1, 0x64, 0xEF, 0xBB, 0xBF, 0x78, 0x01]
		XCTAssertEqual(try archive(bytes).decode([String: Int].self), ["\u{FEFF}x": 1])
	}

	/// A key and its BOM-prefixed twin are distinct strings and must both
	/// survive. Used to seal cleanly and throw `.malformedArchive` on every
	/// decode: `"x"` validated fine, `"\u{FEFF}x"` materialized as `"x"`, so
	/// the map decoded as two entries under one key — the same emit/reject
	/// split as the canonical-equivalence case above, from the opposite
	/// direction (the archive was well-formed; only decode disagreed with
	/// itself about what it had already validated).
	func testBOMPrefixedKeyDistinctFromBareKey() throws {
		//  a2  6178 02  64 efbbbf78 01     {"x": 2, "\u{FEFF}x": 1}  (canonical
		//  order: "x"'s encoding is bytewise less than "\u{FEFF}x"'s)
		let bytes: [UInt8] = [
			0xA2, 0x61, 0x78, 0x02, 0x64, 0xEF, 0xBB, 0xBF, 0x78, 0x01,
		]
		XCTAssertEqual(
			try archive(bytes).decode([String: Int].self),
			["x": 2, "\u{FEFF}x": 1])
	}

	private struct BOMPrefixedKey: Codable, Equatable {
		struct AnyKey: CodingKey {
			var stringValue: String
			init(_ s: String) { stringValue = s }
			init?(stringValue s: String) { stringValue = s }
			var intValue: Int? { nil }
			init?(intValue: Int) { nil }
		}
		var value: Int
		init(value: Int) { self.value = value }
		func encode(to encoder: Encoder) throws {
			var c = encoder.container(keyedBy: AnyKey.self)
			try c.encode(value, forKey: AnyKey("\u{FEFF}v"))
		}
		init(from decoder: Decoder) throws {
			let c = try decoder.container(keyedBy: AnyKey.self)
			value = try c.decode(Int.self, forKey: AnyKey("\u{FEFF}v"))
		}
	}

	/// The keyed-container lookup path, not just raw `[String: V]` decode.
	/// Used to throw `keyNotFound`: the map's stored key validated and
	/// materialized as `"v"` (BOM stripped), so a lookup for the literal
	/// `"\u{FEFF}v"` `CodingKey` the encoder actually wrote never matched.
	func testBOMPrefixedKeyRoundTripsThroughKeyedContainer() throws {
		let value = BOMPrefixedKey(value: 42)
		let encoded = try SecretArchive(encoding: value)
		XCTAssertEqual(try encoded.decode(BOMPrefixedKey.self), value)
	}

	// MARK: The encoder never mints what the decoder refuses

	private struct BothNormalizations: Encodable {
		struct AnyKey: CodingKey {
			var stringValue: String
			init(_ s: String) { stringValue = s }
			init?(stringValue s: String) { stringValue = s }
			var intValue: Int? { nil }
			init?(intValue: Int) { nil }
		}
		func encode(to encoder: Encoder) throws {
			var c = encoder.container(keyedBy: AnyKey.self)
			try c.encode(1, forKey: AnyKey("\u{00E9}"))  // NFC "é"
			try c.encode(2, forKey: AnyKey("e\u{0301}"))  // NFD "é"
		}
	}

	/// The decoder rejects canonically-equivalent text keys, so the encoder
	/// must refuse to produce them. It used to emit `a262c3a9016365cc8102`
	/// happily — an archive that seals cleanly and then throws
	/// `malformedArchive` on every attempt to read it back. Data lost at rest,
	/// the same emit/reject split that once made float64 zero unreadable.
	///
	/// A hand-written `CodingKey` is all it takes, which is why "the encoder
	/// cannot produce such a map" was the wrong reason to guard only one side.
	func testEncoderRejectsCanonicallyEquivalentKeys() throws {
		XCTAssertThrowsError(try SecretArchive(encoding: BothNormalizations())) { error in
			XCTAssertEqual(error as? SecretArchiveError, .internalEncodingFailure)
		}
	}

	// MARK: Float narrowing may lose precision, never magnitude

	/// `Float(1e300)` is `+inf` — not a lossy narrowing but a different value,
	/// and it used to arrive silently. Precision loss stays allowed, matching
	/// `JSONDecoder`; magnitude loss does not.
	func testFiniteDoubleOverflowingFloatThrows() throws {
		struct FloatField: Codable { var v: Float }
		let stored = try SecretArchive(encoding: ["v": 1e300])
		XCTAssertThrowsError(try stored.decode(FloatField.self))

		// Precision-only narrowing still decodes.
		let precise = try SecretArchive(encoding: ["v": 0.1])
		XCTAssertEqual(try precise.decode(FloatField.self).v, Float(0.1))

		// A stored infinity is itself, not an overflow.
		let infinite = try SecretArchive(encoding: ["v": Double.infinity])
		XCTAssertEqual(try infinite.decode(FloatField.self).v, .infinity)
	}

	// MARK: allKeys agrees with contains

	/// `allKeys` listed a text wire key that `contains` denied and
	/// `decodeNil(forKey:)` then reported as an explicit null — so a decoder
	/// driven by `allKeys` read a phantom entry as a legitimately encoded nil.
	func testAllKeysAgreesWithContainsForIntegerKeyedSchema() throws {
		struct Probe: Decodable {
			let keys: [String]
			let contains: Bool
			let nilThrew: Bool
			init(from decoder: Decoder) throws {
				let c = try decoder.container(keyedBy: IntKeyed.CodingKeys.self)
				keys = c.allKeys.map(\.stringValue)
				contains = c.contains(.kty)
				nilThrew = (try? c.decodeNil(forKey: .kty)) == nil
			}
		}
		//  a1 63 6b7479 09   {"kty": 9} — the text spelling of an integer key
		let probe = try archive([0xA1, 0x63, 0x6B, 0x74, 0x79, 0x09]).decode(Probe.self)
		XCTAssertEqual(probe.keys, [], "a key contains() denies must not be listed")
		XCTAssertFalse(probe.contains)
		XCTAssertTrue(probe.nilThrew, "an absent key is keyNotFound, not an encoded nil")
	}

	// MARK: The older guards the newer ones quietly narrowed

	private struct DuplicateIntegerKey: Encodable {
		enum Keys: Int, CodingKey, ArchiveIntegerCodingKey { case only = 1 }
		func encode(to encoder: Encoder) throws {
			var c = encoder.container(keyedBy: Keys.self)
			try c.encode(1, forKey: .only)
			try c.encode(2, forKey: .only)
		}
	}

	/// Adding the canonical-equivalence guard silently took over the older
	/// byte-duplicate check's job *for text keys* — `String ==` implies byte
	/// equality — leaving that check's only remaining responsibility, integer
	/// keys, untested. Deleting it left the whole suite green while the
	/// encoder emitted `a2 01 01 01 02` (`{1: 1, 1: 2}`), which the decoder
	/// rejects: one mutation away from another emit/reject split, in the
	/// COSE_Key case integer keying exists for.
	func testDuplicateIntegerKeysRejectedAtEncode() throws {
		XCTAssertThrowsError(try SecretArchive(encoding: DuplicateIntegerKey())) { error in
			XCTAssertEqual(error as? SecretArchiveError, .internalEncodingFailure)
		}
	}

	/// The guard tested directly, below the archive entry point.
	///
	/// `testDuplicateIntegerKeysRejectedAtEncode` goes through
	/// `SecretArchive(encoding:)`, where the DEBUG self-validation also rejects
	/// this — so deleting the serializer's own byte-duplicate check left that
	/// test green. The self-validation is a net for tests, not a release
	/// guarantee: it is compiled out of release builds, where only this guard
	/// stands between a duplicate key and the wire. Driving the serializer
	/// directly is what actually pins it.
	func testSerializerItselfRejectsDuplicateIntegerKeys() throws {
		let map = ArchiveNode(
			.map([
				(key: .uint(1), value: ArchiveNode(.uint(1))),
				(key: .uint(1), value: ArchiveNode(.uint(2))),
			]))
		XCTAssertThrowsError(try ArchiveSerializer.size(map)) { error in
			XCTAssertEqual(error as? SecretArchiveError, .internalEncodingFailure)
		}
	}

	/// The decode-side mirror. `testDuplicateMapKeysRejected` uses *text* keys,
	/// so after the new guard landed it no longer exercised `strictlyAscending`
	/// at all — replacing that comparison's result wholesale kept the suite
	/// green and made the decoder accept `a2 0101 0102`.
	func testDuplicateIntegerKeysRejectedAtDecode() throws {
		//  a2  01 01  01 02   {1: 1, 1: 2}
		let bytes: [UInt8] = [0xA2, 0x01, 0x01, 0x01, 0x02]
		XCTAssertThrowsError(try archive(bytes).decode([String: Int].self)) { error in
			XCTAssertEqual(error as? SecretArchiveError, .malformedArchive)
		}
	}

	/// Out-of-order integer keys, likewise — the ordering half of the same
	/// comparison, also uncovered once text keys stopped reaching it.
	func testUnsortedIntegerKeysRejectedAtDecode() throws {
		//  a2  02 01  01 02   {2: 1, 1: 2} — descending, so not canonical
		let bytes: [UInt8] = [0xA2, 0x02, 0x01, 0x01, 0x02]
		XCTAssertThrowsError(try archive(bytes).decode([String: Int].self)) { error in
			XCTAssertEqual(error as? SecretArchiveError, .malformedArchive)
		}
	}

	// MARK: An unused superEncoder slot — the one new wire-visible behavior

	private struct UnusedKeyedSuper: Encodable {
		enum Keys: String, CodingKey { case a, sub }
		func encode(to encoder: Encoder) throws {
			var c = encoder.container(keyedBy: Keys.self)
			try c.encode(1, forKey: .a)
			_ = c.superEncoder(forKey: .sub)  // requested, never written to
		}
	}

	private struct UnusedUnkeyedSuper: Encodable {
		func encode(to encoder: Encoder) throws {
			var c = encoder.unkeyedContainer()
			try c.encode(1)
			_ = c.superEncoder()  // requested, never written to
			try c.encode(3)
		}
	}

	/// `.unset` is the placeholder a `superEncoder` leaves behind, and if the
	/// caller never writes to it, it reaches the serializer. Nothing pinned
	/// what it emits there: making `size` and `emit` disagree about its width
	/// (a genuine sizing/fill desync) and making it emit `false` instead of
	/// null both left the suite green.
	func testUnusedKeyedSuperEncoderSlotEmitsNull() throws {
		//  a2  6161 01  63737562 f6   {"a": 1, "sub": null}
		XCTAssertEqual(
			hex(try SecretArchive(encoding: UnusedKeyedSuper())),
			"a2" + "6161" + "01" + "63737562" + "f6")
	}

	func testUnusedUnkeyedSuperEncoderSlotEmitsNull() throws {
		//  83  01  f6  03   [1, null, 3]
		XCTAssertEqual(
			hex(try SecretArchive(encoding: UnusedUnkeyedSuper())),
			"83" + "01" + "f6" + "03")
	}

	// MARK: Container encoding is linear, not quadratic

	/// `case .array(var items) = node.kind` used to leave the node's own
	/// payload referencing the same buffer, so every append copy-on-wrote the
	/// whole array: 16k elements took ~500 ms and the curve was 4× time per
	/// 2× length. This asserts the shape of the curve rather than a wall-clock
	/// threshold, so it stays meaningful on slower machines.
	///
	/// **Not run on the simulator.** A shared CI runner measured 37× here
	/// with the fix in place — worse than the ~16× a genuine quadratic
	/// regression produces, so the reading was environmental, not algorithmic
	/// (the same job took 13 minutes against 6 for its sibling leg). On real
	/// hardware the curve is clean: 2× elements costs 2.02× time, flat from
	/// 4k to 64k. A ratio test cannot survive a host that pauses the process
	/// mid-measurement, and no threshold rescues it — loosening the bar past
	/// 37× would stop detecting the defect. The property under test is a
	/// property of the algorithm, not of the platform, so measuring it where
	/// the clock is trustworthy loses nothing.
	func testLargeArrayEncodingScalesLinearly() throws {
		#if targetEnvironment(simulator)
			throw XCTSkip("timing ratios are not measurable on a shared simulator host")
		#endif
		try assertLinearScaling { count in
			[UInt8](repeating: 0x11, count: count)
		}
	}

	/// The identical hazard in `ArchiveKeyedContainer.put`, which was unpinned:
	/// deleting *its* `node.kind = .null` left the whole suite green while a
	/// `[String: Int]` degraded to a ~12× ratio for 4× the entries. Arrays and
	/// maps are separate code paths, and a dictionary is the larger container
	/// in practice.
	func testLargeDictionaryEncodingScalesLinearly() throws {
		#if targetEnvironment(simulator)
			throw XCTSkip("timing ratios are not measurable on a shared simulator host")
		#endif
		try assertLinearScaling { count in
			Dictionary(uniqueKeysWithValues: (0..<count).map { ("k\($0)", $0) })
		}
	}

	/// Asserts the *shape* of the curve rather than a wall-clock threshold, so
	/// it survives a slow machine: quadratic growth at 4× the elements is ~16×
	/// the time, linear is ~4×, and the bar sits between them.
	private func assertLinearScaling<T: Encodable>(
		_ make: (Int) -> T, file: StaticString = #filePath, line: UInt = #line
	) throws {
		func encodeSeconds(count: Int) throws -> Double {
			let value = make(count)
			let start = ProcessInfo.processInfo.systemUptime
			_ = try SecretArchive(encoding: value)
			return ProcessInfo.processInfo.systemUptime - start
		}
		_ = try encodeSeconds(count: 2000)  // warm up
		let small = try encodeSeconds(count: 8000)
		let large = try encodeSeconds(count: 32000)
		let floor = 0.0005  // ignore timer noise on very fast runs
		XCTAssertLessThan(
			large, max(small, floor) * 10,
			"4× the elements took \(large / max(small, floor))× the time — "
				+ "encoding looks quadratic again",
			file: file, line: line)
	}

}

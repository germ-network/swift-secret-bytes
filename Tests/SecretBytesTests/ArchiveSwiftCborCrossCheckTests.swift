import Foundation
import SwiftCbor
import XCTest

@testable import SecretBytes

/// Cross-checks this package's hand-rolled CBOR encoder against swift-cbor —
/// an independent, external implementation — closing the other half of the
/// gap `RFC8949AppendixATests` opened. That file proves the decoder agrees
/// with the standard's own examples; this file proves the *encoder*'s output
/// is real, standard CBOR by having a second implementation read it, and
/// (where possible) reproduce it byte for byte.
///
/// swift-cbor is test-only (see `Package.swift`): it is never a dependency of
/// the `SecretBytes` library product.
///
/// One constraint shapes everything here: secret fields encode as CBOR byte
/// strings, and the entire point of this package is that plaintext secrets
/// never leave zeroizing storage. So value-level cross-checks below use
/// archives built from non-secret fields only. The one secret-bearing archive
/// this file does cross-check (`CoseKey`) is asserted *structurally* —
/// swift-cbor sees a byte string of the right length at the right key — and
/// never by extracting this package's own secret plaintext (`withSecretBytes`)
/// for a value comparison, which would be the exact custody violation the
/// package exists to prevent.
///
/// The honest qualifier: `rawData(_:)` copies a whole archive out of
/// zeroizing storage into an ordinary `Data`, secret bytes included, because
/// swift-cbor's entry points take `Data` and no narrower seam exists. That is
/// a **test-only transient over test constants** — never a pattern for
/// adopters, and the reason this file's secret fixture is `0xAB`-filled
/// rather than a real key. It is a compromise, not an invariant this file
/// upholds.
final class ArchiveSwiftCborCrossCheckTests: XCTestCase {
	private func hex(_ archive: SecretArchive) -> String {
		archive.withUnsafeBytes { $0.map { String(format: "%02x", $0) }.joined() }
	}
	private func hex(_ data: Data) -> String {
		data.map { String(format: "%02x", $0) }.joined()
	}
	private func rawData(_ archive: SecretArchive) -> Data {
		archive.withUnsafeBytes { Data($0) }
	}

	/// **Not** `CborEncoder.Options.deterministicCbor` — that preset composes
	/// `.lexicographicallySortedMapKeys` with `.shortestFloatingPointEncoding`
	/// (RFC 8949 §4.2.1's core determinism, width-minimal like every other
	/// numeric field). This archive follows the *different* application
	/// profile in §4.2.2 instead — Rule 3, float64 for every value, no
	/// float16/float32 shortcut for values that would fit. Not a stricter
	/// profile: §4.2.1 says plainly that Rule 3 does not use preferred
	/// serialization. `.floatingPoint64Only` is swift-cbor's
	/// equivalent of that choice. `testBuiltinDeterministicPresetDivergesOnFloats`
	/// below pins the difference with real bytes so this substitution doesn't
	/// silently rot back to the wrong preset.
	private let reencodeOptions: CborEncoder.Options = [
		.lexicographicallySortedMapKeys, .floatingPoint64Only,
	]

	// MARK: - Representative non-secret archive: value agreement + byte-identical re-encode

	private struct Inner: Codable, Equatable {
		var n: Int
		var tags: [String]
	}

	/// One archive touching every shape the task's representative set asks
	/// for: a large `UInt64`, `Int64.min`, non-ASCII text, a `Data` byte
	/// string, `0.0`, a present and an absent optional, and nested
	/// arrays/maps. No secret fields, so both directions of the cross-check —
	/// decoding with swift-cbor into this exact type, and re-encoding what it
	/// decoded — are available (see the file doc comment for why secret
	/// fields cannot use either).
	private struct Fixture: Codable, Equatable {
		var hugeUnsigned: UInt64
		var mostNegative: Int64
		var text: String
		var blob: Data
		var zero: Double
		var present: Int?
		var absent: Int?
		var nested: [Inner]
		var meta: [String: Int]
	}

	private let fixture = Fixture(
		hugeUnsigned: .max,
		mostNegative: .min,
		text: "水",
		blob: Data([0xDE, 0xAD, 0xBE, 0xEF]),
		zero: 0.0,
		present: 7,
		absent: nil,
		nested: [Inner(n: 1, tags: ["a", "b"]), Inner(n: 2, tags: [])],
		meta: ["y": 2, "x": 1])

	/// Every strictness rule this archive claims, expressed as swift-cbor's
	/// own decoder options. `.stringMapKeysOnly` is deliberately absent —
	/// integer map keys are the point of `ArchiveIntegerCodingKey` — and
	/// `.shortestFloatingPointEncoding` is replaced by `.floatingPoint64Only`
	/// for the profile reason given on `reencodeOptions`.
	///
	/// This is the half of the oracle that matters most. Decoding with the
	/// *default* options only shows an external implementation can read our
	/// bytes; decoding with these shows it judges them *canonical*. Without
	/// it nothing outside this package ever asserted that our heads are
	/// minimally encoded or our map keys correctly sorted.
	private let strictOptions: CborDecoder.Options = [
		.minimalArgumentEncoding, .definiteLengthItems,
		.lexicographicallySortedMapKeys, .floatingPoint64Only,
		.basicSimpleValuesOnly, .validUTF8Only, .singleTopLevelItem,
	]

	/// swift-cbor, decoding our wire bytes into the same Swift type we
	/// encoded, reconstructs the exact original value.
	func testFixtureDecodesToSameValueWithSwiftCbor() throws {
		let ours = try SecretArchive(encoding: fixture)
		let decoded = try CborDecoder().decode(Fixture.self, from: rawData(ours))
		XCTAssertEqual(decoded, fixture)
	}

	/// An external *validator*, not merely an external reader: swift-cbor
	/// checks our output against RFC 8949 §4.2.1's canonicity rules and
	/// accepts it. Shortest-form heads and canonical map ordering are the two
	/// places a deterministic encoder goes silently wrong, and this is the
	/// only assertion in the package that either is judged correct by
	/// something other than this package.
	func testFixturePassesSwiftCborStrictValidation() throws {
		let ours = try SecretArchive(encoding: fixture)
		let decoded = try CborDecoder(options: strictOptions)
			.decode(Fixture.self, from: rawData(ours))
		XCTAssertEqual(decoded, fixture)
	}

	/// The strict validator applied across argument widths, which the
	/// `Fixture` alone does not reach: it holds only inline-argument and
	/// 8-byte values, so a regression in the 1-, 2- or 4-byte head forms
	/// would slip past `testFixtureReencodesByteIdenticalWithSwiftCbor`.
	func testEveryArgumentWidthPassesStrictValidation() throws {
		struct Widths: Codable, Equatable {
			var inlineMax: Int  // 23  — no argument byte
			var oneByte: Int  // 24  — 1-byte argument
			var twoByte: Int  // 256 — 2-byte
			var fourByte: Int  // 65536 — 4-byte
			var eightByte: UInt64  // 2^32 — 8-byte
			var blob: Data  // a 256-byte string: 2-byte length head
		}
		let value = Widths(
			inlineMax: 23, oneByte: 24, twoByte: 256, fourByte: 65536,
			eightByte: 4_294_967_296,
			blob: Data(repeating: 0x5A, count: 256))
		let ours = try SecretArchive(encoding: value)
		let decoded = try CborDecoder(options: strictOptions)
			.decode(Widths.self, from: rawData(ours))
		XCTAssertEqual(decoded, value)
	}

	/// The strongest form of the check: swift-cbor, told to sort map keys
	/// lexicographically and always use float64 (matching this archive's
	/// profile — see `reencodeOptions`), reproduces our exact bytes when
	/// encoding the identical value. Two independent CBOR implementations
	/// agree not just on meaning but on the deterministic wire form.
	func testFixtureReencodesByteIdenticalWithSwiftCbor() throws {
		let ours = try SecretArchive(encoding: fixture)
		let theirs = try CborEncoder(options: reencodeOptions).encode(fixture)
		XCTAssertEqual(hex(ours), hex(theirs))
	}

	/// Confirms `reencodeOptions` is the right substitute for the built-in
	/// preset, with real bytes rather than just the doc comment's claim:
	/// `.deterministicCbor` picks float16 for `1.5` (RFC 8949's own Appendix A
	/// encoding for that value), which is a different, non-float64 wire form
	/// than this archive ever emits.
	func testBuiltinDeterministicPresetDivergesOnFloats() throws {
		struct F: Codable { var v: Double }
		let ours = try SecretArchive(encoding: F(v: 1.5))
		let builtinPreset = try CborEncoder(options: .deterministicCbor).encode(F(v: 1.5))
		XCTAssertEqual(hex(builtinPreset), "a16176f93e00")  // float16
		XCTAssertNotEqual(hex(ours), hex(builtinPreset))
		// float64, this archive's profile:
		XCTAssertEqual(hex(ours), "a16176fb3ff8000000000000")
	}

	/// `0.0` and `-0.0` share a value but not a bit pattern; both this
	/// archive and swift-cbor (with `.floatingPoint64Only`) preserve the sign
	/// bit rather than normalizing it away.
	func testSignedZeroReencodesByteIdentical() throws {
		struct F: Codable { var v: Double }
		let encoder = CborEncoder(options: reencodeOptions)

		let ours = try SecretArchive(encoding: F(v: 0.0))
		XCTAssertEqual(hex(ours), hex(try encoder.encode(F(v: 0.0))))

		let negOurs = try SecretArchive(encoding: F(v: -0.0))
		XCTAssertEqual(hex(negOurs), hex(try encoder.encode(F(v: -0.0))))
		XCTAssertNotEqual(hex(ours), hex(negOurs))
	}

	// MARK: - The COSE_Key integer-keyed vector: structural agreement only

	private struct CoseKey: Codable {
		var kty = 1, crv = 6
		@SecretField var d: SecretBytes
		enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
			case kty = 1
			case crv = -1
			case d = -4
		}
	}

	/// swift-cbor's `KeyedDecodingContainer` cannot see this map's keys at
	/// all: `CborKeyedDecodingContainer.asDictionary` coerces every CBOR map
	/// key through `String.self` and silently drops (`try?`, then `continue`)
	/// any key that isn't a text string — verified by reading that method.
	/// Since every key this archive's COSE_Key vector uses is a CBOR integer
	/// (major type 0/1, via `ArchiveIntegerCodingKey`), an ordinary keyed
	/// decode sees an apparently *empty* map, with no error. This is exactly
	/// the gap `container(keyedBy:)` cannot cross — pinned here so the next
	/// section's workaround doesn't look unmotivated.
	func testSwiftCborKeyedContainerCannotSeeIntegerMapKeys() throws {
		let d = try SecretBytes(bytes: [UInt8](repeating: 0xAB, count: 32))
		let ours = try SecretArchive(encoding: CoseKey(d: d))

		struct Probe: Decodable { var kty: Int? }
		let probed = try CborDecoder().decode(Probe.self, from: rawData(ours))
		XCTAssertNil(
			probed.kty, "the integer key 1 is invisible via the keyed container path")
	}

	/// The workaround: a CBOR map decodes internally to the flat sequence
	/// key0,value0,key1,value1,... regardless of key type, and swift-cbor's
	/// `unkeyedContainer()` — ordinary, public `Decoder` API, not a
	/// swift-cbor internal — walks that sequence untouched by the
	/// keyed-container's string coercion. Each position is decoded as the
	/// type this package's own encoder is known to have put there (canonical
	/// key order `01 < 20 < 23`, i.e. kty, crv, d) rather than guessed by
	/// trying types and catching failures: swift-cbor's `String`/`Bool`
	/// unkeyed-decode overloads advance `currentIndex` *before* the type
	/// check that can fail it, so a `try?`-based type guess silently
	/// desyncs every read after a wrong guess. Decoding the position we
	/// already know the type of sidesteps that entirely.
	///
	/// `d`'s value is read only as `Data.count` — never compared to this
	/// package's actual secret plaintext, which is never extracted via
	/// `withSecretBytes` anywhere in this file. `kty` and `crv` are ordinary
	/// (non-secret) integers, so their exact values are asserted.
	func testCoseKeyIntegerKeyedVectorStructuralAgreement() throws {
		let d = try SecretBytes(bytes: [UInt8](repeating: 0xAB, count: 32))
		let ours = try SecretArchive(encoding: CoseKey(d: d))

		struct RawCoseKeyWalk: Decodable {
			var ktyKey: Int64
			var ktyValue: Int64
			var crvKey: Int64
			var crvValue: Int64
			var dKey: Int64
			var dByteLength: Int

			init(from decoder: Decoder) throws {
				var c = try decoder.unkeyedContainer()
				ktyKey = try c.decode(Int64.self)
				ktyValue = try c.decode(Int64.self)
				crvKey = try c.decode(Int64.self)
				crvValue = try c.decode(Int64.self)
				dKey = try c.decode(Int64.self)
				dByteLength = try c.decode(Data.self).count
			}
		}
		let walked = try CborDecoder().decode(RawCoseKeyWalk.self, from: rawData(ours))
		XCTAssertEqual(walked.ktyKey, 1)
		XCTAssertEqual(walked.ktyValue, 1)
		XCTAssertEqual(walked.crvKey, -1)
		XCTAssertEqual(walked.crvValue, 6)
		XCTAssertEqual(walked.dKey, -4)
		XCTAssertEqual(walked.dByteLength, 32)
	}

	// MARK: - Custody holds against a foreign coder too

	/// Text-keyed on purpose, unlike `CoseKey` above: every key here is a
	/// plain string, so swift-cbor's keyed container (which only ever sees
	/// text keys — the previous section) can actually reach the secret
	/// property during decode instead of failing earlier on a missing
	/// integer-keyed field. `label` decodes first and succeeds; `key` is
	/// what's under test.
	private struct SecretHolder: Codable {
		var label: String
		@SecretField var key: SecretBytes
	}

	/// `ArchiveCustodyTests` proves the tripwire fires against `JSONEncoder`.
	/// swift-cbor is a different foreign coder — a real, independent CBOR
	/// implementation, not a toy — so this is the same guarantee re-checked
	/// against the one coder in this suite that could plausibly be mistaken
	/// for `SecretArchive` itself. `@SecretField`'s conformance is
	/// unconditional and throws before writing regardless of which coder
	/// reaches it.
	func testSecretFieldTripwireFiresAgainstSwiftCborToo() throws {
		let key = try SecretBytes(bytes: [1, 2, 3])
		let ours = try SecretArchive(encoding: SecretHolder(label: "x", key: key))
		XCTAssertThrowsError(
			try CborDecoder().decode(SecretHolder.self, from: rawData(ours))
		) {
			XCTAssertEqual($0 as? SecretArchiveError, .secretOutsideSecretArchive)
		}
	}
}

import Crypto
import Foundation
import XCTest

@testable import SecretBytes

/// The encoder and the decoder hold independent definitions of a valid
/// archive, and every rule the decoder enforces is a place they can disagree.
/// Three separate defects came from that one seam — float64 zero,
/// canonically-equivalent text keys, and nesting past the depth limit — each
/// found by hand, one review round apart, each producing an archive that
/// sealed cleanly and could never be read back.
///
/// This file attacks the seam generically instead of one rule at a time. The
/// `#if DEBUG` self-validation in `SecretArchive.init(encoding:)` means every
/// successful encode below has already been offered to the decoder's own
/// validator; these tests exist to *drive shapes at it* that hand-written
/// vectors would not reach.
final class ArchiveEmitRejectTests: XCTestCase {

	// MARK: Depth — the third instance of the class

	private indirect enum Tree: Codable, Equatable {
		case leaf(Int)
		case node(Tree)

		init(depth: Int) {
			var t = Tree.leaf(0)
			for _ in 0..<depth { t = .node(t) }
			self = t
		}
	}

	/// An `indirect enum` is the ordinary way to write a recursive `Codable`,
	/// and a deep enough value used to encode and seal without complaint, then
	/// throw `malformedArchive` on every attempt to restore it. Strictly more
	/// reachable than the other two instances: this needs only a *synthesized*
	/// conformance and data that happens to be deep.
	func testDeeplyNestedValueIsRejectedAtEncodeNotAfterSealing() throws {
		XCTAssertThrowsError(try SecretArchive(encoding: Tree(depth: 80))) { error in
			XCTAssertEqual(error as? SecretArchiveError, .nestingTooDeep)
		}
	}

	/// The bound has to admit what the decoder admits, or the fix trades a
	/// silent corruption for a false rejection.
	func testNestingWithinTheLimitStillRoundTrips() throws {
		// SE-0295 wraps each level in a keyed container, so a `Tree` of depth d
		// nests roughly 2d deep on the wire; 24 stays clear of the limit.
		let value = Tree(depth: 24)
		XCTAssertEqual(try SecretArchive(encoding: value).decode(Tree.self), value)
	}

	/// Plain containers reach the same limit without any recursive type.
	func testDeepNestedContainerChainIsRejected() throws {
		struct DeepChain: Encodable {
			enum K: String, CodingKey { case next }
			let levels: Int
			func encode(to encoder: Encoder) throws {
				var c = encoder.container(keyedBy: K.self)
				var nested = c.nestedContainer(keyedBy: K.self, forKey: .next)
				for _ in 0..<levels {
					nested = nested.nestedContainer(
						keyedBy: K.self, forKey: .next)
				}
			}
		}
		XCTAssertThrowsError(try SecretArchive(encoding: DeepChain(levels: 80))) {
			XCTAssertEqual($0 as? SecretArchiveError, .nestingTooDeep)
		}
	}

	private final class Chain: Codable, Equatable {
		var next: Chain?
		init(depth: Int) {
			next = depth > 0 ? Chain(depth: depth - 1) : nil
		}
		static func == (a: Chain, b: Chain) -> Bool { a.next == b.next }
	}

	/// Depth reached through the *funnel* rather than through
	/// `nestedContainer`: a recursive class nests by encoding a child value at
	/// each level, so `wrap` is the only place the level increases. The two
	/// tests above both nest via `nestedContainer`, whose own check covers
	/// them — so without this one, deleting `wrap`'s guard changed nothing and
	/// the suite stayed green.
	func testDepthReachedThroughTheFunnelIsRejected() throws {
		XCTAssertThrowsError(try SecretArchive(encoding: Chain(depth: 80))) { error in
			XCTAssertEqual(error as? SecretArchiveError, .nestingTooDeep)
		}
	}

	func testFunnelNestingWithinTheLimitRoundTrips() throws {
		let value = Chain(depth: 30)
		XCTAssertEqual(try SecretArchive(encoding: value).decode(Chain.self), value)
	}

	// MARK: The boundary itself — every node kind, both sides of the limit

	/// `levels` nested containers, then a node of the given kind one deeper.
	private struct DeepTail: Encodable {
		enum Tail { case primitive, unusedSuper, emptyContainer }
		let levels: Int
		let tail: Tail

		func encode(to encoder: Encoder) throws {
			var root = encoder.unkeyedContainer()
			var cur = root.nestedUnkeyedContainer()
			for _ in 1..<levels { cur = cur.nestedUnkeyedContainer() }
			switch tail {
			case .primitive: try cur.encode(true)
			case .unusedSuper: _ = cur.superEncoder()
			case .emptyContainer: _ = cur.nestedUnkeyedContainer()
			}
		}
	}

	/// The depth checks used to live at each site that *created a container*,
	/// which missed every other way a node comes into being: a primitive leaf,
	/// an unused `superEncoder` slot, a single-value write. A container at the
	/// limit is legal, so writing a primitive into it put a node one past the
	/// limit — sealing cleanly, unreadable forever, and in DEBUG masked by the
	/// self-validation into the wrong error entirely.
	///
	/// This sweeps *both sides* of the boundary for each node kind, which the
	/// previous depth tests did not: their deepest case sat seven levels short
	/// of it, so the region where an off-by-one lives was never visited.
	func testEveryNodeKindRespectsTheDepthBoundary() throws {
		for tail in [DeepTail.Tail.primitive, .unusedSuper, .emptyContainer] {
			for levels in [62, 63] {
				XCTAssertNoThrow(
					try SecretArchive(
						encoding: DeepTail(levels: levels, tail: tail)),
					"\(tail) at \(levels) is within the limit and must encode")
			}
			for levels in [64, 65] {
				XCTAssertThrowsError(
					try SecretArchive(
						encoding: DeepTail(levels: levels, tail: tail)),
					"\(tail) at \(levels) exceeds the limit"
				) { error in
					// Must be the caller-data error, not the DEBUG net's
					// generic one — the net is compiled out of release.
					XCTAssertEqual(
						error as? SecretArchiveError, .nestingTooDeep,
						"\(tail) at \(levels) must report nestingTooDeep")
				}
			}
		}
	}

	/// The check lives in the serializer's size walk, the one place every node
	/// passes in every build configuration. Driving it directly proves the
	/// bound holds where the DEBUG self-validation is absent — the archive-level
	/// test above cannot distinguish the two in a debug build.
	func testSerializerSizeWalkEnforcesDepthWithoutTheDebugNet() throws {
		func nest(_ depth: Int) -> ArchiveNode {
			var node = ArchiveNode(.bool(true))
			for _ in 0..<depth { node = ArchiveNode(.array([node])) }
			return node
		}
		XCTAssertNoThrow(try ArchiveSerializer.size(nest(64)))
		XCTAssertThrowsError(try ArchiveSerializer.size(nest(65))) { error in
			XCTAssertEqual(error as? SecretArchiveError, .nestingTooDeep)
		}
	}

	// MARK: Float magnitude — precision may be lost, magnitude may not

	private struct FloatField: Codable { var v: Float }

	/// `1e-300` narrowing to `0.0` is the same defect as `1e300` narrowing to
	/// `+inf`: a finite stored value replaced by a different one, silently.
	/// The first round of this fix caught only the overflow half and claimed
	/// `JSONDecoder` parity — Foundation rejects both.
	func testFloatUnderflowAndOverflowBothRejected() throws {
		for value in [1e300, -1e300, 1e-300, 1e-46, -1e-300] {
			let archive = try SecretArchive(encoding: ["v": value])
			XCTAssertThrowsError(
				try archive.decode(FloatField.self),
				"\(value) is not representable as Float and must not decode")
		}
	}

	/// The boundaries the guard must not over-reach: the largest and smallest
	/// magnitudes `Float` genuinely represents, plus the values that are
	/// legitimately zero, infinite, or NaN.
	func testFloatBoundariesAndNonFiniteValuesStillDecode() throws {
		let representable: [Double] = [
			0.0, -0.0,
			0.1,  // precision loss is fine
			Double(Float.greatestFiniteMagnitude),
			Double(Float.leastNonzeroMagnitude),
			.infinity, -.infinity,
		]
		for value in representable {
			let archive = try SecretArchive(encoding: ["v": value])
			let decoded = try archive.decode(FloatField.self).v
			XCTAssertEqual(decoded, Float(value), "\(value) must still decode")
			XCTAssertEqual(
				decoded.sign, Float(value).sign, "\(value) must keep its sign")
		}
		let nan = try SecretArchive(encoding: ["v": Double.nan])
		XCTAssertTrue(try nan.decode(FloatField.self).v.isNaN)
	}

	// MARK: Generic sweep — shapes no hand-written vector would reach

	/// A grid over the axes where the encoder and decoder hold *separate*
	/// rules, driven through a real encode: nesting depth, float magnitude,
	/// integer width, key kind and spelling, empty containers, and text that
	/// exercises UTF-8 and normalization. Each successful encode is validated
	/// by the decoder inside `init(encoding:)` (DEBUG), and each is decoded
	/// here as well, so a disagreement in *either* direction fails.
	///
	/// This is the part that generalizes: depth survived four review passes
	/// because no existing test happened to nest deeply, not because anyone
	/// decided it was safe.
	func testShapeSweepEncodesAndDecodes() throws {
		struct Cell: Codable, Equatable {
			var text: String
			var number: Int64
			var unsigned: UInt64
			var float: Double
			var blob: Data
			var flag: Bool
			var maybe: Int?
			var list: [Int]
			var map: [String: Int]
		}

		let texts = [
			"", "a", "水", "e\u{0301}", "\u{00E9}", String(repeating: "x", count: 300),
		]
		let numbers: [Int64] = [0, 23, 24, -1, -24, .min, .max, 255, 256, 65535, 65536]
		let unsigneds: [UInt64] = [0, 23, 24, .max, 4_294_967_295, 4_294_967_296]
		let floats: [Double] = [0.0, -0.0, 1.5, .infinity, 1e300, 1e-300]
		let blobs = [Data(), Data([0]), Data(repeating: 0xAB, count: 300)]

		for i in 0..<max(texts.count, max(numbers.count, unsigneds.count)) {
			let cell = Cell(
				text: texts[i % texts.count],
				number: numbers[i % numbers.count],
				unsigned: unsigneds[i % unsigneds.count],
				float: floats[i % floats.count],
				blob: blobs[i % blobs.count],
				flag: i % 2 == 0,
				maybe: i % 3 == 0 ? nil : i,
				list: Array(0..<(i % 4)),
				map: i % 2 == 0 ? [:] : ["k\(i)": i])
			let archive = try SecretArchive(encoding: cell)
			XCTAssertEqual(try archive.decode(Cell.self), cell, "cell \(i)")
		}
	}

	/// The same sweep over nesting depth specifically, on both container kinds,
	/// right up to the boundary — the region where an off-by-one between the
	/// encoder's new bound and the decoder's would show up.
	func testNestingDepthSweepAgreesOnBothSides() throws {
		struct Nest: Codable, Equatable {
			var depth: Int
			var payload: [Int]

			func encode(to encoder: Encoder) throws {
				var container = encoder.unkeyedContainer()
				try container.encode(depth)
				var inner = container.nestedUnkeyedContainer()
				for _ in 0..<depth {
					inner = inner.nestedUnkeyedContainer()
				}
				try inner.encode(contentsOf: payload)
			}

			init(depth: Int, payload: [Int]) {
				self.depth = depth
				self.payload = payload
			}

			init(from decoder: Decoder) throws {
				var container = try decoder.unkeyedContainer()
				depth = try container.decode(Int.self)
				var inner = try container.nestedUnkeyedContainer()
				for _ in 0..<depth {
					inner = try inner.nestedUnkeyedContainer()
				}
				var read: [Int] = []
				while !inner.isAtEnd { read.append(try inner.decode(Int.self)) }
				payload = read
			}
		}

		for depth in [0, 1, 8, 32, 55] {
			let value = Nest(depth: depth, payload: [1, 2, 3])
			let archive = try SecretArchive(encoding: value)
			XCTAssertEqual(try archive.decode(Nest.self), value, "depth \(depth)")
		}
	}
}

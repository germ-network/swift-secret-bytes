import Foundation

/// A validated view of an archive: one strict pass that both *checks* the whole
/// document and *indexes* it into byte ranges.
///
/// Leaves hold `Range<Int>` into the archive's buffer, never pointers and never
/// copies — the actual bytes are read later, inside a scoped
/// `withUnsafeMutablePointerToElements`. Nothing here allocates from an
/// attacker-supplied count, and every failure throws.
final class IndexNode {
	enum Kind {
		case uint(UInt64)
		case negative(UInt64)
		case bytes(Range<Int>)
		case text(Range<Int>)
		case bool(Bool)
		case null
		case float(Double)
		case array([IndexNode])
		case map([(key: IndexKey, keyBytes: Range<Int>, value: IndexNode)])
	}

	enum IndexKey: Equatable {
		case uint(UInt64)
		case negative(UInt64)
		case text(String)
	}

	let kind: Kind
	init(_ kind: Kind) { self.kind = kind }
}

enum ArchiveIndex {
	/// Strict UTF-8 validation, without the BOM-stripping `String(bytes:encoding:
	/// .utf8)` (Foundation) applies. `String(decoding:as:)` never strips or
	/// otherwise transforms a valid sequence, so re-encoding a valid decode
	/// reproduces the exact input bytes; anything invalid decodes lossily (with
	/// U+FFFD) and so fails the round trip. Swift 6's `String(validating:as:)`
	/// does this natively but needs a higher deployment floor than this package
	/// supports (macOS 13 / iOS 16).
	private static func strictUTF8String(_ bytes: UnsafeRawBufferPointer) -> String? {
		let text = String(decoding: bytes, as: UTF8.self)
		return Array(text.utf8).elementsEqual(bytes) ? text : nil
	}

	/// Nesting limit. Comfortably above real schemas (group-in-session-in-account
	/// is single digits) and low enough that recursion cannot exhaust the stack.
	static let maxDepth = 64

	/// Validates and indexes the whole buffer, requiring exactly one top-level
	/// item that consumes it completely.
	static func build(_ buffer: UnsafeRawBufferPointer) throws -> IndexNode {
		var offset = 0
		let root = try parse(buffer, at: &offset, depth: 0)
		guard offset == buffer.count else { throw SecretArchiveError.trailingBytes }
		return root
	}

	private static func parse(
		_ buffer: UnsafeRawBufferPointer,
		at offset: inout Int,
		depth: Int
	) throws -> IndexNode {
		guard depth <= maxDepth else { throw SecretArchiveError.malformedArchive }
		let (major, value, additionalInfo) = try CborHead.parse(buffer, at: &offset)

		switch major {
		case .unsigned:
			return IndexNode(.uint(value))

		case .negative:
			return IndexNode(.negative(value))

		case .bytes, .text:
			guard value <= UInt64(Int.max) else {
				throw SecretArchiveError.malformedArchive
			}
			let length = Int(value)
			guard buffer.count - offset >= length else {
				throw SecretArchiveError.truncated
			}
			let range = offset..<(offset + length)
			offset += length
			if major == .text {
				// Strict UTF-8: a text string that is not valid UTF-8 is a
				// malformed archive, not a lossy decode. See strictUTF8String.
				let bytes = UnsafeRawBufferPointer(rebasing: buffer[range])
				guard strictUTF8String(bytes) != nil else {
					throw SecretArchiveError.malformedArchive
				}
				return IndexNode(.text(range))
			}
			return IndexNode(.bytes(range))

		case .array:
			// Each element occupies at least one byte, so a count larger than
			// the bytes remaining is a lie — rejected before anything is
			// reserved. Capacity is never reserved from this count.
			guard value <= UInt64(buffer.count - offset) else {
				throw SecretArchiveError.malformedArchive
			}
			var items: [IndexNode] = []
			for _ in 0..<value {
				items.append(try parse(buffer, at: &offset, depth: depth + 1))
			}
			return IndexNode(.array(items))

		case .map:
			// An entry is a key *and* a value, each at least one byte, so the
			// tight bound is half the bytes remaining.
			guard value <= UInt64((buffer.count - offset) / 2) else {
				throw SecretArchiveError.malformedArchive
			}
			var entries:
				[(key: IndexNode.IndexKey, keyBytes: Range<Int>, value: IndexNode)] =
					[]
			var previousKeyBytes: Range<Int>?
			// Bytewise uniqueness (above) does not imply uniqueness as Swift
			// sees it: `String ==` is *canonical equivalence*, so "é" as
			// U+00E9 and as U+0065 U+0301 are byte-distinct, sort correctly,
			// and are still the same `String`. Left unchecked, a map holding
			// both decoded into a `[String: V]` of one entry — two keys in,
			// one out, no error. Insertion into a `Set<String>` catches it in
			// O(n) precisely because that hashing is canonical too.
			var seenTextKeys: Set<String> = []
			for _ in 0..<value {
				let keyStart = offset
				let key = try parseMapKey(buffer, at: &offset)
				let keyBytes = keyStart..<offset

				// Keys must arrive in canonical order, and uniqueness follows
				// from comparing against the predecessor alone — O(n), not the
				// O(n²) an all-pairs check would cost on valid-looking input.
				if let previous = previousKeyBytes {
					guard strictlyAscending(buffer, previous, keyBytes) else {
						throw SecretArchiveError.malformedArchive
					}
				}
				previousKeyBytes = keyBytes

				if case .text(let text) = key {
					guard seenTextKeys.insert(text).inserted else {
						throw SecretArchiveError.malformedArchive
					}
				}

				let value = try parse(buffer, at: &offset, depth: depth + 1)
				entries.append((key: key, keyBytes: keyBytes, value: value))
			}
			return IndexNode(.map(entries))

		case .tag:
			// Tags are outside the profile entirely.
			throw SecretArchiveError.malformedArchive

		case .simple:
			// Dispatch on `additionalInfo`, not `value`: bool/null are only
			// canonical in the inline (additional < 24) form. Switching on
			// `value` here would also accept the non-canonical one-byte-argument
			// encoding of 20/21/22 (e.g. `0xF8 0x14`), since CborHead no longer
			// enforces shortest-form for major 7.
			switch additionalInfo {
			case 20: return IndexNode(.bool(false))
			case 21: return IndexNode(.bool(true))
			case 22: return IndexNode(.null)
			default:
				return try parseFloat(
					buffer, at: &offset, headValue: value,
					additionalInfo: additionalInfo)
			}
		}
	}

	/// Map keys are restricted to unsigned, negative and text — the three the
	/// encoder can produce. Anything else is malformed.
	private static func parseMapKey(
		_ buffer: UnsafeRawBufferPointer,
		at offset: inout Int
	) throws -> IndexNode.IndexKey {
		let (major, value, _) = try CborHead.parse(buffer, at: &offset)
		switch major {
		case .unsigned:
			return .uint(value)
		case .negative:
			return .negative(value)
		case .text:
			guard value <= UInt64(Int.max) else {
				throw SecretArchiveError.malformedArchive
			}
			let length = Int(value)
			guard buffer.count - offset >= length else {
				throw SecretArchiveError.truncated
			}
			let bytes = UnsafeRawBufferPointer(
				rebasing: buffer[offset..<(offset + length)])
			guard let text = strictUTF8String(bytes) else {
				throw SecretArchiveError.malformedArchive
			}
			offset += length
			return .text(text)
		default:
			throw SecretArchiveError.malformedArchive
		}
	}

	/// The float profile: `0xFB` float64 for every value, plus the single
	/// canonical NaN `0xf97e00`. `0xFA` (float32) and any other float16 are
	/// rejected, so one value has exactly one wire form.
	private static func parseFloat(
		_ buffer: UnsafeRawBufferPointer,
		at offset: inout Int,
		headValue: UInt64,
		additionalInfo: UInt8
	) throws -> IndexNode {
		switch additionalInfo {
		case 25:
			// float16 — allowed only as the canonical NaN.
			guard UInt16(truncatingIfNeeded: headValue) == 0x7E00 else {
				throw SecretArchiveError.malformedArchive
			}
			return IndexNode(.float(.nan))
		case 27:
			let d = Double(bitPattern: headValue)
			// NaN must use the canonical short form, never float64.
			guard !d.isNaN else { throw SecretArchiveError.malformedArchive }
			return IndexNode(.float(d))
		default:
			// float32 (26), one-byte simple value (24, incl. non-canonical
			// bool/null), undefined (23), and every other simple value.
			throw SecretArchiveError.malformedArchive
		}
	}

	/// Bytewise-lexicographic, strict. Equal keys are duplicates and fail the
	/// same check that catches unsorted ones. Deliberately not Foundation's
	/// `ComparisonResult`, whose case spellings differ across platforms.
	private static func strictlyAscending(
		_ buffer: UnsafeRawBufferPointer,
		_ lhs: Range<Int>,
		_ rhs: Range<Int>
	) -> Bool {
		let n = min(lhs.count, rhs.count)
		for i in 0..<n {
			let a = buffer[lhs.lowerBound + i]
			let b = buffer[rhs.lowerBound + i]
			if a != b { return a < b }
		}
		return lhs.count < rhs.count
	}
}

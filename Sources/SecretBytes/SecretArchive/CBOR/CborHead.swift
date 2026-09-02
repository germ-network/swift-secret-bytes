/// CBOR major types. Tag (6) is parsed only so it can be rejected — the archive
/// profile forbids tags entirely (see the format notes on `ArchiveDecoder`).
enum CborMajor: UInt8 {
	case unsigned = 0
	case negative = 1
	case bytes = 2
	case text = 3
	case array = 4
	case map = 5
	case tag = 6
	case simple = 7
}

/// Head encoding and strict head parsing for the archive's CBOR subset.
///
/// A head is one initial byte — `major << 5 | additionalInfo` — optionally
/// followed by 1, 2, 4 or 8 big-endian argument bytes. This type owns the two
/// rules the format depends on:
///
///  * **emit shortest form** — the smallest argument width that represents the
///    value, per RFC 8949 §4.2.1;
///  * **reject anything else on parse** — a non-shortest head, a reserved
///    additional-info value (28–30), or the indefinite-length marker (31).
///
/// One accepted wire form per value is what makes golden vectors exact and
/// removes parser-differential surface. Nothing here allocates, and every parse
/// path throws rather than trapping.
enum CborHead {
	/// Additional-info values 24…27 select a 1/2/4/8-byte big-endian argument.
	/// Below 24 the value is the additional info itself.
	static func argumentByteCount(for value: UInt64) -> Int {
		switch value {
		case ..<24: 0
		case ..<0x1_00: 1
		case ..<0x1_0000: 2
		case ..<0x1_0000_0000: 4
		default: 8
		}
	}

	/// Total encoded size of a head carrying `value`, including the initial byte.
	static func encodedSize(for value: UInt64) -> Int {
		1 + argumentByteCount(for: value)
	}

	/// The shortest-form head bytes for `major`/`value`, not including any
	/// following payload (text/byte content).
	///
	/// Shared by `write` and by the canonical map-key sort
	/// (`ArchiveSerializer.encodedKey`), which needs the identical bytes as a
	/// plain array to sort on. One implementation is what makes it impossible
	/// for the two to independently drift apart — exactly the failure mode a
	/// hand-rolled canonical encoder is prone to.
	static func encodedHead(major: CborMajor, value: UInt64) -> [UInt8] {
		let width = argumentByteCount(for: value)
		let base = major.rawValue << 5
		switch width {
		case 0: return [base | UInt8(value)]
		case 1: return [base | 24, UInt8(value)]
		case 2:
			return [base | 25]
				+ withUnsafeBytes(of: UInt16(value).bigEndian, Array.init)
		case 4:
			return [base | 26]
				+ withUnsafeBytes(of: UInt32(value).bigEndian, Array.init)
		default: return [base | 27] + withUnsafeBytes(of: value.bigEndian, Array.init)
		}
	}

	/// Appends the shortest-form head for `major`/`value` through `cursor`.
	static func write(
		major: CborMajor,
		value: UInt64,
		into cursor: inout ArchiveWriteCursor
	) throws {
		let head = encodedHead(major: major, value: value)
		try head.withUnsafeBytes { try cursor.append(contentsOf: $0) }
	}

	/// Parses one head at `offset`, advancing past it.
	///
	/// Throws `.malformedArchive` on a non-shortest encoding, additional info
	/// 28–30 (reserved) or 31 (indefinite length), and `.truncated` if the
	/// argument bytes run past the end.
	///
	/// `additionalInfo` is returned alongside `value` because for major 7
	/// (simple/float) the argument is a representation-selecting bit pattern,
	/// not a magnitude — callers that need to know *which form* arrived (an
	/// inline simple value vs. a float16/float32/float64 argument) must not
	/// reconstruct it from `value`, which is ambiguous by design once the
	/// shortest-form rule below is skipped for that major.
	static func parse(
		_ buffer: UnsafeRawBufferPointer,
		at offset: inout Int
	) throws -> (major: CborMajor, value: UInt64, additionalInfo: UInt8) {
		guard offset < buffer.count else { throw SecretArchiveError.truncated }
		let initial = buffer[offset]
		offset += 1

		// Safe: the mask yields 0...7 and CborMajor covers every case.
		let major = CborMajor(rawValue: initial >> 5)!
		let additional = initial & 0x1F

		if additional < 24 {
			return (major, UInt64(additional), additional)
		}
		guard additional <= 27 else {
			// 28–30 reserved; 31 is indefinite length, forbidden by the profile.
			throw SecretArchiveError.malformedArchive
		}

		let width = 1 << Int(additional - 24)  // 1, 2, 4, 8
		guard buffer.count - offset >= width else { throw SecretArchiveError.truncated }

		var value: UInt64 = 0
		for i in 0..<width {
			value = (value << 8) | UInt64(buffer[offset + i])
		}
		offset += width

		// Shortest-form applies to magnitudes — integers, and lengths for
		// bytes/text/array/map. For major 7 the argument bytes select a
		// representation (which float width, or a one-byte simple value);
		// there is no shorter competing encoding of a given bit pattern, so
		// the rule doesn't apply. Rejecting non-canonical simple/float wire
		// forms is the caller's job, using `additionalInfo`.
		if major != .simple {
			guard argumentByteCount(for: value) == width else {
				throw SecretArchiveError.malformedArchive
			}
		}
		return (major, value, additional)
	}
}

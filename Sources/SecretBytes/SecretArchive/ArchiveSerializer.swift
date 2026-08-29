import Foundation

extension SecretArchive {
	/// Carrier for an already-serialized archive produced elsewhere — the one
	/// case ordinary `Codable` nesting cannot cover, because the inner bytes
	/// are opaque to the outer schema.
	///
	/// Same-package nesting should use ordinary nested `Codable` types instead:
	/// those produce **one** buffer for the whole graph, whereas embedding
	/// copies the inner bytes into the outer buffer, so a depth-*d* chain of
	/// live archives holds and scrubs the innermost bytes *d* times. That makes
	/// this a cost rule as well as a style rule.
	///
	/// Same tripwire semantics as `SecretField` under a foreign coder.
	public struct Embedded {
		public var archive: SecretArchive

		public init(_ archive: SecretArchive) {
			self.archive = archive
		}
	}
}

extension SecretArchive.Embedded: Codable {
	public func encode(to encoder: Encoder) throws {
		throw SecretArchiveError.secretOutsideSecretArchive
	}

	public init(from decoder: Decoder) throws {
		throw SecretArchiveError.secretOutsideSecretArchive
	}
}

// MARK: - Canonical serialization

/// Turns an `ArchiveNode` tree into deterministic CBOR.
///
/// Two walks. `size` computes the exact encoded length so the archive can be
/// one exact allocation with no growth and no abandoned buffers to scrub;
/// `emit` fills it through a bounds-checked cursor that throws on any
/// divergence. The sizing walk is an optimization; the cursor is the safety.
enum ArchiveSerializer {
	/// Map entries sort bytewise on their **encoded** key bytes, per RFC 8949
	/// §4.2.1. Note the consequence for negative keys: `-1` encodes as `0x20`,
	/// `-2` as `0x21`, `-4` as `0x23`, so negatives sort *after* all
	/// non-negatives and in **descending** numeric order. Sorting semantically
	/// instead would produce different bytes.
	private static func encodedKey(_ key: ArchiveNode.MapKey) -> [UInt8] {
		switch key {
		case .uint(let v):
			return CborHead.encodedHead(major: .unsigned, value: v)
		case .negative(let v):
			return CborHead.encodedHead(major: .negative, value: v)
		case .text(let s):
			let utf8 = Array(s.utf8)
			return CborHead.encodedHead(major: .text, value: UInt64(utf8.count)) + utf8
		}
	}

	/// Sorts a map's entries into canonical order, rejecting duplicates.
	/// Uniqueness is checked against the *predecessor only* — the keys are
	/// already sorted, so one comparison yields both the order and the
	/// duplicate check in O(n). An all-pairs check would be O(n²) on
	/// valid-looking input.
	private static func canonicalEntries(
		_ entries: [(key: ArchiveNode.MapKey, value: ArchiveNode)]
	) throws -> [(encoded: [UInt8], value: ArchiveNode)] {
		let sorted =
			entries
			.map { (encoded: encodedKey($0.key), value: $0.value) }
			.sorted { lhs, rhs in
				lhs.encoded.lexicographicallyPrecedes(rhs.encoded)
			}
		// A duplicate here means the same keyed container encoded one key
		// twice — a caller bug (hand-written `Codable` conformance), not a
		// wire-format defect. `.malformedArchive` documents parse-time
		// canonicity failures on untrusted bytes; this is encode-side, so it
		// gets the same "package/caller bug, not attacker-reachable" case the
		// sizing/fill desync uses.
		for i in 1..<max(sorted.count, 1) where sorted[i].encoded == sorted[i - 1].encoded {
			throw SecretArchiveError.internalEncodingFailure
		}
		return sorted
	}

	/// Exact encoded size of `node`.
	static func size(_ node: ArchiveNode) throws -> Int {
		switch node.kind {
		case .uint(let v), .negative(let v):
			return CborHead.encodedSize(for: v)
		case .bool, .null:
			return 1
		case .float(let d):
			return d.isNaN ? 3 : 9  // canonical NaN is 0xf97e00; else float64
		case .bytes(let data):
			return CborHead.encodedSize(for: UInt64(data.count)) + data.count
		case .text(let s):
			let n = Array(s.utf8).count
			return CborHead.encodedSize(for: UInt64(n)) + n
		case .secret(let value):
			let n = value.withSecretBytes { $0.count }
			return CborHead.encodedSize(for: UInt64(n)) + n
		case .embedded(let archive):
			let n = archive.withUnsafeBytes { $0.count }
			return CborHead.encodedSize(for: UInt64(n)) + n
		case .array(let items):
			var total = CborHead.encodedSize(for: UInt64(items.count))
			for item in items { total += try size(item) }
			return total
		case .map(let entries):
			let canonical = try canonicalEntries(entries)
			var total = CborHead.encodedSize(for: UInt64(canonical.count))
			for entry in canonical {
				total += entry.encoded.count
				total += try size(entry.value)
			}
			return total
		}
	}

	/// Writes `node` through `cursor`.
	static func emit(_ node: ArchiveNode, into cursor: inout ArchiveWriteCursor) throws {
		switch node.kind {
		case .uint(let v):
			try CborHead.write(major: .unsigned, value: v, into: &cursor)
		case .negative(let v):
			try CborHead.write(major: .negative, value: v, into: &cursor)
		case .bool(let b):
			try cursor.append(b ? 0xF5 : 0xF4)
		case .null:
			try cursor.append(0xF6)
		case .float(let d):
			if d.isNaN {
				// Canonical NaN, the one float16 form the profile emits.
				try cursor.append(0xF9)
				try cursor.append(0x7E)
				try cursor.append(0x00)
			} else {
				try cursor.append(0xFB)
				try cursor.appendBigEndian(d.bitPattern)
			}
		case .bytes(let data):
			try CborHead.write(major: .bytes, value: UInt64(data.count), into: &cursor)
			try data.withUnsafeBytes { try cursor.append(contentsOf: $0) }
		case .text(let s):
			let utf8 = Array(s.utf8)
			try CborHead.write(major: .text, value: UInt64(utf8.count), into: &cursor)
			try utf8.withUnsafeBytes { try cursor.append(contentsOf: $0) }
		case .secret(let value):
			// The only place secret bytes are read during encode, and they go
			// straight into the zeroizing archive buffer.
			try value.withSecretBytes { raw in
				try CborHead.write(
					major: .bytes, value: UInt64(raw.count), into: &cursor)
				try cursor.append(contentsOf: raw)
			}
		case .embedded(let archive):
			try archive.withUnsafeBytes { raw in
				try CborHead.write(
					major: .bytes, value: UInt64(raw.count), into: &cursor)
				try cursor.append(contentsOf: raw)
			}
		case .array(let items):
			try CborHead.write(major: .array, value: UInt64(items.count), into: &cursor)
			for item in items { try emit(item, into: &cursor) }
		case .map(let entries):
			let canonical = try canonicalEntries(entries)
			try CborHead.write(
				major: .map, value: UInt64(canonical.count), into: &cursor)
			for entry in canonical {
				try entry.encoded.withUnsafeBytes {
					try cursor.append(contentsOf: $0)
				}
				try emit(entry.value, into: &cursor)
			}
		}
	}
}

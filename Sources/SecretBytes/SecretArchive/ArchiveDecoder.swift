import Crypto
import Foundation

/// `Decoder` over a validated index tree.
///
/// The archive is retained for the decoder's lifetime, so every leaf read
/// re-enters a scoped pointer closure rather than holding one. Secret fields go
/// range → `Value.init(restoringSecretBytes:)` directly: the concrete type named
/// by the schema builds itself from the in-buffer bytes, with no intermediate
/// `SecretBytes` and no `Data` hop.
final class ArchiveDecoder: Decoder {
	let archive: SecretArchive
	let node: IndexNode
	var codingPath: [any CodingKey]
	var userInfo: [CodingUserInfoKey: Any] { [:] }

	init(archive: SecretArchive, node: IndexNode, codingPath: [any CodingKey] = []) {
		self.archive = archive
		self.node = node
		self.codingPath = codingPath
	}

	// MARK: The funnel

	/// Mirror of the encoder's funnel: secret carriers and embedded archives are
	/// recognised by *metatype*, before `init(from:)` could run.
	func unwrap<T: Decodable>(_ type: T.Type, from node: IndexNode) throws -> T {
		if let carrier = type as? any AnySecretFieldType.Type {
			guard case .bytes(let range) = node.kind else {
				throw DecodingError.typeMismatch(
					type,
					.init(
						codingPath: codingPath,
						debugDescription: "expected a CBOR byte string"))
			}
			let made = try archive.withUnsafeBytes { buffer -> Any in
				try carrier.makeRestoring(
					UnsafeRawBufferPointer(rebasing: buffer[range]))
			}
			// The value constructed *is* the type asked for; a mismatch would be
			// a package bug, so it throws rather than trapping.
			guard let typed = made as? T else {
				throw SecretArchiveError.internalEncodingFailure
			}
			return typed
		}
		if type == SecretArchive.Embedded.self {
			guard case .bytes(let range) = node.kind else {
				throw DecodingError.typeMismatch(
					type,
					.init(
						codingPath: codingPath,
						debugDescription: "expected a CBOR byte string"))
			}
			let inner = try archive.copyingRange(range)
			return SecretArchive.Embedded(inner) as! T
		}
		if type == Data.self {
			guard case .bytes(let range) = node.kind else {
				throw DecodingError.typeMismatch(
					type,
					.init(
						codingPath: codingPath,
						debugDescription: "expected a CBOR byte string"))
			}
			let data = archive.withUnsafeBytes {
				Data(UnsafeRawBufferPointer(rebasing: $0[range]))
			}
			return data as! T
		}
		return try T(
			from: ArchiveDecoder(archive: archive, node: node, codingPath: codingPath))
	}

	// MARK: Decoder

	func container<Key: CodingKey>(
		keyedBy type: Key.Type
	) throws -> KeyedDecodingContainer<Key> {
		guard case .map(let entries) = node.kind else {
			throw DecodingError.typeMismatch(
				[String: Any].self,
				.init(
					codingPath: codingPath,
					debugDescription: "expected a CBOR map"))
		}
		return KeyedDecodingContainer(
			ArchiveKeyedDecodingContainer<Key>(
				decoder: self, entries: entries, codingPath: codingPath))
	}

	func unkeyedContainer() throws -> any UnkeyedDecodingContainer {
		guard case .array(let items) = node.kind else {
			throw DecodingError.typeMismatch(
				[Any].self,
				.init(
					codingPath: codingPath,
					debugDescription: "expected a CBOR array"))
		}
		return ArchiveUnkeyedDecodingContainer(
			decoder: self, items: items, codingPath: codingPath)
	}

	func singleValueContainer() throws -> any SingleValueDecodingContainer {
		ArchiveSingleValueDecodingContainer(
			decoder: self, node: node, codingPath: codingPath)
	}
}

// MARK: - Scalar extraction

extension IndexNode {
	func integer<T: FixedWidthInteger>(_ type: T.Type, at path: [any CodingKey]) throws -> T {
		switch kind {
		case .uint(let v):
			// `T(exactly:)` never traps, unlike narrowing through `Int64` first —
			// which made every `UInt64`/`UInt` value above `Int64.max` (a full
			// hash fragment, a random nonce) unreadable even into a `UInt64`
			// field that could hold it.
			guard let narrowed = T(exactly: v) else {
				throw DecodingError.dataCorrupted(
					.init(
						codingPath: path,
						debugDescription: "integer does not fit \(type)"))
			}
			return narrowed
		case .negative(let v):
			guard v <= UInt64(Int64.max) else {
				throw DecodingError.dataCorrupted(
					.init(
						codingPath: path,
						debugDescription: "integer overflows Int64"))
			}
			guard let narrowed = T(exactly: -1 - Int64(v)) else {
				throw DecodingError.dataCorrupted(
					.init(
						codingPath: path,
						debugDescription: "integer does not fit \(type)"))
			}
			return narrowed
		default:
			throw DecodingError.typeMismatch(
				type,
				.init(codingPath: path, debugDescription: "expected a CBOR integer")
			)
		}
	}

	func boolean(at path: [any CodingKey]) throws -> Bool {
		guard case .bool(let b) = kind else {
			throw DecodingError.typeMismatch(
				Bool.self,
				.init(codingPath: path, debugDescription: "expected a CBOR bool"))
		}
		return b
	}

	/// Narrowing float64 to `Float` may lose *precision* — `0.1` arrives as the
	/// nearest `Float`, which is expected and matches `JSONDecoder`. It must
	/// not lose *magnitude*: `1e300` becoming `+inf` and `1e-300` becoming
	/// `0.0` are both different values, not roundings, and a strict format does
	/// not substitute one value for another in silence. `JSONDecoder` rejects
	/// both ("Number 1e-300 is not representable in Swift"); so does this.
	///
	/// A stored infinity, NaN, or zero decodes as itself — the guards fire only
	/// where a *finite non-zero* input lands on a non-finite or zero result.
	func float(at path: [any CodingKey]) throws -> Float {
		let stored = try double(at: path)
		let narrowed = Float(stored)
		let overflowed = !narrowed.isFinite && stored.isFinite
		let underflowed = narrowed == 0 && stored != 0
		guard !overflowed && !underflowed else {
			throw DecodingError.dataCorrupted(
				.init(
					codingPath: path,
					debugDescription:
						"\(stored) is not representable as Float"))
		}
		return narrowed
	}

	func double(at path: [any CodingKey]) throws -> Double {
		guard case .float(let d) = kind else {
			throw DecodingError.typeMismatch(
				Double.self,
				.init(codingPath: path, debugDescription: "expected a CBOR float"))
		}
		return d
	}

	func string(_ archive: SecretArchive, at path: [any CodingKey]) throws -> String {
		guard case .text(let range) = kind else {
			throw DecodingError.typeMismatch(
				String.self,
				.init(
					codingPath: path,
					debugDescription: "expected a CBOR text string"))
		}
		// UTF-8 validity was proven during validation; this cannot fail.
		return archive.withUnsafeBytes {
			String(decoding: UnsafeRawBufferPointer(rebasing: $0[range]), as: UTF8.self)
		}
	}

	var isNull: Bool {
		if case .null = kind { return true }
		return false
	}
}

// MARK: - Containers

private struct ArchiveKeyedDecodingContainer<Key: CodingKey>: KeyedDecodingContainerProtocol {
	let decoder: ArchiveDecoder
	let entries: [(key: IndexNode.IndexKey, keyBytes: Range<Int>, value: IndexNode)]
	var codingPath: [any CodingKey]

	/// Mirrors `node(for:)`'s gating: integer wire keys only surface through a
	/// key type that opted in, and only when they fit `Int` — an
	/// attacker-controlled archive can carry an integer key of any width, and
	/// `Int(v)`/`Int64(v)` on an out-of-range `UInt64` traps rather than
	/// throwing.
	var allKeys: [Key] {
		let integerKeyed = Key.self is any ArchiveIntegerCodingKey.Type
		return entries.compactMap { entry in
			switch entry.key {
			case .text(let s):
				guard let key = Key(stringValue: s) else { return nil }
				// Completes the mirror `node(for:)` establishes. An opted-in
				// key whose `intValue` is non-nil is addressed by integer
				// *only*, so surfacing it here for a text wire key would list
				// a key `contains` denies — and an `allKeys`-driven decoder
				// would then read a phantom entry.
				if integerKeyed && key.intValue != nil { return nil }
				return key
			case .uint(let v):
				guard integerKeyed, let i = Int(exactly: v) else { return nil }
				return Key(intValue: i)
			case .negative(let v):
				guard integerKeyed, v <= UInt64(Int64.max) else { return nil }
				guard let i = Int(exactly: -1 - Int64(v)) else { return nil }
				return Key(intValue: i)
			}
		}
	}

	/// Mirrors `ArchiveKeyedContainer.mapKey` exactly: a key is addressed by
	/// integer **only** when the schema opted in *and* this key has an
	/// `intValue`; otherwise by text. One key, one wire form.
	///
	/// The mirroring is the point. Matching text unconditionally — as this
	/// once did — let an integer-keyed schema also answer to the case name
	/// Swift synthesises for it, so `{"kty": 9}` decoded as though it were
	/// `{1: 9}` even though the encoder emits only the latter. That is two
	/// wire forms for one value and a shadowing channel into a COSE_Key,
	/// which is precisely the shape integer keying exists to serve.
	private func node(for key: Key) -> IndexNode? {
		if Key.self is any ArchiveIntegerCodingKey.Type, let i = key.intValue {
			for entry in entries {
				switch entry.key {
				case .uint(let v) where i >= 0 && UInt64(i) == v:
					return entry.value
				case .negative(let v) where i < 0 && UInt64(-1 - Int64(i)) == v:
					return entry.value
				default:
					continue
				}
			}
			return nil
		}
		for entry in entries {
			if case .text(let s) = entry.key, s == key.stringValue {
				return entry.value
			}
		}
		return nil
	}

	private func require(_ key: Key) throws -> IndexNode {
		guard let node = node(for: key) else {
			throw DecodingError.keyNotFound(
				key, .init(codingPath: codingPath, debugDescription: "no such key"))
		}
		return node
	}

	func contains(_ key: Key) -> Bool { node(for: key) != nil }

	/// Absence is `keyNotFound`, not `true`. Reporting a missing key as an
	/// explicit null is what let a phantom key — one `allKeys` listed but
	/// `contains` denied — read as a legitimately encoded nil. `JSONDecoder`
	/// throws here too, and `decodeIfPresent` is unaffected because it
	/// consults `contains` first.
	func decodeNil(forKey key: Key) throws -> Bool {
		try require(key).isNull
	}

	func decode(_ type: Bool.Type, forKey key: Key) throws -> Bool {
		try require(key).boolean(at: codingPath + [key])
	}
	func decode(_ type: String.Type, forKey key: Key) throws -> String {
		try require(key).string(decoder.archive, at: codingPath + [key])
	}
	func decode(_ type: Double.Type, forKey key: Key) throws -> Double {
		try require(key).double(at: codingPath + [key])
	}
	func decode(_ type: Float.Type, forKey key: Key) throws -> Float {
		try require(key).float(at: codingPath + [key])
	}
	func decode(_ type: Int.Type, forKey key: Key) throws -> Int {
		try require(key).integer(Int.self, at: codingPath + [key])
	}
	func decode(_ type: Int8.Type, forKey key: Key) throws -> Int8 {
		try require(key).integer(Int8.self, at: codingPath + [key])
	}
	func decode(_ type: Int16.Type, forKey key: Key) throws -> Int16 {
		try require(key).integer(Int16.self, at: codingPath + [key])
	}
	func decode(_ type: Int32.Type, forKey key: Key) throws -> Int32 {
		try require(key).integer(Int32.self, at: codingPath + [key])
	}
	func decode(_ type: Int64.Type, forKey key: Key) throws -> Int64 {
		try require(key).integer(Int64.self, at: codingPath + [key])
	}
	func decode(_ type: UInt.Type, forKey key: Key) throws -> UInt {
		try require(key).integer(UInt.self, at: codingPath + [key])
	}
	func decode(_ type: UInt8.Type, forKey key: Key) throws -> UInt8 {
		try require(key).integer(UInt8.self, at: codingPath + [key])
	}
	func decode(_ type: UInt16.Type, forKey key: Key) throws -> UInt16 {
		try require(key).integer(UInt16.self, at: codingPath + [key])
	}
	func decode(_ type: UInt32.Type, forKey key: Key) throws -> UInt32 {
		try require(key).integer(UInt32.self, at: codingPath + [key])
	}
	func decode(_ type: UInt64.Type, forKey key: Key) throws -> UInt64 {
		try require(key).integer(UInt64.self, at: codingPath + [key])
	}

	func decode<T: Decodable>(_ type: T.Type, forKey key: Key) throws -> T {
		let node = try require(key)
		let child = ArchiveDecoder(
			archive: decoder.archive, node: node, codingPath: codingPath + [key])
		return try child.unwrap(type, from: node)
	}

	func nestedContainer<NK: CodingKey>(
		keyedBy type: NK.Type, forKey key: Key
	) throws -> KeyedDecodingContainer<NK> {
		try ArchiveDecoder(
			archive: decoder.archive, node: try require(key),
			codingPath: codingPath + [key]
		).container(keyedBy: type)
	}

	func nestedUnkeyedContainer(forKey key: Key) throws -> any UnkeyedDecodingContainer {
		try ArchiveDecoder(
			archive: decoder.archive, node: try require(key),
			codingPath: codingPath + [key]
		).unkeyedContainer()
	}

	/// Mirrors the encoder's `"super"`-keyed convention.
	func superDecoder() throws -> any Decoder {
		for entry in entries {
			if case .text("super") = entry.key {
				return ArchiveDecoder(
					archive: decoder.archive, node: entry.value,
					codingPath: codingPath)
			}
		}
		throw DecodingError.keyNotFound(
			SuperCodingKey(),
			.init(codingPath: codingPath, debugDescription: "no super key"))
	}

	func superDecoder(forKey key: Key) throws -> any Decoder {
		ArchiveDecoder(
			archive: decoder.archive, node: try require(key),
			codingPath: codingPath + [key])
	}
}

/// Stand-in `CodingKey` for the conventional `"super"` map entry — mirrors the
/// private key type `JSONEncoder` uses for the same purpose, since the
/// schema's own `Key` type has no reason to declare a `"super"` case.
private struct SuperCodingKey: CodingKey {
	var stringValue: String { "super" }
	init() {}
	init?(stringValue: String) { nil }
	var intValue: Int? { nil }
	init?(intValue: Int) { nil }
}

private struct ArchiveUnkeyedDecodingContainer: UnkeyedDecodingContainer {
	let decoder: ArchiveDecoder
	let items: [IndexNode]
	var codingPath: [any CodingKey]
	var currentIndex: Int = 0

	var count: Int? { items.count }
	var isAtEnd: Bool { currentIndex >= items.count }

	private mutating func next() throws -> IndexNode {
		guard !isAtEnd else {
			throw DecodingError.valueNotFound(
				Any.self,
				.init(
					codingPath: codingPath,
					debugDescription: "unkeyed container is at end"))
		}
		defer { currentIndex += 1 }
		return items[currentIndex]
	}

	mutating func decodeNil() throws -> Bool {
		guard !isAtEnd else { return true }
		if items[currentIndex].isNull {
			currentIndex += 1
			return true
		}
		return false
	}

	mutating func decode(_ type: Bool.Type) throws -> Bool {
		try next().boolean(at: codingPath)
	}
	mutating func decode(_ type: String.Type) throws -> String {
		try next().string(decoder.archive, at: codingPath)
	}
	mutating func decode(_ type: Double.Type) throws -> Double {
		try next().double(at: codingPath)
	}
	mutating func decode(_ type: Float.Type) throws -> Float {
		try next().float(at: codingPath)
	}
	mutating func decode(_ type: Int.Type) throws -> Int {
		try next().integer(Int.self, at: codingPath)
	}
	mutating func decode(_ type: Int8.Type) throws -> Int8 {
		try next().integer(Int8.self, at: codingPath)
	}
	mutating func decode(_ type: Int16.Type) throws -> Int16 {
		try next().integer(Int16.self, at: codingPath)
	}
	mutating func decode(_ type: Int32.Type) throws -> Int32 {
		try next().integer(Int32.self, at: codingPath)
	}
	mutating func decode(_ type: Int64.Type) throws -> Int64 {
		try next().integer(Int64.self, at: codingPath)
	}
	mutating func decode(_ type: UInt.Type) throws -> UInt {
		try next().integer(UInt.self, at: codingPath)
	}
	mutating func decode(_ type: UInt8.Type) throws -> UInt8 {
		try next().integer(UInt8.self, at: codingPath)
	}
	mutating func decode(_ type: UInt16.Type) throws -> UInt16 {
		try next().integer(UInt16.self, at: codingPath)
	}
	mutating func decode(_ type: UInt32.Type) throws -> UInt32 {
		try next().integer(UInt32.self, at: codingPath)
	}
	mutating func decode(_ type: UInt64.Type) throws -> UInt64 {
		try next().integer(UInt64.self, at: codingPath)
	}

	mutating func decode<T: Decodable>(_ type: T.Type) throws -> T {
		let node = try next()
		return try ArchiveDecoder(
			archive: decoder.archive, node: node, codingPath: codingPath
		).unwrap(type, from: node)
	}

	mutating func nestedContainer<NK: CodingKey>(
		keyedBy type: NK.Type
	) throws -> KeyedDecodingContainer<NK> {
		try ArchiveDecoder(
			archive: decoder.archive, node: try next(), codingPath: codingPath
		)
		.container(keyedBy: type)
	}

	mutating func nestedUnkeyedContainer() throws -> any UnkeyedDecodingContainer {
		try ArchiveDecoder(
			archive: decoder.archive, node: try next(), codingPath: codingPath
		)
		.unkeyedContainer()
	}

	/// Mirrors `ArchiveUnkeyedContainer.superEncoder()`: consumes the next
	/// array element as the super object.
	mutating func superDecoder() throws -> any Decoder {
		let node = try next()
		return ArchiveDecoder(archive: decoder.archive, node: node, codingPath: codingPath)
	}
}

private struct ArchiveSingleValueDecodingContainer: SingleValueDecodingContainer {
	let decoder: ArchiveDecoder
	let node: IndexNode
	var codingPath: [any CodingKey]

	func decodeNil() -> Bool { node.isNull }
	func decode(_ type: Bool.Type) throws -> Bool { try node.boolean(at: codingPath) }
	func decode(_ type: String.Type) throws -> String {
		try node.string(decoder.archive, at: codingPath)
	}
	func decode(_ type: Double.Type) throws -> Double { try node.double(at: codingPath) }
	func decode(_ type: Float.Type) throws -> Float { try node.float(at: codingPath) }
	func decode(_ type: Int.Type) throws -> Int { try node.integer(Int.self, at: codingPath) }
	func decode(_ type: Int8.Type) throws -> Int8 {
		try node.integer(Int8.self, at: codingPath)
	}
	func decode(_ type: Int16.Type) throws -> Int16 {
		try node.integer(Int16.self, at: codingPath)
	}
	func decode(_ type: Int32.Type) throws -> Int32 {
		try node.integer(Int32.self, at: codingPath)
	}
	func decode(_ type: Int64.Type) throws -> Int64 {
		try node.integer(Int64.self, at: codingPath)
	}
	func decode(_ type: UInt.Type) throws -> UInt {
		try node.integer(UInt.self, at: codingPath)
	}
	func decode(_ type: UInt8.Type) throws -> UInt8 {
		try node.integer(UInt8.self, at: codingPath)
	}
	func decode(_ type: UInt16.Type) throws -> UInt16 {
		try node.integer(UInt16.self, at: codingPath)
	}
	func decode(_ type: UInt32.Type) throws -> UInt32 {
		try node.integer(UInt32.self, at: codingPath)
	}
	func decode(_ type: UInt64.Type) throws -> UInt64 {
		try node.integer(UInt64.self, at: codingPath)
	}

	func decode<T: Decodable>(_ type: T.Type) throws -> T {
		try decoder.unwrap(type, from: node)
	}
}

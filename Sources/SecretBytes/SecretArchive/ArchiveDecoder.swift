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
		let value: Int64
		switch kind {
		case .uint(let v):
			guard v <= UInt64(Int64.max) else {
				throw DecodingError.dataCorrupted(
					.init(
						codingPath: path,
						debugDescription: "integer overflows Int64"))
			}
			value = Int64(v)
		case .negative(let v):
			guard v <= UInt64(Int64.max) else {
				throw DecodingError.dataCorrupted(
					.init(
						codingPath: path,
						debugDescription: "integer overflows Int64"))
			}
			value = -1 - Int64(v)
		default:
			throw DecodingError.typeMismatch(
				type,
				.init(codingPath: path, debugDescription: "expected a CBOR integer")
			)
		}
		guard let narrowed = T(exactly: value) else {
			throw DecodingError.dataCorrupted(
				.init(
					codingPath: path,
					debugDescription: "integer does not fit \(type)"))
		}
		return narrowed
	}

	func boolean(at path: [any CodingKey]) throws -> Bool {
		guard case .bool(let b) = kind else {
			throw DecodingError.typeMismatch(
				Bool.self,
				.init(codingPath: path, debugDescription: "expected a CBOR bool"))
		}
		return b
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

	var allKeys: [Key] {
		entries.compactMap { entry in
			switch entry.key {
			case .text(let s): Key(stringValue: s)
			case .uint(let v): Key(intValue: Int(v))
			case .negative(let v): Key(intValue: -1 - Int(v))
			}
		}
	}

	/// Integer wire keys are addressable only by a key type that opted in;
	/// text keys always match on `stringValue`.
	private func node(for key: Key) -> IndexNode? {
		for entry in entries {
			switch entry.key {
			case .text(let s) where s == key.stringValue:
				return entry.value
			case .uint(let v)
			where Key.self is any ArchiveIntegerCodingKey.Type
				&& key.intValue.map({ $0 >= 0 && UInt64($0) == v }) == true:
				return entry.value
			case .negative(let v)
			where Key.self is any ArchiveIntegerCodingKey.Type
				&& key.intValue.map({ $0 < 0 && UInt64(-1 - Int64($0)) == v })
					== true:
				return entry.value
			default:
				continue
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

	func decodeNil(forKey key: Key) throws -> Bool {
		guard let node = node(for: key) else { return true }
		return node.isNull
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
		Float(try require(key).double(at: codingPath + [key]))
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
		let child = ArchiveDecoder(
			archive: decoder.archive, node: try require(key),
			codingPath: codingPath + [key])
		return try child.unwrap(type, from: try require(key))
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

	func superDecoder() throws -> any Decoder { decoder }
	func superDecoder(forKey key: Key) throws -> any Decoder { decoder }
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
		Float(try next().double(at: codingPath))
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

	mutating func superDecoder() throws -> any Decoder { decoder }
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
	func decode(_ type: Float.Type) throws -> Float { Float(try node.double(at: codingPath)) }
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

import Foundation

/// `Encoder` that accumulates into an `ArchiveNode` tree, then serializes once.
///
/// Two passes are structural, not stylistic: deterministic CBOR forbids
/// indefinite-length items, so definite map/array heads need entry counts that
/// are unknowable until a container finishes. Every container feeds one funnel
/// (`wrap`), which is where secret carriers are intercepted by identity before
/// their own `encode(to:)` could run.
final class ArchiveEncoder: Encoder {
	var codingPath: [any CodingKey]
	var userInfo: [CodingUserInfoKey: Any] { [:] }

	/// Filled in by whichever container this encoder hands out. `superEncoder`
	/// pre-sets this to a node it already inserted into the parent tree, so
	/// the container methods below populate that same reference in place
	/// rather than allocating a disconnected one.
	var node: ArchiveNode?

	init(codingPath: [any CodingKey] = [], node: ArchiveNode? = nil) {
		self.codingPath = codingPath
		self.node = node
	}

	// MARK: The funnel

	/// The single point every encoded value passes through. Secret carriers and
	/// embedded archives are recognised **by type, before** `encode(to:)`, so a
	/// carrier's throwing conformance is never reached inside this coder.
	func wrap(_ value: some Encodable, at path: [any CodingKey]) throws -> ArchiveNode {
		if let secret = value as? AnySecretField {
			return ArchiveNode(.secret(secret))
		}
		if let embedded = value as? SecretArchive.Embedded {
			return ArchiveNode(.embedded(embedded.archive))
		}
		if let data = value as? Data {
			return ArchiveNode(.bytes(data))
		}
		let child = ArchiveEncoder(codingPath: path)
		try value.encode(to: child)
		return child.node ?? ArchiveNode(.null)
	}

	// MARK: Encoder

	func container<Key: CodingKey>(keyedBy type: Key.Type) -> KeyedEncodingContainer<Key> {
		let box = node ?? ArchiveNode(.null)
		box.kind = .map([])
		node = box
		return KeyedEncodingContainer(
			ArchiveKeyedContainer<Key>(encoder: self, node: box, codingPath: codingPath)
		)
	}

	func unkeyedContainer() -> any UnkeyedEncodingContainer {
		let box = node ?? ArchiveNode(.null)
		box.kind = .array([])
		node = box
		return ArchiveUnkeyedContainer(encoder: self, node: box, codingPath: codingPath)
	}

	func singleValueContainer() -> any SingleValueEncodingContainer {
		ArchiveSingleValueContainer(encoder: self, codingPath: codingPath)
	}
}

// MARK: - Containers

private struct ArchiveKeyedContainer<Key: CodingKey>: KeyedEncodingContainerProtocol {
	let encoder: ArchiveEncoder
	let node: ArchiveNode
	var codingPath: [any CodingKey]

	/// Integer wire keys only when the key type opted in — never inferred.
	private func mapKey(_ key: Key) -> ArchiveNode.MapKey {
		if Key.self is any ArchiveIntegerCodingKey.Type, let i = key.intValue {
			return i < 0 ? .negative(UInt64(-1 - Int64(i))) : .uint(UInt64(i))
		}
		return .text(key.stringValue)
	}

	private func put(_ value: ArchiveNode, _ key: Key) {
		guard case .map(var entries) = node.kind else { return }
		entries.append((key: mapKey(key), value: value))
		node.kind = .map(entries)
	}

	mutating func encodeNil(forKey key: Key) throws { put(ArchiveNode(.null), key) }
	mutating func encode(_ v: Bool, forKey key: Key) throws { put(ArchiveNode(.bool(v)), key) }
	mutating func encode(_ v: String, forKey key: Key) throws {
		put(ArchiveNode(.text(v)), key)
	}
	mutating func encode(_ v: Double, forKey key: Key) throws {
		put(ArchiveNode(.float(v)), key)
	}
	mutating func encode(_ v: Float, forKey key: Key) throws {
		put(ArchiveNode(.float(Double(v))), key)
	}
	mutating func encode(_ v: Int, forKey key: Key) throws { put(.integer(Int64(v)), key) }
	mutating func encode(_ v: Int8, forKey key: Key) throws { put(.integer(Int64(v)), key) }
	mutating func encode(_ v: Int16, forKey key: Key) throws { put(.integer(Int64(v)), key) }
	mutating func encode(_ v: Int32, forKey key: Key) throws { put(.integer(Int64(v)), key) }
	mutating func encode(_ v: Int64, forKey key: Key) throws { put(.integer(v), key) }
	mutating func encode(_ v: UInt, forKey key: Key) throws { put(.integer(UInt64(v)), key) }
	mutating func encode(_ v: UInt8, forKey key: Key) throws { put(.integer(UInt64(v)), key) }
	mutating func encode(_ v: UInt16, forKey key: Key) throws { put(.integer(UInt64(v)), key) }
	mutating func encode(_ v: UInt32, forKey key: Key) throws { put(.integer(UInt64(v)), key) }
	mutating func encode(_ v: UInt64, forKey key: Key) throws { put(.integer(v), key) }

	mutating func encode<T: Encodable>(_ value: T, forKey key: Key) throws {
		put(try encoder.wrap(value, at: codingPath + [key]), key)
	}

	mutating func nestedContainer<NK: CodingKey>(
		keyedBy keyType: NK.Type, forKey key: Key
	) -> KeyedEncodingContainer<NK> {
		let child = ArchiveNode(.map([]))
		put(child, key)
		return KeyedEncodingContainer(
			ArchiveKeyedContainer<NK>(
				encoder: encoder, node: child, codingPath: codingPath + [key]))
	}

	mutating func nestedUnkeyedContainer(forKey key: Key) -> any UnkeyedEncodingContainer {
		let child = ArchiveNode(.array([]))
		put(child, key)
		return ArchiveUnkeyedContainer(
			encoder: encoder, node: child, codingPath: codingPath + [key])
	}

	/// Inserts a fresh node under the conventional `"super"` text key (matching
	/// `JSONEncoder`'s convention) and hands back an encoder pre-bound to that
	/// same node, so whatever `super.encode(to:)` writes lands there rather
	/// than replacing this container's own map.
	mutating func superEncoder() -> any Encoder {
		let child = ArchiveNode(.null)
		if case .map(var entries) = node.kind {
			entries.append((key: .text("super"), value: child))
			node.kind = .map(entries)
		}
		return ArchiveEncoder(codingPath: codingPath, node: child)
	}

	mutating func superEncoder(forKey key: Key) -> any Encoder {
		let child = ArchiveNode(.null)
		put(child, key)
		return ArchiveEncoder(codingPath: codingPath + [key], node: child)
	}
}

private struct ArchiveUnkeyedContainer: UnkeyedEncodingContainer {
	let encoder: ArchiveEncoder
	let node: ArchiveNode
	var codingPath: [any CodingKey]

	var count: Int {
		if case .array(let items) = node.kind { return items.count }
		return 0
	}

	private func append(_ value: ArchiveNode) {
		guard case .array(var items) = node.kind else { return }
		items.append(value)
		node.kind = .array(items)
	}

	mutating func encodeNil() throws { append(ArchiveNode(.null)) }
	mutating func encode(_ v: Bool) throws { append(ArchiveNode(.bool(v))) }
	mutating func encode(_ v: String) throws { append(ArchiveNode(.text(v))) }
	mutating func encode(_ v: Double) throws { append(ArchiveNode(.float(v))) }
	mutating func encode(_ v: Float) throws { append(ArchiveNode(.float(Double(v)))) }
	mutating func encode(_ v: Int) throws { append(.integer(Int64(v))) }
	mutating func encode(_ v: Int8) throws { append(.integer(Int64(v))) }
	mutating func encode(_ v: Int16) throws { append(.integer(Int64(v))) }
	mutating func encode(_ v: Int32) throws { append(.integer(Int64(v))) }
	mutating func encode(_ v: Int64) throws { append(.integer(v)) }
	mutating func encode(_ v: UInt) throws { append(.integer(UInt64(v))) }
	mutating func encode(_ v: UInt8) throws { append(.integer(UInt64(v))) }
	mutating func encode(_ v: UInt16) throws { append(.integer(UInt64(v))) }
	mutating func encode(_ v: UInt32) throws { append(.integer(UInt64(v))) }
	mutating func encode(_ v: UInt64) throws { append(.integer(v)) }

	mutating func encode<T: Encodable>(_ value: T) throws {
		append(try encoder.wrap(value, at: codingPath))
	}

	mutating func nestedContainer<NK: CodingKey>(
		keyedBy keyType: NK.Type
	) -> KeyedEncodingContainer<NK> {
		let child = ArchiveNode(.map([]))
		append(child)
		return KeyedEncodingContainer(
			ArchiveKeyedContainer<NK>(
				encoder: encoder, node: child, codingPath: codingPath))
	}

	mutating func nestedUnkeyedContainer() -> any UnkeyedEncodingContainer {
		let child = ArchiveNode(.array([]))
		append(child)
		return ArchiveUnkeyedContainer(
			encoder: encoder, node: child, codingPath: codingPath)
	}

	mutating func superEncoder() -> any Encoder {
		let child = ArchiveNode(.null)
		append(child)
		return ArchiveEncoder(codingPath: codingPath, node: child)
	}
}

private struct ArchiveSingleValueContainer: SingleValueEncodingContainer {
	let encoder: ArchiveEncoder
	var codingPath: [any CodingKey]

	/// Writes into `encoder.node` in place when `superEncoder` preset it to a
	/// node it already inserted into the parent tree — reassigning `node`
	/// outright there would orphan that reference: the parent keeps pointing
	/// at the old (empty) object while this write lands somewhere it never
	/// sees.
	private func set(_ kind: ArchiveNode.Kind) {
		if let existing = encoder.node {
			existing.kind = kind
		} else {
			encoder.node = ArchiveNode(kind)
		}
	}

	mutating func encodeNil() throws { set(.null) }
	mutating func encode(_ v: Bool) throws { set(.bool(v)) }
	mutating func encode(_ v: String) throws { set(.text(v)) }
	mutating func encode(_ v: Double) throws { set(.float(v)) }
	mutating func encode(_ v: Float) throws { set(.float(Double(v))) }
	mutating func encode(_ v: Int) throws { set(ArchiveNode.integer(Int64(v)).kind) }
	mutating func encode(_ v: Int8) throws { set(ArchiveNode.integer(Int64(v)).kind) }
	mutating func encode(_ v: Int16) throws { set(ArchiveNode.integer(Int64(v)).kind) }
	mutating func encode(_ v: Int32) throws { set(ArchiveNode.integer(Int64(v)).kind) }
	mutating func encode(_ v: Int64) throws { set(ArchiveNode.integer(v).kind) }
	mutating func encode(_ v: UInt) throws { set(ArchiveNode.integer(UInt64(v)).kind) }
	mutating func encode(_ v: UInt8) throws { set(ArchiveNode.integer(UInt64(v)).kind) }
	mutating func encode(_ v: UInt16) throws { set(ArchiveNode.integer(UInt64(v)).kind) }
	mutating func encode(_ v: UInt32) throws { set(ArchiveNode.integer(UInt64(v)).kind) }
	mutating func encode(_ v: UInt64) throws { set(ArchiveNode.integer(v).kind) }

	mutating func encode<T: Encodable>(_ value: T) throws {
		set(try encoder.wrap(value, at: codingPath).kind)
	}
}

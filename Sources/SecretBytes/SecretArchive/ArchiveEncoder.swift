import Foundation

/// `Encoder` that accumulates into an `ArchiveNode` tree, then serializes once.
///
/// Two passes are structural, not stylistic: deterministic CBOR forbids
/// indefinite-length items, so definite map/array heads need entry counts that
/// are unknowable until a container finishes. Every container feeds one funnel
/// (`wrap`), which is where secret carriers are intercepted by identity before
/// their own `encode(to:)` could run.
final class ArchiveEncoder: Encoder {
	/// Records a container-shape violation detected where the `Encoder` and
	/// container protocols forbid throwing. Shared by reference across the
	/// whole encode tree — including encoders handed out by `superEncoder` —
	/// so a violation anywhere reaches `SecretArchive.init(encoding:)`, which
	/// throws before a single byte is serialized.
	///
	/// The alternative Foundation picks here is `preconditionFailure`. This
	/// package throws instead: an aborting process is a worse answer than an
	/// error, and "never trap" is applied uniformly rather than case by case.
	final class Failure {
		var error: SecretArchiveError?

		func record(_ error: SecretArchiveError) {
			// First violation wins; later ones are usually its fallout.
			if self.error == nil { self.error = error }
		}
	}

	var codingPath: [any CodingKey]
	var userInfo: [CodingUserInfoKey: Any] { [:] }

	/// Filled in by whichever container this encoder hands out. `superEncoder`
	/// pre-sets this to a node it already inserted into the parent tree, so
	/// the container methods below populate that same reference in place
	/// rather than allocating a disconnected one.
	var node: ArchiveNode?

	let failure: Failure

	/// Nesting level of this encoder's own node, counted the way
	/// `ArchiveIndex` counts it on the way back in: the root is 0, and every
	/// container nested inside another is one deeper.
	let depth: Int

	init(
		codingPath: [any CodingKey] = [],
		node: ArchiveNode? = nil,
		failure: Failure = Failure(),
		depth: Int = 0
	) {
		self.codingPath = codingPath
		self.node = node
		self.failure = failure
		self.depth = depth
	}

	/// Returns the node this encoder's container writes into, adopting `kind`
	/// if the node is still unshaped.
	///
	/// A second container of a *different* kind on one encoder is a caller
	/// bug — `{ keyed; unkeyed; keyed }` in one `encode(to:)`. It used to
	/// overwrite the node's kind, after which the earlier container's writes
	/// hit a `guard case … else { return }` and vanished: encoding succeeded
	/// and silently produced a document missing whole fields. Recorded as a
	/// failure now, and the detached node keeps the rest of the encode from
	/// compounding the damage before it surfaces.
	///
	/// Re-requesting the *same* kind returns the same node, which is what
	/// `Codable` expects: two `container(keyedBy:)` calls write into one map.
	fileprivate func box(shapedAs kind: ArchiveNode.Kind) -> ArchiveNode {
		let box = node ?? ArchiveNode(.unset)
		node = box
		switch (box.kind, kind) {
		case (.map, .map), (.array, .array):
			return box
		case (.unset, _):
			box.kind = kind
			return box
		default:
			// Reached by a genuine conflict *and* by `.null` — an explicitly
			// encoded nil is a written value, not an empty slot, so asking for
			// a container after one is the same caller bug as asking for two
			// container kinds.
			failure.record(.internalEncodingFailure)
			return ArchiveNode(kind)
		}
	}

	// MARK: The funnel

	/// The single point every encoded value passes through. Secret carriers and
	/// embedded archives are recognised **by type, before** `encode(to:)`, so a
	/// carrier's throwing conformance is never reached inside this coder.
	func wrap(
		_ value: some Encodable, at path: [any CodingKey], depth: Int
	) throws -> ArchiveNode {
		// The decoder refuses anything nested past `ArchiveIndex.maxDepth`, and
		// for three review rounds the encoder had no matching rule — so an
		// ordinary recursive `Codable` (an `indirect enum` 65 levels deep)
		// encoded and sealed without complaint and then threw on every attempt
		// to read it back. Enforcing the *same* constant here is what makes the
		// two definitions of a valid archive agree; enforcing it during tree
		// construction rather than at serialization also bounds the recursion
		// itself, which otherwise overflows the stack on a deep enough value.
		guard depth <= ArchiveIndex.maxDepth else {
			failure.record(.nestingTooDeep)
			return ArchiveNode(.null)
		}
		if let secret = value as? AnySecretField {
			return ArchiveNode(.secret(secret))
		}
		if let embedded = value as? SecretArchive.Embedded {
			return ArchiveNode(.embedded(embedded.archive))
		}
		if let data = value as? Data {
			return ArchiveNode(.bytes(data))
		}
		let child = ArchiveEncoder(codingPath: path, failure: failure, depth: depth)
		try value.encode(to: child)
		return child.node ?? ArchiveNode(.null)
	}

	// MARK: Encoder

	func container<Key: CodingKey>(keyedBy type: Key.Type) -> KeyedEncodingContainer<Key> {
		KeyedEncodingContainer(
			ArchiveKeyedContainer<Key>(
				encoder: self, node: box(shapedAs: .map([])),
				codingPath: codingPath,
				depth: depth
			)
		)
	}

	func unkeyedContainer() -> any UnkeyedEncodingContainer {
		ArchiveUnkeyedContainer(
			encoder: self, node: box(shapedAs: .array([])), codingPath: codingPath,
			depth: depth)
	}

	func singleValueContainer() -> any SingleValueEncodingContainer {
		ArchiveSingleValueContainer(encoder: self, codingPath: codingPath, depth: depth)
	}
}

// MARK: - Containers

private struct ArchiveKeyedContainer<Key: CodingKey>: KeyedEncodingContainerProtocol {
	let encoder: ArchiveEncoder
	let node: ArchiveNode
	var codingPath: [any CodingKey]
	/// Depth of `node`; children are one deeper. See `ArchiveEncoder.wrap`.
	let depth: Int

	/// Integer wire keys only when the key type opted in — never inferred.
	private func mapKey(_ key: Key) -> ArchiveNode.MapKey {
		if Key.self is any ArchiveIntegerCodingKey.Type, let i = key.intValue {
			return i < 0 ? .negative(UInt64(-1 - Int64(i))) : .uint(UInt64(i))
		}
		return .text(key.stringValue)
	}

	/// `node.kind = .null` before mutating is load-bearing, not tidying: the
	/// `case .map(var entries)` binding and the node's own payload otherwise
	/// both reference the array, so `append` sees a non-unique buffer and
	/// copy-on-write duplicates the whole thing — per element, making an
	/// N-element container O(N²) to encode. Dropping the node's reference
	/// first leaves `entries` uniquely referenced and the append in place.
	private func put(_ value: ArchiveNode, _ key: Key) {
		guard case .map(var entries) = node.kind else {
			encoder.failure.record(.internalEncodingFailure)
			return
		}
		node.kind = .null
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
		put(try encoder.wrap(value, at: codingPath + [key], depth: depth + 1), key)
	}

	mutating func nestedContainer<NK: CodingKey>(
		keyedBy keyType: NK.Type, forKey key: Key
	) -> KeyedEncodingContainer<NK> {
		let child = ArchiveNode(.map([]))
		put(child, key)
		return KeyedEncodingContainer(
			ArchiveKeyedContainer<NK>(
				encoder: encoder, node: child, codingPath: codingPath + [key],
				depth: depth + 1))
	}

	mutating func nestedUnkeyedContainer(forKey key: Key) -> any UnkeyedEncodingContainer {
		let child = ArchiveNode(.array([]))
		put(child, key)
		return ArchiveUnkeyedContainer(
			encoder: encoder, node: child, codingPath: codingPath + [key],
			depth: depth + 1)
	}

	/// Inserts a fresh node under the conventional `"super"` text key (matching
	/// `JSONEncoder`'s convention) and hands back an encoder pre-bound to that
	/// same node, so whatever `super.encode(to:)` writes lands there rather
	/// than replacing this container's own map.
	mutating func superEncoder() -> any Encoder {
		let child = ArchiveNode(.unset)
		if case .map(var entries) = node.kind {
			entries.append((key: .text("super"), value: child))
			node.kind = .map(entries)
		}
		return ArchiveEncoder(
			codingPath: codingPath, node: child, failure: encoder.failure,
			depth: depth + 1)
	}

	mutating func superEncoder(forKey key: Key) -> any Encoder {
		let child = ArchiveNode(.unset)
		put(child, key)
		return ArchiveEncoder(
			codingPath: codingPath + [key], node: child, failure: encoder.failure,
			depth: depth + 1)
	}
}

private struct ArchiveUnkeyedContainer: UnkeyedEncodingContainer {
	let encoder: ArchiveEncoder
	let node: ArchiveNode
	var codingPath: [any CodingKey]
	/// Depth of `node`; children are one deeper. See `ArchiveEncoder.wrap`.
	let depth: Int

	var count: Int {
		if case .array(let items) = node.kind { return items.count }
		return 0
	}

	/// Same uniqueness discipline as `ArchiveKeyedContainer.put` — see there
	/// for why the `.null` assignment is what keeps this out of O(N²).
	private func append(_ value: ArchiveNode) {
		guard case .array(var items) = node.kind else {
			encoder.failure.record(.internalEncodingFailure)
			return
		}
		node.kind = .null
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
		append(try encoder.wrap(value, at: codingPath, depth: depth + 1))
	}

	mutating func nestedContainer<NK: CodingKey>(
		keyedBy keyType: NK.Type
	) -> KeyedEncodingContainer<NK> {
		let child = ArchiveNode(.map([]))
		append(child)
		return KeyedEncodingContainer(
			ArchiveKeyedContainer<NK>(
				encoder: encoder, node: child, codingPath: codingPath,
				depth: depth + 1))
	}

	mutating func nestedUnkeyedContainer() -> any UnkeyedEncodingContainer {
		let child = ArchiveNode(.array([]))
		append(child)
		return ArchiveUnkeyedContainer(
			encoder: encoder, node: child, codingPath: codingPath,
			depth: depth + 1)
	}

	mutating func superEncoder() -> any Encoder {
		let child = ArchiveNode(.unset)
		append(child)
		return ArchiveEncoder(
			codingPath: codingPath, node: child, failure: encoder.failure,
			depth: depth + 1)
	}
}

private struct ArchiveSingleValueContainer: SingleValueEncodingContainer {
	let encoder: ArchiveEncoder
	var codingPath: [any CodingKey]
	let depth: Int

	/// Writes into `encoder.node` in place when `superEncoder` preset it to a
	/// node it already inserted into the parent tree — reassigning `node`
	/// outright there would orphan that reference: the parent keeps pointing
	/// at the old (empty) object while this write lands somewhere it never
	/// sees.
	private func set(_ kind: ArchiveNode.Kind) {
		guard let existing = encoder.node else {
			encoder.node = ArchiveNode(kind)
			return
		}
		// The third route into the container-shape conflict `box(shapedAs:)`
		// guards, and the one that does not pass through it: a single value
		// written onto an encoder that already handed out a map or array
		// would overwrite the whole container, silently. `.unset` is the one
		// kind that may be filled — that is `superEncoder`'s placeholder, and
		// filling it is exactly what this container is for. `.null` is *not*
		// replaceable: it means a nil was already encoded here, and the
		// second write would discard it.
		guard case .unset = existing.kind else {
			encoder.failure.record(.internalEncodingFailure)
			return
		}
		existing.kind = kind
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
		set(try encoder.wrap(value, at: codingPath, depth: depth).kind)
	}
}

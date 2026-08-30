/// A serialized, secret-bearing payload held entirely in zeroizing storage.
///
/// An archive is the composable middle of the custody chain: a `Codable` value
/// encodes into one, archives `Embedded` into bigger ones, and the only exit to
/// ordinary `Data` is `seal(with:aad:)`, which returns AEAD ciphertext. Restore
/// is the mirror — `open` yields an archive and `decode` reads a value back out,
/// secret fields going straight into their concrete type with no plaintext
/// `Data` hop.
///
/// `@unchecked Sendable`: an archive is constructed once — by the encoder or by
/// `open` — and never mutated afterward, so there is nothing to race. The
/// `@unchecked` is only because the backing is a class; swift-crypto marks its
/// own zeroizing store the same way (`SecureBytes` is `@unchecked Sendable`
/// beneath a plain `Sendable` `SymmetricKey`). This matters in practice:
/// archives cross isolation domains in real adopters, and a non-`Sendable`
/// archive would force an escape hatch at every crossing, in app code.
///
/// It exposes no public byte accessor other than `seal`.
public struct SecretArchive: @unchecked Sendable {
	var storage: ZeroizingBuffer

	init(storage: ZeroizingBuffer) {
		self.storage = storage
	}

	/// Writes straight into the final zeroizing allocation, avoiding a
	/// plaintext staging buffer for bulk producers. `initializer` receives a
	/// buffer of exactly `capacity` bytes and sets `initializedCount` to the
	/// number it wrote (which must not exceed `capacity`).
	///
	/// Internal: `capacity` is a length the *caller* chooses and traps if
	/// violated, which is only safe for producers inside this package (the
	/// serializer, the seal-open path) that compute their own capacity. There
	/// is no `Reader` left to hand an external caller attacker-shaped bytes
	/// through this entry point.
	init(
		unsafeUninitializedCapacity capacity: Int,
		initializingWith initializer: (
			_ buffer: UnsafeMutableRawBufferPointer,
			_ initializedCount: inout Int
		) throws -> Void
	) rethrows {
		precondition(capacity >= 0, "capacity must be non-negative")
		let buffer = ZeroizingBuffer.allocate(minimumCapacity: capacity)
		var written = 0
		try buffer.withUnsafeMutablePointerToElements { elements in
			let raw = UnsafeMutableRawBufferPointer(start: elements, count: capacity)
			try initializer(raw, &written)
		}
		precondition(written <= capacity, "initialized more bytes than capacity")
		buffer.count = written
		self.storage = buffer
	}

	/// The written bytes, valid only for the closure's duration.
	func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
		try storage.withUnsafeMutablePointerToElements { elements in
			try body(UnsafeRawBufferPointer(start: elements, count: storage.count))
		}
	}
}

// MARK: - Codable entry points

extension SecretArchive {
	/// Encodes `value` into one deterministic CBOR item held entirely in
	/// zeroizing storage.
	///
	/// Plain properties ride ordinary `Codable`; secret properties must be
	/// declared with `@SecretField`, which this coder intercepts before the
	/// carrier's own (always-throwing) conformance is reached. A secret-bearing
	/// type handed to any other encoder throws instead of writing.
	public init(encoding value: some Encodable) throws {
		let encoder = ArchiveEncoder()
		let root = try encoder.wrap(value, at: [])
		// Violations the Encoder protocol's non-throwing methods could only
		// record, not raise — a container-shape conflict, most of all. Checked
		// before sizing so a malformed tree never reaches the wire.
		if let failure = encoder.failure.error { throw failure }
		let capacity = try ArchiveSerializer.size(root)

		try self.init(unsafeUninitializedCapacity: capacity) { buffer, count in
			var cursor = ArchiveWriteCursor(buffer: buffer)
			try ArchiveSerializer.emit(root, into: &cursor)
			// The sizing walk is an optimization, not a safety invariant — the
			// cursor already bounds every append. This catches the other
			// direction: a short write would leave uninitialized tail bytes.
			guard cursor.written == capacity else {
				throw SecretArchiveError.internalEncodingFailure
			}
			count = cursor.written
		}
	}
}

extension SecretArchive {
	/// Copies a sub-range into its own zeroizing allocation — how an embedded
	/// archive is lifted back out without the inner bytes ever leaving
	/// zeroizing storage.
	func copyingRange(_ range: Range<Int>) throws -> SecretArchive {
		try SecretArchive(unsafeUninitializedCapacity: range.count) { buffer, count in
			if range.count > 0 {
				withUnsafeBytes { source in
					buffer.baseAddress!.copyMemory(
						from: UnsafeRawBufferPointer(
							rebasing: source[range]
						).baseAddress!,
						byteCount: range.count)
				}
			}
			count = range.count
		}
	}

	/// Decodes the archive as `type`, requiring the whole archive to be
	/// consumed.
	///
	/// Validation happens once, up front, over the entire document: bounds,
	/// shortest-form heads, definite lengths, canonical and unique map keys,
	/// UTF-8, depth, and full consumption. Only then are values materialized —
	/// secret fields straight into the concrete type the schema names, with no
	/// intermediate `Data`.
	public func decode<T: Decodable>(_ type: T.Type = T.self) throws -> T {
		let root = try withUnsafeBytes { try ArchiveIndex.build($0) }
		let decoder = ArchiveDecoder(archive: self, node: root)
		return try decoder.unwrap(type, from: root)
	}
}

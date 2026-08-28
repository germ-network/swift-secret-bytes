/// A serialized, secret-bearing payload held entirely in zeroizing storage.
///
/// An archive is the composable middle of the custody chain: `SecretArchivable`
/// values write their fields into a `Writer`, small archives `embed` into
/// bigger ones, and the only exit to ordinary `Data` is `seal(with:aad:)`, which
/// returns AEAD ciphertext. Restore is the mirror — `open` yields an archive and
/// a `Reader` reads fields back out, secret fields going straight into
/// `SecretBytes` with no plaintext `Data` hop.
///
/// Deliberately **not** `Sendable` (its backing is a mutable class) and it
/// exposes no public byte accessor other than `seal`. Copies share the backing
/// but the archive is immutable after construction, so there is no mutation to
/// race.
public struct SecretArchive {
	var storage: ZeroizingBuffer

	init(storage: ZeroizingBuffer) {
		self.storage = storage
	}

	/// Writes straight into the final zeroizing allocation, avoiding a
	/// plaintext staging buffer for bulk producers. `initializer` receives a
	/// buffer of exactly `capacity` bytes and sets `initializedCount` to the
	/// number it wrote (which must not exceed `capacity`).
	public init(
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

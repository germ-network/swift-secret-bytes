import Foundation

extension SecretArchive {
	/// Builds an archive field by field into zeroizing storage.
	///
	/// The API makes the secret/non-secret split visible at every call site:
	/// `writeSecret`/`embed` consume custodied bytes and are length-prefixed;
	/// the plain `write(_:)`/`writeBytes` overloads take ordinary values.
	/// Callers should route non-secret variable data through `writeBytes` and
	/// reserve `writeSecret` for real secrets.
	///
	/// A value-type, single-threaded builder; deliberately not `Sendable`.
	public struct Writer {
		var storage: ZeroizingBuffer

		public init(reservingCapacity: Int = 64) {
			storage = ZeroizingBuffer.allocate(minimumCapacity: reservingCapacity)
		}

		// MARK: Secret fields (length-prefixed)

		/// Appends a secret, length-prefixed, keeping its bytes in zeroizing
		/// storage the whole way.
		public mutating func writeSecret(_ secret: SecretBytes) {
			secret.withUnsafeBytes { appendLengthPrefixed($0) }
		}

		/// Embeds an inner archive, length-prefixed — the composition primitive.
		public mutating func embed(_ archive: SecretArchive) {
			archive.withUnsafeBytes { appendLengthPrefixed($0) }
		}

		// MARK: Plain fields (fixed-width, big-endian, unprefixed)

		public mutating func write(_ value: UInt8) { appendRaw(of: value) }
		public mutating func write(_ value: UInt16) { appendRaw(of: value.bigEndian) }
		public mutating func write(_ value: UInt32) { appendRaw(of: value.bigEndian) }
		public mutating func write(_ value: UInt64) { appendRaw(of: value.bigEndian) }

		/// Appends non-secret variable-length bytes, length-prefixed. For plain
		/// data (labels, indices); `writeSecret` is the path for secrets.
		public mutating func writeBytes(_ bytes: some ContiguousBytes) {
			bytes.withUnsafeBytes { appendLengthPrefixed($0) }
		}

		/// Finalizes the written bytes into an archive. The `Writer` should not
		/// be used afterward; if it is, the shared backing is copied first.
		public func finalize() -> SecretArchive {
			SecretArchive(storage: storage)
		}

		// MARK: Append machinery (CoW-guarded, doubling growth)

		private mutating func appendRaw<T>(of value: T) {
			Swift.withUnsafeBytes(of: value) { appendRaw($0) }
		}

		private mutating func appendLengthPrefixed(_ source: UnsafeRawBufferPointer) {
			var prefix: [UInt8] = []
			VarInt.encode(UInt64(source.count), into: &prefix)
			prefix.withUnsafeBytes { appendRaw($0) }
			appendRaw(source)
		}

		private mutating func appendRaw(_ source: UnsafeRawBufferPointer) {
			guard source.count > 0, let base = source.baseAddress else { return }
			reserve(additional: source.count)
			storage.withUnsafeMutablePointerToElements { elements in
				(UnsafeMutableRawPointer(elements) + storage.count)
					.copyMemory(from: base, byteCount: source.count)
			}
			storage.count += source.count
		}

		/// Ensures room for `additional` more bytes, reallocating (and scrubbing
		/// the old allocation on release) when the buffer is shared or full.
		private mutating func reserve(additional: Int) {
			let needed = storage.count + additional
			guard !isKnownUniquelyReferenced(&storage) || needed > storage.capacity
			else {
				return
			}
			let grown = ZeroizingBuffer.allocate(
				minimumCapacity: Swift.max(needed, storage.capacity * 2)
			)
			let existing = storage.count
			storage.withUnsafeMutablePointerToElements { source in
				grown.withUnsafeMutablePointerToElements { destination in
					destination.update(from: source, count: existing)
				}
			}
			grown.count = existing
			storage = grown
		}
	}
}

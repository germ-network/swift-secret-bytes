import Crypto

extension SecretArchive {
	/// Reads fields back out of an archive.
	///
	/// Secret and non-secret reads are distinguished by return type at the call
	/// site: `readSecret`/`readArchive` yield custodied values (a secret goes
	/// pointer → zeroizing storage with no plaintext `Data` hop), while
	/// `readUInt*`/`readBytes` yield ordinary values. Use `readBytes` only for
	/// non-secret variable data.
	///
	/// A value-type cursor; deliberately not `Sendable`.
	public struct Reader {
		let storage: ZeroizingBuffer
		private var offset: Int = 0

		init(_ archive: SecretArchive) {
			storage = archive.storage
		}

		/// True once every written byte has been consumed.
		public var isAtEnd: Bool { offset >= storage.count }

		// MARK: Secret reads

		/// Reads a length-prefixed secret straight into zeroizing storage.
		public mutating func readSecret() throws -> SecretBytes {
			let end = storage.count
			var cursor = offset
			let secret = try storage.withUnsafeMutablePointerToElements {
				elements -> SecretBytes in
				let buffer = UnsafeRawBufferPointer(start: elements, count: end)
				let length = try Reader.readLength(buffer, offset: &cursor)
				let region = UnsafeRawBufferPointer(
					rebasing: buffer[cursor..<cursor + length])
				let key = SymmetricKey(data: region)
				cursor += length
				return SecretBytes(key)
			}
			offset = cursor
			return secret
		}

		/// Reads a length-prefixed embedded archive into its own zeroizing storage.
		public mutating func readArchive() throws -> SecretArchive {
			let end = storage.count
			var cursor = offset
			let inner = try storage.withUnsafeMutablePointerToElements {
				elements -> ZeroizingBuffer in
				let buffer = UnsafeRawBufferPointer(start: elements, count: end)
				let length = try Reader.readLength(buffer, offset: &cursor)
				let copy = ZeroizingBuffer.allocate(minimumCapacity: length)
				if length > 0 {
					copy.withUnsafeMutablePointerToElements { destination in
						destination.update(
							from: elements + cursor, count: length)
					}
				}
				copy.count = length
				cursor += length
				return copy
			}
			offset = cursor
			return SecretArchive(storage: inner)
		}

		// MARK: Plain reads

		public mutating func readUInt8() throws -> UInt8 { try readFixedWidth() }
		public mutating func readUInt16() throws -> UInt16 { try readFixedWidth() }
		public mutating func readUInt32() throws -> UInt32 { try readFixedWidth() }
		public mutating func readUInt64() throws -> UInt64 { try readFixedWidth() }

		/// Reads length-prefixed non-secret bytes into an ordinary array.
		public mutating func readBytes() throws -> [UInt8] {
			let end = storage.count
			var cursor = offset
			let bytes = try storage.withUnsafeMutablePointerToElements {
				elements -> [UInt8] in
				let buffer = UnsafeRawBufferPointer(start: elements, count: end)
				let length = try Reader.readLength(buffer, offset: &cursor)
				let region = UnsafeRawBufferPointer(
					rebasing: buffer[cursor..<cursor + length])
				cursor += length
				return [UInt8](region)
			}
			offset = cursor
			return bytes
		}

		// MARK: Framing

		private mutating func readFixedWidth<T: FixedWidthInteger>() throws -> T {
			let size = MemoryLayout<T>.size
			let end = storage.count
			var cursor = offset
			let value = try storage.withUnsafeMutablePointerToElements {
				elements -> T in
				let buffer = UnsafeRawBufferPointer(start: elements, count: end)
				guard buffer.count - cursor >= size else {
					throw SecretArchiveError.truncated
				}
				var raw: T = 0
				withUnsafeMutableBytes(of: &raw) { destination in
					destination.copyMemory(
						from: UnsafeRawBufferPointer(
							rebasing: buffer[cursor..<cursor + size])
					)
				}
				cursor += size
				return T(bigEndian: raw)
			}
			offset = cursor
			return value
		}

		/// Decodes a length prefix and confirms that many bytes remain.
		private static func readLength(
			_ buffer: UnsafeRawBufferPointer,
			offset: inout Int
		) throws -> Int {
			let value = try VarInt.decode(buffer, offset: &offset)
			guard value <= UInt64(Int.max) else {
				throw SecretArchiveError.malformedLength
			}
			let length = Int(value)
			guard buffer.count - offset >= length else {
				throw SecretArchiveError.malformedLength
			}
			return length
		}
	}
}

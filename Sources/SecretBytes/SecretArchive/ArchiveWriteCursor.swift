/// A bounds-checked write head over a fixed allocation.
///
/// The encoder sizes an archive in one walk and fills it in another. The sizing
/// walk is an *optimization* — it buys a single exact allocation with no growth
/// and no abandoned buffers to scrub — but it is deliberately **not** a safety
/// invariant. Every append here re-checks the remaining capacity and throws on
/// overflow, so a divergence between the two walks surfaces as
/// `.internalEncodingFailure` rather than as a heap overflow in a security
/// leaf.
///
/// The cursor never traps: `SecretArchiveError.internalEncodingFailure` is a
/// package-bug surface, not an attacker-reachable one, but the hostile-input
/// rule ("throw, never trap") is applied uniformly rather than case by case.
struct ArchiveWriteCursor {
	private let base: UnsafeMutableRawPointer
	private let capacity: Int
	private(set) var offset: Int

	init(buffer: UnsafeMutableRawBufferPointer) {
		// A zero-capacity archive has no base address; appends will throw.
		self.base = buffer.baseAddress ?? UnsafeMutableRawPointer(bitPattern: -1)!
		self.capacity = buffer.count
		self.offset = 0
	}

	/// Bytes written so far. The encoder asserts this equals the sized capacity.
	var written: Int { offset }

	mutating func append(_ byte: UInt8) throws {
		guard capacity - offset >= 1 else {
			throw SecretArchiveError.internalEncodingFailure
		}
		base.storeBytes(of: byte, toByteOffset: offset, as: UInt8.self)
		offset += 1
	}

	mutating func appendBigEndian<T: FixedWidthInteger>(_ value: T) throws {
		let width = MemoryLayout<T>.size
		guard capacity - offset >= width else {
			throw SecretArchiveError.internalEncodingFailure
		}
		var be = value.bigEndian
		withUnsafeBytes(of: &be) { source in
			(base + offset).copyMemory(from: source.baseAddress!, byteCount: width)
		}
		offset += width
	}

	mutating func append(contentsOf bytes: UnsafeRawBufferPointer) throws {
		guard let source = bytes.baseAddress, bytes.count > 0 else { return }
		guard capacity - offset >= bytes.count else {
			throw SecretArchiveError.internalEncodingFailure
		}
		(base + offset).copyMemory(from: source, byteCount: bytes.count)
		offset += bytes.count
	}
}

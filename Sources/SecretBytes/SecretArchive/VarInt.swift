/// Unsigned LEB128 length framing, shared by `Writer` (encode) and `Reader`
/// (decode). Minimal-encoding is required on decode so a length has exactly one
/// wire form; overflow past `UInt64` is rejected.
enum VarInt {
	/// Appends the LEB128 encoding of `value` to `bytes`.
	static func encode(_ value: UInt64, into bytes: inout [UInt8]) {
		var v = value
		repeat {
			var byte = UInt8(v & 0x7F)
			v >>= 7
			if v != 0 { byte |= 0x80 }
			bytes.append(byte)
		} while v != 0
	}

	/// Decodes a LEB128 value starting at `offset` within `buffer`, advancing
	/// `offset` past it. Rejects truncation, `UInt64` overflow, and non-minimal
	/// encodings (a trailing 0x00 continuation).
	static func decode(
		_ buffer: UnsafeRawBufferPointer,
		offset: inout Int
	) throws -> UInt64 {
		var result: UInt64 = 0
		var shift: UInt64 = 0
		while true {
			guard offset < buffer.count else { throw SecretArchiveError.truncated }
			let byte = buffer[offset]
			offset += 1
			// A 10th byte could only carry the single top bit; more than 63
			// bits of payload overflows UInt64.
			if shift >= 64 || (shift == 63 && byte > 0x01) {
				throw SecretArchiveError.malformedLength
			}
			result |= UInt64(byte & 0x7F) << shift
			if byte & 0x80 == 0 {
				// Minimal-encoding: a non-zero final byte, unless it is the only
				// byte (which legitimately encodes 0).
				if byte == 0 && shift != 0 {
					throw SecretArchiveError.malformedLength
				}
				return result
			}
			shift += 7
		}
	}
}

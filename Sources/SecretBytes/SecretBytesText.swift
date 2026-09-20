import Foundation

extension SecretBytes {
	/// Wraps a UTF-8 string into zeroizing custody — the counterpart to
	/// `utf8String()`.
	///
	/// The credentials this package tends to carry are ASCII byte strings
	/// carried as JSON text (RFC 6749's `access_token`/`refresh_token` are
	/// `1*VSCHAR`, RFC 6750's bearer `b64token` a narrower ASCII set), so UTF-8
	/// is the lossless bridge in both directions.
	///
	/// - Throws: `SecretBytesError.emptySecret` for an empty string, which this
	///   type cannot represent. A Swift `String` is always valid UTF-8, so
	///   `notUTF8` is not reachable here.
	public init(utf8 string: String) throws {
		try self.init(bytes: Data(string.utf8))
	}

	/// Materializes the held bytes as UTF-8 text — a **plaintext copy**, with
	/// none of this type's scrubbing.
	///
	/// This is the one deliberate text exit from `SecretBytes`, and it is the
	/// caller's to contain: use it for the call that genuinely needs a `String`
	/// (an HTTP header value, a form field), keep that `String` transient, and
	/// never persist, log or retain it. Everything else should hold the secret
	/// as `SecretBytes`.
	///
	/// - Throws: `SecretBytesError.notUTF8` if the bytes are not valid UTF-8.
	///   Substituting U+FFFD would silently corrupt a credential, so the read
	///   refuses instead.
	public func utf8String() throws -> String {
		try withUnsafeBytes { bytes in
			guard let string = String(bytes: bytes, encoding: .utf8) else {
				throw SecretBytesError.notUTF8
			}
			return string
		}
	}
}

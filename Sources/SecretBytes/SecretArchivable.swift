/// A type that serializes itself to and from a `SecretArchive`.
///
/// Adopters implement two small functions instead of fighting a `Codable`
/// encoder that assumes plain `Data`. Inside them, use `Writer.writeSecret` /
/// `Reader.readSecret` for secret fields and the plain `write`/`read` overloads
/// for counters, indices, and other non-secret values, so the split is visible
/// at every call site.
public protocol SecretArchivable {
	func archive(into writer: inout SecretArchive.Writer)
	init(restoring reader: inout SecretArchive.Reader) throws
}

extension SecretArchive {
	/// Archives `value` into fresh zeroizing storage.
	public init(archiving value: some SecretArchivable) {
		var writer = Writer()
		value.archive(into: &writer)
		self = writer.finalize()
	}

	/// Restores a `SecretArchivable`, requiring the whole archive to be
	/// consumed (trailing bytes are a decode error).
	public func restore<T: SecretArchivable>(_ type: T.Type = T.self) throws -> T {
		var reader = Reader(self)
		let value = try T(restoring: &reader)
		guard reader.isAtEnd else { throw SecretArchiveError.trailingBytes }
		return value
	}
}

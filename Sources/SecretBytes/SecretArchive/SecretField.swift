/// Opt-in marker for integer CBOR map keys.
///
/// A `CodingKeys` type that conforms encodes its int-valued keys as CBOR
/// integer keys — which is what lets an archive body be a byte-for-byte
/// COSE_Key map. Integer keying is **opt-in and never inferred**: the standard
/// library's dictionary coding key sets `intValue = Int(stringValue)`, so
/// inferring from `intValue` alone would silently re-key `["5": v]` as `[5: v]`,
/// make `["05": v]` round-trip as `["5": v]`, and let `["5": a, "05": b]` emit
/// duplicate map keys that this package's own strict decoder then rejects.
/// Stdlib dictionary keys never conform, so `[String: V]` and `[Int: V]` always
/// use text keys.
public protocol ArchiveIntegerCodingKey: CodingKey {}

/// The explicit opt-in that lets a secret ride `Codable` — but only into a
/// `SecretArchive`.
///
/// `SecretBytes` and `SymmetricKey` are deliberately not `Codable`, so a bare
/// secret property in a `Codable` type is a compile error. This wrapper is how
/// a schema opts in, one level up, at the declaration site:
///
/// ```swift
/// struct SessionSecrets: Codable {
///     @SecretField var sealingKey: SymmetricKey      // restores AS a SymmetricKey
///     @SecretField var exporterSecret: SecretBytes   // no key role — stays general
///     var epoch: UInt64
/// }
/// ```
///
/// Its own `Codable` conformance is a **tripwire, not an implementation**: the
/// archive's coder intercepts this type by identity before `encode(to:)` is
/// ever reached, so these methods run only under a foreign coder — and then they
/// throw unconditionally, having written nothing. A secret-bearing type handed
/// to `JSONEncoder` fails loudly rather than base64-ing a private key into an
/// immortal `String`.
///
/// Deliberately **not** `Hashable`: a secret's hash is a leak vector, and it
/// makes a secret usable as a dictionary key, which this format cannot express.
@propertyWrapper
public struct SecretField<Value: SecretRestorable>:
	CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable
{
	public var wrappedValue: Value

	public init(wrappedValue: Value) {
		self.wrappedValue = wrappedValue
	}

	/// Redacted regardless of `Value`, so logging or dumping a *containing*
	/// struct cannot leak. A naked unwrapped value's own reflection is that
	/// type's pre-existing surface, not this one's.
	public var description: String { "SecretField(<redacted>)" }
	public var debugDescription: String { description }
	public var customMirror: Mirror {
		Mirror(self, children: ["wrappedValue": "<redacted>"])
	}
}

extension SecretField: Equatable where Value: Equatable {}
extension SecretField: Sendable where Value: Sendable {}

/// Unconditional in `Value` on purpose: `Value` need not — and must not — be
/// `Codable`, and the tripwire must fire for every instantiation.
extension SecretField: Codable {
	public func encode(to encoder: Encoder) throws {
		throw SecretArchiveError.secretOutsideSecretArchive
	}

	public init(from decoder: Decoder) throws {
		throw SecretArchiveError.secretOutsideSecretArchive
	}
}

// MARK: - Funnel seams

/// Lets the encoder's funnel intercept any `SecretField<Value>` without knowing
/// `Value`. Internal: adopters conform to `SecretRestorable`, never to this.
protocol AnySecretField {
	func withSecretBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
}

/// The decode-side mirror, reached by metatype rather than by value.
protocol AnySecretFieldType {
	static func makeRestoring(_ bytes: UnsafeRawBufferPointer) throws -> Any
}

extension SecretField: AnySecretField {
	func withSecretBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
		try wrappedValue.withSecretBytes(body)
	}
}

extension SecretField: AnySecretFieldType {
	static func makeRestoring(_ bytes: UnsafeRawBufferPointer) throws -> Any {
		SecretField(wrappedValue: try Value(restoringSecretBytes: bytes))
	}
}

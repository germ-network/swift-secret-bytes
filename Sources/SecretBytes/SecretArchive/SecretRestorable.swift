import Crypto

/// A type that can hold secret bytes with **no plaintext hop in either
/// direction**.
///
/// Conforming is an assertion of custody, and the package cannot verify it:
/// conforming a type that stores plain `Data` silently defeats the whole point.
/// This is the same class of opt-in promise as `@unchecked Sendable` — the
/// conformance is the greppable audit point. The obligations:
///
///  * `init(restoringSecretBytes:)` must copy synchronously into the type's own
///    zeroizing storage and must never retain the pointer, which is valid only
///    for the call. It **throws** so each type enforces its own invariant at the
///    restore boundary rather than the archive imposing one for everybody.
///  * `withSecretBytes` must expose the held bytes for the closure's duration
///    without minting non-zeroizing copies.
///
/// Only types with a zeroizing byte accessor can honour this. `SymmetricKey`
/// can. CryptoKit's asymmetric private keys **cannot**: they expose bytes only
/// as `rawRepresentation: Data`, a plaintext copy. Note the failure is
/// specifically the encode half — their `init(rawRepresentation:)` accepts
/// `ContiguousBytes`, so a restore-only conformance would be mechanically
/// possible and is deliberately not offered: a one-way conformance would admit
/// schema types that decode but cannot be re-archived without a hop, breaking
/// round-trip symmetry. Such types restore as `SecretBytes`, and the consumer
/// converts at the use site (inbound conversion is itself hop-free, since
/// `SecretBytes` is `ContiguousBytes`).
public protocol SecretRestorable {
	init(restoringSecretBytes bytes: UnsafeRawBufferPointer) throws
	func withSecretBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
}

extension SecretBytes: SecretRestorable {
	public init(restoringSecretBytes bytes: UnsafeRawBufferPointer) throws {
		// Rejects a zero-byte secret with SecretBytesError.emptySecret, which
		// propagates unmasked. The wire permits a zero-length byte string; what
		// happens to one is this type's invariant, not the format's.
		try self.init(bytes: bytes)
	}

	public func withSecretBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
		try withUnsafeBytes(body)
	}
}

extension SymmetricKey: SecretRestorable {
	/// Accepts any length, including zero — swift-crypto does not validate, and
	/// this conformance does not add a rule the type itself does not have.
	public init(restoringSecretBytes bytes: UnsafeRawBufferPointer) throws {
		self.init(data: bytes)
	}

	public func withSecretBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
		try withUnsafeBytes(body)
	}
}

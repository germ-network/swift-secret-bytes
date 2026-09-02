/// Failures surfaced by archiving, restoring, and the AEAD exit.
///
/// Two deliberate shapes here. The AEAD cases are **coarse**:
/// `authenticationFailure` covers wrong key, wrong AAD, and tampering alike, so
/// `open` is not a distinguishing oracle, and the underlying
/// swift-crypto/CryptoKit error is never surfaced (it differs across platforms
/// and across the supported swift-crypto range). The decode cases are
/// **fine-grained**, which is safe: they describe the *plaintext* after
/// authentication has already succeeded.
///
/// Schema-level failures — a missing key, a type mismatch, an out-of-range
/// integer — throw a standard `DecodingError` instead. That is what makes the
/// archive a well-behaved `Decoder` that synthesized conformances understand.
/// This type is reserved for format-, custody-, and invariant-level failures.
/// Errors thrown by a value's own restoring initializer (for instance
/// `SecretBytesError.emptySecret`) propagate as themselves rather than being
/// masked — they are the schema type's invariant, not the archive's, and
/// rewrapping them would hide the actionable error.
public enum SecretArchiveError: Error, Equatable, Sendable {
	/// A read ran past the end of the archive.
	case truncated
	/// Structure or canonicity: a non-shortest head, an indefinite length, a
	/// tag, an unsorted, duplicated or ill-typed map key, invalid UTF-8, a
	/// disallowed simple value, or nesting past the depth limit.
	case malformedArchive
	/// The top-level item ended before the archive did.
	case trailingBytes
	/// A secret carrier met a coder other than `SecretArchive`'s. Thrown before
	/// anything is written, so no secret byte reaches a foreign encoder.
	case secretOutsideSecretArchive
	/// The encoder's sizing walk and fill walk disagreed. A package bug, not an
	/// attacker-reachable condition — surfaced as a throw rather than a trap so
	/// the "never trap" rule holds uniformly.
	case internalEncodingFailure
	/// The value nests deeper than the format's limit. Distinct from
	/// `.internalEncodingFailure` because this one is about the *caller's
	/// data*, not a package bug: a recursive `Codable` with a deep enough
	/// value is the ordinary way to reach it, and the caller can act on it by
	/// flattening. The encoder enforces the same bound the decoder does, so an
	/// archive that encodes can always be read back.
	case nestingTooDeep
	/// The sealed blob was too short or otherwise not a valid AEAD container.
	case malformedCiphertext
	/// AEAD open failed: wrong key, wrong AAD, or the ciphertext was tampered.
	case authenticationFailure
	/// AEAD seal failed to produce a combined representation.
	case sealFailure
}

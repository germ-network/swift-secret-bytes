/// Failures surfaced by archiving, restoring, and the AEAD exit.
///
/// The AEAD cases are deliberately coarse: `authenticationFailure` covers wrong
/// key, wrong AAD, and tampering alike, so `open` is not a distinguishing
/// oracle. The underlying swift-crypto/CryptoKit error is not surfaced (it
/// differs across platforms and the `3.0.0..<5.0.0` range).
public enum SecretArchiveError: Error, Equatable, Sendable {
	/// A read ran past the end of the archive.
	case truncated
	/// A length prefix was non-minimal, overflowed, or exceeded the bytes left.
	case malformedLength
	/// The sealed blob was too short or otherwise not a valid AEAD container.
	case malformedCiphertext
	/// AEAD open failed: wrong key, wrong AAD, or the ciphertext was tampered.
	case authenticationFailure
	/// AEAD seal failed to produce a combined representation.
	case sealFailure
	/// `restore` finished with bytes left unconsumed.
	case trailingBytes
}

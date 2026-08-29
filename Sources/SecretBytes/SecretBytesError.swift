/// Failures constructing a `SecretBytes`.
///
/// Separate from `SecretArchiveError` on purpose: the leaf type does not depend
/// on the archive layer, and an adopter using `SecretBytes` alone should not
/// have to catch archive errors.
public enum SecretBytesError: Error, Equatable, Sendable {
	/// A zero-byte secret was requested. Meaningless as a secret, and it would
	/// compare unequal to itself under `SymmetricKey`'s constant-time compare.
	case emptySecret
}

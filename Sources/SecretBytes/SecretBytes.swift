import Crypto
import Foundation

/// A held secret: raw bytes in zeroizing storage, with byte access confined to
/// two deliberate escape hatches and nothing else.
///
/// `SecretBytes` is a thin newtype over swift-crypto's `SymmetricKey`, whose
/// backing scrubs on release (verifiable against swift-crypto source on Linux;
/// CryptoKit's word on Apple platforms — see `SECURITY.md`). The newtype adds
/// domain naming, a redacting description so logging an owning object cannot
/// leak, and — the point of the type — it does **not** re-expose the raw bytes.
///
/// The only ways bytes leave a `SecretBytes` are:
///   1. `withUnsafeBytes(_:)` — scoped, in-process interop (a KDF, an AEAD, a
///      wire writer). Never for persistence.
///   2. sealing a `SecretArchive` that carries it (`SecretArchive.seal`), which
///      yields AEAD ciphertext.
///
/// There is deliberately no third: no `Codable`, no `var data`, no `Hashable`
/// (a secret's hash is a leak vector), and reflection is redacted.
public struct SecretBytes: Sendable, Equatable, ContiguousBytes,
	CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable
{
	/// Zeroizing backing. Kept `internal` so the only same-module reader is
	/// `SecretArchive.seal`; there is no public accessor for it.
	let symmetricKey: SymmetricKey

	/// Wraps an existing `SymmetricKey` without copying its bytes out.
	/// Internal: constructing from a `SymmetricKey` is an in-module concern
	/// (e.g. the archive reader); external callers use `init(bytes:)`.
	init(_ symmetricKey: SymmetricKey) {
		self.symmetricKey = symmetricKey
	}

	/// Copies `bytes` into fresh zeroizing storage.
	///
	/// - Throws: `SecretBytesError.emptySecret` if `bytes` is empty. A zero-byte
	///   secret is meaningless, and permitting one is not harmless:
	///   `SymmetricKey`'s constant-time compare returns false for zero-length
	///   input, so an empty secret would compare unequal to itself and break
	///   `Equatable`'s reflexivity requirement.
	///
	///   This **throws** rather than trapping because `bytes` is caller data and
	///   may be attacker-influenced — a decoder handing over a zero-length field
	///   must surface an error, not abort the process. Contrast
	///   `init(randomByteCount:)`, whose argument is a length the programmer
	///   chose rather than data anyone supplied; a non-positive count there is a
	///   programming error and traps, matching stdlib convention.
	public init(bytes: some ContiguousBytes) throws {
		let symmetricKey = SymmetricKey(data: bytes)
		guard symmetricKey.withUnsafeBytes({ !$0.isEmpty }) else {
			throw SecretBytesError.emptySecret
		}
		self.symmetricKey = symmetricKey
	}

	/// Generates `count` cryptographically random bytes in zeroizing storage.
	///
	/// - Precondition: `count > 0`. Unlike `init(bytes:)` this argument is a
	///   length the caller chose, not data it received, so a non-positive value
	///   is a programming error rather than faulty input.
	public init(randomByteCount count: Int) {
		precondition(count > 0, "SecretBytes must hold at least one byte")
		self.symmetricKey = SymmetricKey(size: .init(bitCount: count * 8))
	}

	/// Number of secret bytes held.
	public var byteCount: Int {
		symmetricKey.withUnsafeBytes { $0.count }
	}

	/// Escape hatch #1: hands the raw bytes to `body` for the closure's
	/// duration only. For in-process interop, never persistence.
	public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
		try symmetricKey.withUnsafeBytes(body)
	}

	/// Constant-time equality, forwarded from `SymmetricKey`. Exposed on
	/// purpose: hiding it pushes callers toward hand-rolled byte comparisons
	/// that leak timing.
	///
	/// - Note: `ContiguousBytes` conformance (below) is deliberate and adds no
	///   capability — its sole requirement is `withUnsafeBytes`, which is
	///   already public here. It exists so a secret can be handed to a
	///   `some ContiguousBytes` parameter (swift-crypto's KDFs, AEADs, and
	///   `SymmetricKey.init(data:)`) with no copy and no intermediate `Data`.
	///   Without it the ergonomic path is `withUnsafeBytes { Data($0) }`,
	///   which mints an unscrubbed copy per call on hot paths — a regression
	///   this type exists to prevent. `SymmetricKey` itself conforms for the
	///   same reason (`SymmetricKeys.swift:77`).
	///
	/// - Note: swift-crypto's KDF entry points are not uniform, so the
	///   conformance covers some but not all of them:
	///   - `HKDF.expand(pseudoRandomKey:info:outputByteCount:)` constrains its
	///     key to `ContiguousBytes`, so a `SecretBytes` passes **directly**.
	///   - `HKDF.extract(inputKeyMaterial:salt:)` and
	///     `HKDF.deriveKey(inputKeyMaterial:…)` take a concrete
	///     `SymmetricKey`. Bridge with
	///     `secret.withUnsafeBytes { SymmetricKey(data: $0) }` — that stays in
	///     zeroizing storage the whole way (`SymmetricKey` copies into its own
	///     `SecureBytes`), so it is ceremony, not a plaintext hop. Do **not**
	///     reach for `Data($0)` to satisfy these.
	///
	/// - Important: The conformance has a cost adopters must actively manage.
	///   `SecretBytes` inherits **every public `extension ContiguousBytes`
	///   anywhere in the importing module's dependency graph** — including
	///   ones this package cannot see. A convenience such as
	///   `extension ContiguousBytes { public var dataRepresentation: Data }`
	///   silently becomes a one-property plaintext exit on every secret. Audit
	///   for such extensions when adopting, and shadow any that are reachable:
	///   `extension SecretBytes { @available(*, unavailable, message: "…")
	///   public var dataRepresentation: Data { fatalError() } }` turns the
	///   exit into a compile error without touching the offending package.
	public static func == (lhs: SecretBytes, rhs: SecretBytes) -> Bool {
		// Defense in depth. Both initializers reject a zero-byte secret — one by
		// throwing, one by precondition — so an empty `SecretBytes` should be
		// unconstructible through public API. But if one ever exists,
		// `SymmetricKey`'s constant-time compare returns false for zero-length
		// input, which would make it unequal to *itself* and silently break
		// `Equatable`'s reflexivity requirement. A silent failure is worth four
		// lines of belt and braces. Length is already public via `byteCount`,
		// so branching on it leaks nothing that was secret, and the
		// constant-time path still covers every comparison where both operands
		// actually hold bytes.
		let leftCount = lhs.byteCount
		let rightCount = rhs.byteCount
		guard leftCount > 0, rightCount > 0 else { return leftCount == rightCount }
		return lhs.symmetricKey == rhs.symmetricKey
	}

	public var description: String { "SecretBytes(\(byteCount) bytes)" }

	public var debugDescription: String { description }

	/// Redacted reflection so `dump()`/`Mirror` cannot walk into the bytes.
	public var customMirror: Mirror {
		Mirror(self, children: ["bytes": "\(byteCount) bytes redacted"])
	}
}

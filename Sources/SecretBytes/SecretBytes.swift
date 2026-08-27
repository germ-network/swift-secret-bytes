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
public struct SecretBytes: Sendable, Equatable, CustomStringConvertible,
	CustomDebugStringConvertible, CustomReflectable
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
	public init(bytes: some ContiguousBytes) {
		self.symmetricKey = SymmetricKey(data: bytes)
	}

	/// Generates `count` cryptographically random bytes in zeroizing storage.
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
	public static func == (lhs: SecretBytes, rhs: SecretBytes) -> Bool {
		lhs.symmetricKey == rhs.symmetricKey
	}

	public var description: String { "SecretBytes(\(byteCount) bytes)" }

	public var debugDescription: String { description }

	/// Redacted reflection so `dump()`/`Mirror` cannot walk into the bytes.
	public var customMirror: Mirror {
		Mirror(self, children: ["bytes": "\(byteCount) bytes redacted"])
	}
}

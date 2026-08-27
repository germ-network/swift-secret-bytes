import CSecretBytesZeroize
import Crypto
import Foundation

extension SecretArchive {
	/// The AEAD used by `seal`/`open`. `chaChaPoly` is the default so archives
	/// match the app's default sealing cipher; `aesGCM` is available where a
	/// caller prefers it. The sealed blob is the AEAD's own `combined`
	/// representation (`nonce ‖ ciphertext ‖ tag`) with no extra framing, so
	/// the algorithm is the caller's choice and must match between `seal` and
	/// `open` — it is not encoded in the output.
	public enum SealAlgorithm: Sendable {
		case chaChaPoly
		case aesGCM
	}

	/// The persistence exit: encrypts the archive under `key` and returns AEAD
	/// ciphertext — the only way secret bytes reach ordinary `Data`.
	///
	/// `aad` is authenticated but not encrypted; put a format version and a
	/// domain tag there so archives cannot be confused across contexts. The
	/// plaintext is handed to the AEAD as a no-copy view over the zeroizing
	/// buffer, so no second plaintext copy is made on this side.
	///
	/// - Note: With a random 96-bit nonce, keep well under ~2³² seals per key
	///   to stay clear of the nonce-collision bound. Key custody is the
	///   caller's concern (see `SECURITY.md`).
	public func seal(
		with key: SecretBytes,
		aad: Data,
		using algorithm: SealAlgorithm = .chaChaPoly
	) throws -> Data {
		do {
			return try withUnsafeBytes { raw -> Data in
				let message: Data
				if let base = raw.baseAddress, raw.count > 0 {
					message = Data(
						bytesNoCopy: UnsafeMutableRawPointer(
							mutating: base),
						count: raw.count,
						deallocator: .none
					)
				} else {
					message = Data()
				}
				switch algorithm {
				case .chaChaPoly:
					return try ChaChaPoly.seal(
						message, using: key.symmetricKey,
						authenticating: aad
					).combined
				case .aesGCM:
					guard
						let combined = try AES.GCM.seal(
							message, using: key.symmetricKey,
							authenticating: aad
						).combined
					else { throw SecretArchiveError.sealFailure }
					return combined
				}
			}
		} catch let error as SecretArchiveError {
			throw error
		} catch {
			throw SecretArchiveError.sealFailure
		}
	}

	/// Restores an archive from `seal`ed ciphertext. `key`, `aad`, and
	/// `algorithm` must match the seal, or this throws `.authenticationFailure`.
	///
	/// swift-crypto's only public AEAD decrypt returns `Data`, so one transient
	/// plaintext copy is unavoidable here. It is copied into zeroizing storage
	/// and then scrubbed while it is the sole owner of its buffer — best-effort,
	/// and recorded as a named residue in `SECURITY.md`.
	public static func open(
		_ ciphertext: Data,
		with key: SecretBytes,
		aad: Data,
		using algorithm: SealAlgorithm = .chaChaPoly
	) throws -> SecretArchive {
		// `plaintext` is the sole owner of its buffer here (the decrypt result is
		// never aliased or escaped), so the scrub below mutates in place rather
		// than a CoW copy. Keep it that way: do not retain `plaintext` past the
		// archive copy, or the scrub would miss the real transient.
		var plaintext = try decrypt(ciphertext, with: key, aad: aad, using: algorithm)
		defer {
			plaintext.withUnsafeMutableBytes { raw in
				gsb_secure_zero(raw.baseAddress, raw.count)
			}
		}
		// The archive copy is fully constructed before this returns; the defer
		// then scrubs the transient. Copy-then-scrub, in that order.
		return SecretArchive(unsafeUninitializedCapacity: plaintext.count) {
			buffer, count in
			if let destination = buffer.baseAddress, plaintext.count > 0 {
				plaintext.withUnsafeBytes { source in
					destination.copyMemory(
						from: source.baseAddress!, byteCount: source.count)
				}
			}
			count = plaintext.count
		}
	}

	/// Splits container-parse failure (`malformedCiphertext`) from
	/// authentication failure so `open` is not a distinguishing oracle: wrong
	/// key, wrong AAD, and tampering all surface as `authenticationFailure`.
	private static func decrypt(
		_ ciphertext: Data,
		with key: SecretBytes,
		aad: Data,
		using algorithm: SealAlgorithm
	) throws -> Data {
		switch algorithm {
		case .chaChaPoly:
			let box: ChaChaPoly.SealedBox
			do {
				box = try ChaChaPoly.SealedBox(combined: ciphertext)
			} catch {
				throw SecretArchiveError.malformedCiphertext
			}
			do {
				return try ChaChaPoly.open(
					box, using: key.symmetricKey, authenticating: aad)
			} catch {
				throw SecretArchiveError.authenticationFailure
			}
		case .aesGCM:
			let box: AES.GCM.SealedBox
			do {
				box = try AES.GCM.SealedBox(combined: ciphertext)
			} catch {
				throw SecretArchiveError.malformedCiphertext
			}
			do {
				return try AES.GCM.open(
					box, using: key.symmetricKey, authenticating: aad)
			} catch {
				throw SecretArchiveError.authenticationFailure
			}
		}
	}
}

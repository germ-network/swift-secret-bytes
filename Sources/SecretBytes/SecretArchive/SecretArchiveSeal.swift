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
	/// The AEAD runs **in place** over the archive's own zeroizing buffer where
	/// the span surface exists (swift-crypto 5 on non-CryptoKit platforms;
	/// CryptoKit at runtime on OS 27 or newer on Darwin), so the plaintext only
	/// ever exists in zeroizing memory — no transient `Data`. Everywhere else —
	/// including a Darwin build against a pre-Xcode-27 SDK, which takes the
	/// fallback unconditionally regardless of the runtime OS — swift-crypto's
	/// public AEAD decrypt returns `Data`, one transient plaintext copy is
	/// unavoidable, and it is scrubbed while the sole owner of its buffer —
	/// best-effort, recorded as a named residue in `SECURITY.md`.
	public static func open(
		_ ciphertext: Data,
		with key: SecretBytes,
		aad: Data,
		using algorithm: SealAlgorithm = .chaChaPoly
	) throws -> SecretArchive {
		#if canImport(CryptoKit, _version: 383) && compiler(>=6.4)
			// The span surface is OS-27-gated at runtime on Darwin.
			if #available(iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0,
			macCatalyst 27.0,
			visionOS 27.0, *) {
				return try openInPlace(
					ciphertext, with: key, aad: aad, using: algorithm)
			} else {
				return try openWithTransientPlaintext(
					ciphertext, with: key, aad: aad, using: algorithm)
			}
		#elseif canImport(CryptoKit)
			return try openWithTransientPlaintext(
				ciphertext, with: key, aad: aad, using: algorithm)
		#else
			return try openInPlace(
				ciphertext, with: key, aad: aad, using: algorithm)
		#endif
	}

	// The span path, compiled exactly where the span gate is true — see the
	// gate comment in SecretBytesSpan.swift. The two branches below duplicate
	// `openInPlace` body-for-body; the Darwin copy adds OS-27 availability.
	// Keep them in sync.
	#if canImport(CryptoKit, _version: 383) && compiler(>=6.4)
		@available(
			iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0, macCatalyst 27.0,
			visionOS 27.0, *
		)
		/// Decrypts into the archive's own zeroizing storage, in place. The
		/// combined representation is `nonce ‖ ciphertext ‖ tag` (12-byte nonce,
		/// 16-byte tag for both ciphers), matching `SealedBox`'s `combined` —
		/// the fallback path must interoperate byte for byte.
		private static func openInPlace(
			_ ciphertext: Data,
			with key: SecretBytes,
			aad: Data,
			using algorithm: SealAlgorithm
		) throws -> SecretArchive {
			// Container framing, checked before any AEAD work. The fallback's
			// `SealedBox(combined:)` throws below exactly this length.
			guard ciphertext.count >= 12 + 16 else {
				throw SecretArchiveError.malformedCiphertext
			}
			let plaintextCount = ciphertext.count - 12 - 16
			do {
				// The AEAD writes the plaintext over the ciphertext bytes inside
				// the archive's buffer. If it throws, no `SecretArchive` value is
				// produced and the buffer's deinit scrubs the whole allocation,
				// so nothing written so far survives the failure.
				return try SecretArchive(
					unsafeUninitializedCapacity: plaintextCount
				) {
					buffer, count in
					try ciphertext.withUnsafeBytes { combined in
						let base = combined.baseAddress!
						if plaintextCount > 0 {
							buffer.baseAddress?.copyMemory(
								from: base.advanced(by: 12),
								byteCount: plaintextCount)
						}
						let nonceSpan = RawSpan(
							_unsafeBytes: UnsafeRawBufferPointer(
								start: base, count: 12))
						let tagSpan = RawSpan(
							_unsafeBytes: UnsafeRawBufferPointer(
								start: base.advanced(
									by: ciphertext.count - 16),
								count: 16))
						var message = MutableRawSpan(_unsafeBytes: buffer)
						try aad.withUnsafeBytes { aadRaw in
							let aadSpan: RawSpan? =
								aad.isEmpty
								? nil
								: RawSpan(_unsafeBytes: aadRaw)
							switch algorithm {
							case .chaChaPoly:
								try ChaChaPoly.open(
									inPlace: &message,
									using: key.symmetricKey,
									nonce: try ChaChaPoly.Nonce(
										copying: nonceSpan),
									authenticating: aadSpan,
									tag: tagSpan)
							case .aesGCM:
								try AES.GCM.open(
									inPlace: &message,
									using: key.symmetricKey,
									nonce: try AES.GCM.Nonce(
										copying: nonceSpan),
									authenticating: aadSpan,
									tag: tagSpan)
							}
						}
					}
					count = plaintextCount
				}
			} catch {
				// The only throw sources inside are the nonce construction
				// (cannot fail: the nonce slice is exactly 12 bytes for both
				// ciphers) and the AEAD open. Anything that got here is an
				// authentication failure; the underlying error is never surfaced.
				throw SecretArchiveError.authenticationFailure
			}
		}
	#elseif canImport(CryptoKit)
		// Darwin against an older SDK: no span surface, so `openInPlace` is not
		// built and `open` routes to the fallback unconditionally.
	#else
		/// Decrypts into the archive's own zeroizing storage, in place. The
		/// combined representation is `nonce ‖ ciphertext ‖ tag` (12-byte nonce,
		/// 16-byte tag for both ciphers), matching `SealedBox`'s `combined` —
		/// the fallback path must interoperate byte for byte.
		private static func openInPlace(
			_ ciphertext: Data,
			with key: SecretBytes,
			aad: Data,
			using algorithm: SealAlgorithm
		) throws -> SecretArchive {
			// Container framing, checked before any AEAD work. The fallback's
			// `SealedBox(combined:)` throws below exactly this length.
			guard ciphertext.count >= 12 + 16 else {
				throw SecretArchiveError.malformedCiphertext
			}
			let plaintextCount = ciphertext.count - 12 - 16
			do {
				// The AEAD writes the plaintext over the ciphertext bytes inside
				// the archive's buffer. If it throws, no `SecretArchive` value is
				// produced and the buffer's deinit scrubs the whole allocation,
				// so nothing written so far survives the failure.
				return try SecretArchive(
					unsafeUninitializedCapacity: plaintextCount
				) {
					buffer, count in
					try ciphertext.withUnsafeBytes { combined in
						let base = combined.baseAddress!
						if plaintextCount > 0 {
							buffer.baseAddress?.copyMemory(
								from: base.advanced(by: 12),
								byteCount: plaintextCount)
						}
						let nonceSpan = RawSpan(
							_unsafeBytes: UnsafeRawBufferPointer(
								start: base, count: 12))
						let tagSpan = RawSpan(
							_unsafeBytes: UnsafeRawBufferPointer(
								start: base.advanced(
									by: ciphertext.count - 16),
								count: 16))
						var message = MutableRawSpan(_unsafeBytes: buffer)
						try aad.withUnsafeBytes { aadRaw in
							let aadSpan: RawSpan? =
								aad.isEmpty
								? nil
								: RawSpan(_unsafeBytes: aadRaw)
							switch algorithm {
							case .chaChaPoly:
								try ChaChaPoly.open(
									inPlace: &message,
									using: key.symmetricKey,
									nonce: try ChaChaPoly.Nonce(
										copying: nonceSpan),
									authenticating: aadSpan,
									tag: tagSpan)
							case .aesGCM:
								try AES.GCM.open(
									inPlace: &message,
									using: key.symmetricKey,
									nonce: try AES.GCM.Nonce(
										copying: nonceSpan),
									authenticating: aadSpan,
									tag: tagSpan)
							}
						}
					}
					count = plaintextCount
				}
			} catch {
				// The only throw sources inside are the nonce construction
				// (cannot fail: the nonce slice is exactly 12 bytes for both
				// ciphers) and the AEAD open. Anything that got here is an
				// authentication failure; the underlying error is never surfaced.
				throw SecretArchiveError.authenticationFailure
			}
		}
	#endif

	/// The pre-OS-27 fallback: same framing and error split, but the plaintext
	/// transits one transient, scrubbed `Data` — see `open`'s discussion.
	private static func openWithTransientPlaintext(
		_ ciphertext: Data,
		with key: SecretBytes,
		aad: Data,
		using algorithm: SealAlgorithm
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

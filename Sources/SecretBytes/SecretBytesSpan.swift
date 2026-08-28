// Span-based CryptoKit API, adopted where the SDK provides it. The compile
// gate needs both halves: CryptoKit (Darwin — swift-crypto has no counterpart,
// so Linux keeps the portable path) and the Xcode 27 toolchain (Swift 6.4+),
// whose SDK is the first to declare these members. The deployment floor is
// unchanged; callers on earlier OS versions gate with `if #available`.
#if canImport(CryptoKit) && compiler(>=6.4)
	import Crypto

	@available(
		iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0, macCatalyst 27.0, visionOS 27.0, *
	)
	extension SecretBytes {
		// Forwarding SymmetricKey's `bytes: RawSpan` is deliberately absent:
		// returning a ~Escapable requires the experimental Lifetimes feature,
		// which a library should not ship. Revisit when it stabilizes.

		/// Copies `bytes` into zeroizing storage and zeroes the source span —
		/// a consume-style init for producers holding a secret in ordinary
		/// memory. The source scrub is CryptoKit's own.
		public init(copyingWithZeroing bytes: inout MutableRawSpan) {
			self.symmetricKey = SymmetricKey(copyingWithZeroing: &bytes)
		}

		/// Creates `byteCount` secret bytes by writing directly into the final
		/// zeroizing allocation — no staging buffer exists at any point. The
		/// callback must fill the span completely.
		public init<E: Error>(
			byteCount: Int,
			initializingWith callback: (inout OutputRawSpan) throws(E) -> Void
		) throws(E) {
			precondition(byteCount > 0, "SecretBytes must hold at least one byte")
			self.symmetricKey = try SymmetricKey(
				size: .init(bitCount: byteCount * 8), initializingWith: callback)
		}
	}
#endif

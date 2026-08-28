// Span-based CryptoKit API, adopted where the SDK provides it. The compile
// gate needs both halves: CryptoKit (Darwin — swift-crypto has no counterpart,
// so Linux keeps the portable path) and CryptoKit's OS-27 module version,
// which is the first to declare these members. `_version: 383` is the
// `-user-module-version` CryptoKit ships with the Xcode 27 beta 6 SDK — a
// toolchain(>=6.4) check alone is insufficient, since a 6.4 toolchain paired
// with an older SDK (a mixed DEVELOPER_DIR/SDKROOT, a swift.org snapshot) has
// the language feature but not the members, which would otherwise fail the
// whole package to compile. Bump this if a later SDK changes the version and
// the gate stops tracking availability. The deployment floor is unchanged;
// callers on earlier OS versions gate with `if #available`.
#if canImport(CryptoKit, _version: 383) && compiler(>=6.4)
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
		/// callback must fill the span completely; a short fill traps rather
		/// than silently producing a weaker key.
		public init<E: Error>(
			byteCount: Int,
			initializingWith callback: (inout OutputRawSpan) throws(E) -> Void
		) throws(E) {
			precondition(byteCount > 0, "SecretBytes must hold at least one byte")
			self.symmetricKey = try SymmetricKey(size: .init(bitCount: byteCount * 8)) {
				(span: inout OutputRawSpan) throws(E) in
				try callback(&span)
				precondition(
					span.isFull,
					"initializingWith callback filled \(span.byteCount) of \(byteCount) bytes"
				)
			}
		}
	}
#endif

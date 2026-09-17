// Span-based Crypto API, adopted where the platform provides it.
//
// The span gate — spelled exactly `canImport(CryptoKit, _version: 383) &&
// compiler(>=6.4)` — is true exactly where the span surface below exists at
// compile time: on Darwin against the Xcode-27-or-newer SDK (where the
// members come from the SDK's CryptoKit and carry OS-27 availability), and on
// every non-CryptoKit platform, where swift-crypto 5.0 declares them
// unconditionally in its own BoringSSL-backed module. It is false on Darwin
// against an older SDK: a 6.4 toolchain alone is not sufficient there (a
// mixed DEVELOPER_DIR/SDKROOT, a swift.org snapshot has the language feature
// but not the members), which is why the gate checks the module version and
// not the compiler alone. Bump the version by find-replacing the gate string
// at every site — the sites, all spelling it in this positive form:
//   - Sources/SecretBytes/SecretBytesSpan.swift (here, twice)
//   - Sources/SecretBytes/SecretArchive/SecretArchiveSeal.swift (twice)
//   - Tests/SecretBytesTests/SpanAPITests.swift (once)
// The deployment floor is unchanged; callers on earlier OS versions gate
// with `if #available`.
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
		/// memory. The source scrub is the Crypto implementation's own
		/// (CryptoKit on Darwin, swift-crypto's zeroize on Linux).
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
#elseif canImport(CryptoKit)
	// Darwin against an older SDK: CryptoKit lacks these members, and
	// swift-crypto compiles its own declarations out on Darwin — no span
	// surface to build.
#else
	import Crypto

	// Same surface as the Darwin branch above, ungated: swift-crypto declares
	// these members unconditionally on non-CryptoKit platforms. The two bodies
	// must stay in sync.
	extension SecretBytes {
		// Forwarding SymmetricKey's `bytes: RawSpan` is deliberately absent:
		// returning a ~Escapable requires the experimental Lifetimes feature,
		// which a library should not ship. Revisit when it stabilizes.

		/// Copies `bytes` into zeroizing storage and zeroes the source span —
		/// a consume-style init for producers holding a secret in ordinary
		/// memory. The source scrub is the Crypto implementation's own
		/// (CryptoKit on Darwin, swift-crypto's zeroize on Linux).
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

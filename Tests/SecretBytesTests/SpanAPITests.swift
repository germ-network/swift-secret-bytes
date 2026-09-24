// Same span gate as SecretBytesSpan.swift (see the gate comment there for the
// full site list): compiled wherever the span surface exists. On Linux the
// members are ungated, so these run; on Darwin they run only at OS 27+ and
// skip below it.
#if canImport(CryptoKit, _version: 383) && compiler(>=6.4)
	import Testing

	@testable import SecretBytes

	/// Exercises the span-based API adoption. On Darwin these run only where the
	/// OS 27 runtime is present (locally and the iOS 27 simulator CI legs);
	/// elsewhere they skip. On Linux the members are always available, so the
	/// availability guard passes trivially and the tests always run.
	@Suite struct SpanAPITests {
		@Test func copyingWithZeroingRoundTripsAndZeroesSource() throws {
			guard
				#available(iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0,
				macCatalyst 27.0, visionOS 27.0, *)
			else {
				try Test.cancel("requires the OS 27 runtime")
			}
			var source: [UInt8] = Array(repeating: 0xAB, count: 32)
			var elementSpan = source.mutableSpan
			var span = elementSpan.mutableBytes
			let secret = SecretBytes(copyingWithZeroing: &span)
			#expect(secret.byteCount == 32)
			#expect(
				secret.withUnsafeBytes { [UInt8]($0) }
					== [UInt8](repeating: 0xAB, count: 32)
			)
			// Pins CryptoKit's documented behavior: the source is zeroed.
			#expect(
				source.allSatisfy { $0 == 0 },
				"copyingWithZeroing left the source span unscrubbed"
			)
		}

		@Test func initializingWithWritesDirectlyIntoKey() throws {
			guard
				#available(iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0,
				macCatalyst 27.0, visionOS 27.0, *)
			else {
				try Test.cancel("requires the OS 27 runtime")
			}
			let secret = SecretBytes(byteCount: 16) { span in
				for byte in UInt8(0)..<16 {
					span.append(byte)
				}
			}
			#expect(secret.byteCount == 16)
			#expect(
				secret.withUnsafeBytes { [UInt8]($0) }
					== Array(UInt8(0)..<16)
			)
		}
	}
#endif

import CSecretBytesZeroize
import Testing

@testable import SecretBytes

/// Mutation-verifiable tests for the zeroizing storage. Every check reads only
/// live memory — the scrub is exercised on buffers that are still alive, and
/// the deinit path reports its own post-scrub state from inside `deinit` — so
/// nothing here relies on reading freed memory. Each test fails if the
/// corresponding scrub is removed.
///
/// `.serialized`: the two witness-based tests below share a single
/// `ScrubWitness.lastDeinitAllZero` slot, so they must not run concurrently
/// with *each other* (cross-suite concurrency is separately handled by
/// `ScrubWitness.armed` being task-local — see its doc comment).
@Suite(.serialized) struct ZeroizationTests {
	@Test func secureZeroPrimitiveZeroesMemory() {
		var bytes = [UInt8](repeating: 0xA5, count: 64)
		bytes.withUnsafeMutableBytes { raw in
			gsb_secure_zero(raw.baseAddress, raw.count)
		}
		#expect(bytes.allSatisfy { $0 == 0 }, "gsb_secure_zero left non-zero bytes")
	}

	@Test func secureZeroIgnoresNullAndZeroLength() {
		gsb_secure_zero(nil, 0)  // must not crash
		var one: [UInt8] = [0xFF]
		one.withUnsafeMutableBytes { raw in
			gsb_secure_zero(raw.baseAddress, 0)  // len 0 -> no write
		}
		#expect(one[0] == 0xFF)
	}

	@Test func scrubZeroesLiveBuffer() {
		let buffer = ZeroizingBuffer.filledForTesting(byteCount: 256, with: 0xA5)
		#expect(!buffer.allZeroForTesting(), "sentinel fill failed")
		buffer.scrub()
		#expect(buffer.allZeroForTesting(), "scrub() left non-zero bytes")
	}

	// The two tests below observe the deinit scrub through `ScrubWitness`,
	// which is `#if DEBUG` in the library: a release binary deliberately
	// carries no channel for reading memory that just held a secret. The scrub
	// itself is not configuration-dependent — only the ability to watch it —
	// so gating these costs no coverage of shipped behaviour, and it is what
	// lets the rest of the suite run under `-c release`, where the encoder's
	// self-validation net is absent and every guard stands alone.
	#if DEBUG

		/// The load-bearing mutation test: if `deinit` stops scrubbing, the
		/// witness reads back non-zero and this fails.
		@Test func deinitScrubsBeforeRelease() {
			ZeroizingBuffer.ScrubWitness.$armed.withValue(true) {
				ZeroizingBuffer.ScrubWitness.lastDeinitAllZero = nil

				do {
					let buffer = ZeroizingBuffer.filledForTesting(
						byteCount: 256, with: 0xA5)
					#expect(!buffer.allZeroForTesting())
					withExtendedLifetime(buffer) {}
				}  // released here -> deinit scrubs and records the witness

				#expect(
					ZeroizingBuffer.ScrubWitness.lastDeinitAllZero == true,
					"deinit did not scrub the buffer before release"
				)
			}
		}

		/// Encoding allocates the archive buffer exactly once — no growth, so no
		/// abandoned allocations — and the finished archive scrubs on release.
		@Test func archiveBufferScrubsOnRelease() throws {
			try ZeroizingBuffer.ScrubWitness.$armed.withValue(true) {
				ZeroizingBuffer.ScrubWitness.lastDeinitAllZero = nil

				struct Holder: Codable { @SecretField var secret: SecretBytes }
				do {
					let archive = try SecretArchive(
						encoding: Holder(
							secret: try SecretBytes(
								bytes: [UInt8](
									repeating: 0x5A, count: 64))
						)
					)
					withExtendedLifetime(archive) {}
				}  // released here -> deinit scrubs and records the witness

				#expect(
					ZeroizingBuffer.ScrubWitness.lastDeinitAllZero == true,
					"the archive allocation was released without scrubbing")
			}
		}

	#endif
}

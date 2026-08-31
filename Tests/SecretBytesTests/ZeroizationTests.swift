import CSecretBytesZeroize
import XCTest

@testable import SecretBytes

/// Mutation-verifiable tests for the zeroizing storage. Every check reads only
/// live memory — the scrub is exercised on buffers that are still alive, and
/// the deinit path reports its own post-scrub state from inside `deinit` — so
/// nothing here relies on reading freed memory. Each test fails if the
/// corresponding scrub is removed.
final class ZeroizationTests: XCTestCase {
	func testSecureZeroPrimitiveZeroesMemory() {
		var bytes = [UInt8](repeating: 0xA5, count: 64)
		bytes.withUnsafeMutableBytes { raw in
			gsb_secure_zero(raw.baseAddress, raw.count)
		}
		XCTAssertTrue(bytes.allSatisfy { $0 == 0 }, "gsb_secure_zero left non-zero bytes")
	}

	func testSecureZeroIgnoresNullAndZeroLength() {
		gsb_secure_zero(nil, 0)  // must not crash
		var one: [UInt8] = [0xFF]
		one.withUnsafeMutableBytes { raw in
			gsb_secure_zero(raw.baseAddress, 0)  // len 0 -> no write
		}
		XCTAssertEqual(one[0], 0xFF)
	}

	func testScrubZeroesLiveBuffer() {
		let buffer = ZeroizingBuffer.filledForTesting(byteCount: 256, with: 0xA5)
		XCTAssertFalse(buffer.allZeroForTesting(), "sentinel fill failed")
		buffer.scrub()
		XCTAssertTrue(buffer.allZeroForTesting(), "scrub() left non-zero bytes")
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
		func testDeinitScrubsBeforeRelease() {
			ZeroizingBuffer.ScrubWitness.lastDeinitAllZero = nil
			ZeroizingBuffer.ScrubWitness.armed = true
			defer { ZeroizingBuffer.ScrubWitness.armed = false }

			do {
				let buffer = ZeroizingBuffer.filledForTesting(
					byteCount: 256, with: 0xA5)
				XCTAssertFalse(buffer.allZeroForTesting())
				withExtendedLifetime(buffer) {}
			}  // released here -> deinit scrubs and records the witness

			XCTAssertEqual(
				ZeroizingBuffer.ScrubWitness.lastDeinitAllZero, true,
				"deinit did not scrub the buffer before release"
			)
		}

		/// Encoding allocates the archive buffer exactly once — no growth, so no
		/// abandoned allocations — and the finished archive scrubs on release.
		func testArchiveBufferScrubsOnRelease() throws {
			ZeroizingBuffer.ScrubWitness.lastDeinitAllZero = nil
			ZeroizingBuffer.ScrubWitness.armed = true
			defer { ZeroizingBuffer.ScrubWitness.armed = false }

			struct Holder: Codable { @SecretField var secret: SecretBytes }
			do {
				let archive = try SecretArchive(
					encoding: Holder(
						secret: try SecretBytes(
							bytes: [UInt8](repeating: 0x5A, count: 64)))
				)
				withExtendedLifetime(archive) {}
			}  // released here -> deinit scrubs and records the witness

			XCTAssertEqual(
				ZeroizingBuffer.ScrubWitness.lastDeinitAllZero, true,
				"the archive allocation was released without scrubbing")
		}

	#endif
}

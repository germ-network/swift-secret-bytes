import CSecretBytesZeroize

/// Appendable heap storage that scrubs its full allocation on release.
///
/// This is the one piece of swift-crypto's internal `SecureBytes` we
/// reimplement — its default backing is the same shape: a
/// `ManagedBuffer<_, UInt8>` subclass whose `deinit` zeroes the buffer. ARC
/// frees the tail allocation after `deinit` returns, so the class only has to
/// scrub, never deallocate. The scrub covers the entire allocated `capacity`
/// (not just the written `count`), so bytes left in slack after a shrink are
/// still cleared.
///
/// Not thread-safe and deliberately not `Sendable`: a single `Writer`/`Reader`
/// owns one buffer at a time.
final class ZeroizingBuffer: ManagedBuffer<Int, UInt8> {
	/// Allocates a buffer that can hold at least `minimumCapacity` bytes,
	/// with a written count of zero.
	static func allocate(minimumCapacity: Int) -> ZeroizingBuffer {
		let requested = Swift.max(1, minimumCapacity)
		let object = ZeroizingBuffer.create(minimumCapacity: requested) { _ in 0 }
		return unsafeDowncast(object, to: ZeroizingBuffer.self)
	}

	/// Number of bytes written so far. The header stores nothing else.
	var count: Int {
		get { header }
		set { header = newValue }
	}

	/// Best-effort zeroing of the whole allocation. `deinit` calls this; tests
	/// call it directly on a live buffer so the scrub is observable without
	/// reading freed memory.
	func scrub() {
		let capacity = self.capacity
		withUnsafeMutablePointerToElements { elements in
			gsb_secure_zero(elements, capacity)
		}
	}

	deinit {
		scrub()
		#if DEBUG
			// The scrub above ran on still-valid memory; read it back here,
			// before ARC frees the allocation, so a test can confirm the deinit
			// path actually zeroed the bytes without ever touching freed memory.
			if ScrubWitness.armed {
				let capacity = self.capacity
				ScrubWitness.lastDeinitAllZero = withUnsafeMutablePointerToElements
				{ elements in
					UnsafeRawBufferPointer(start: elements, count: capacity)
						.allSatisfy { $0 == 0 }
				}
			}
		#endif
	}
}

#if DEBUG
	extension ZeroizingBuffer {
		/// Test-only channel for observing the deinit scrub. `armed` gates the
		/// observation so only the buffer under test records into it.
		enum ScrubWitness {
			nonisolated(unsafe) static var armed = false
			nonisolated(unsafe) static var lastDeinitAllZero: Bool?
		}

		/// Allocates a buffer with its whole capacity filled with `sentinel`.
		static func filledForTesting(byteCount: Int, with sentinel: UInt8)
			-> ZeroizingBuffer
		{
			let buffer = allocate(minimumCapacity: byteCount)
			buffer.withUnsafeMutablePointerToElements { elements in
				UnsafeMutableRawBufferPointer(
					start: elements, count: buffer.capacity
				)
				.initializeMemory(as: UInt8.self, repeating: sentinel)
			}
			buffer.count = byteCount
			return buffer
		}

		/// True iff every byte of the allocation is zero.
		func allZeroForTesting() -> Bool {
			let capacity = self.capacity
			return withUnsafeMutablePointerToElements { elements in
				UnsafeRawBufferPointer(start: elements, count: capacity).allSatisfy
				{ $0 == 0 }
			}
		}
	}
#endif

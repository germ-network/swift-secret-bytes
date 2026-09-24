import Crypto
import Foundation
import Testing

@testable import SecretBytes

/// The migration ingress: `init(decodingPlaintext:)` wraps already-plaintext
/// archive bytes (another implementation's export) so `decode` can read them —
/// the mirror of `open`'s sealed egress, but with no key, for a trusted export.
@Suite struct SecretArchivePlaintextIngressTests {
	private func sample() throws -> Epoch {
		Epoch(
			index: 42, flags: 7,
			key: try SecretBytes(bytes: [UInt8](repeating: 0x5A, count: 32)),
			sealingKey: SymmetricKey(size: .bits256),
			label: [1, 2, 3, 4],
			inner: .init(
				counter: 99,
				secret: try SecretBytes(bytes: [UInt8](repeating: 0xA5, count: 16)))
		)
	}

	/// The plaintext bytes an archive encodes to round-trip back in through
	/// `decodingPlaintext`, secret fields intact.
	@Test func plaintextIngressRoundTrips() throws {
		let value = try sample()
		let plaintext = try SecretArchive(encoding: value).withUnsafeBytes { Data($0) }
		let ingested = SecretArchive(decodingPlaintext: plaintext)
		#expect(try ingested.decode(Epoch.self) == value)
	}

	/// Ingress only copies; validation is deferred to `decode`, so a malformed
	/// document is rejected there rather than trusted for having been ingested.
	@Test func malformedPlaintextRejectedOnDecode() throws {
		let ingested = SecretArchive(decodingPlaintext: Data([0xFF, 0x00, 0x13, 0x37]))
		#expect(throws: (any Error).self) {
			try ingested.decode(Epoch.self)
		}
	}

	@Test func emptyPlaintextRejectedOnDecode() throws {
		let ingested = SecretArchive(decodingPlaintext: Data())
		#expect(throws: (any Error).self) {
			try ingested.decode(Epoch.self)
		}
	}
}

import Crypto
import Foundation
import XCTest

@testable import SecretBytes

/// The persistence exit. The AEAD errors are deliberately coarse — wrong key,
/// wrong AAD and tampering are indistinguishable — so `open` is not an oracle.
final class SecretArchiveSealTests: XCTestCase {
	private var key: SecretBytes {
		try! SecretBytes(bytes: [UInt8](repeating: 0x2B, count: 32))
	}
	private let aad = Data("v1|epoch-archive".utf8)
	private let algorithms: [SecretArchive.SealAlgorithm] = [.chaChaPoly, .aesGCM]

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

	func testSealOpenRoundTrip() throws {
		for algorithm in algorithms {
			let value = try sample()
			let sealed = try SecretArchive(encoding: value)
				.seal(with: key, aad: aad, using: algorithm)
			let restored = try SecretArchive.open(
				sealed, with: key, aad: aad, using: algorithm
			)
			.decode(Epoch.self)
			XCTAssertEqual(restored, value, "algorithm \(algorithm)")
		}
	}

	func testCiphertextCarriesAEADOverhead() throws {
		for algorithm in algorithms {
			let archive = try SecretArchive(encoding: try sample())
			let plaintextLength = archive.withUnsafeBytes { $0.count }
			let sealed = try archive.seal(with: key, aad: aad, using: algorithm)
			// nonce(12) + tag(16)
			XCTAssertEqual(sealed.count, plaintextLength + 28, "algorithm \(algorithm)")
		}
	}

	func testWrongAADRejected() throws {
		for algorithm in algorithms {
			let sealed = try SecretArchive(encoding: try sample())
				.seal(with: key, aad: aad, using: algorithm)
			XCTAssertThrowsError(
				try SecretArchive.open(
					sealed, with: key, aad: Data("v2".utf8), using: algorithm)
			) { XCTAssertEqual($0 as? SecretArchiveError, .authenticationFailure) }
		}
	}

	func testWrongKeyRejected() throws {
		let other = try SecretBytes(bytes: [UInt8](repeating: 0x3C, count: 32))
		for algorithm in algorithms {
			let sealed = try SecretArchive(encoding: try sample())
				.seal(with: key, aad: aad, using: algorithm)
			XCTAssertThrowsError(
				try SecretArchive.open(
					sealed, with: other, aad: aad, using: algorithm)
			) { XCTAssertEqual($0 as? SecretArchiveError, .authenticationFailure) }
		}
	}

	func testTamperedCiphertextRejected() throws {
		for algorithm in algorithms {
			var sealed = try SecretArchive(encoding: try sample())
				.seal(with: key, aad: aad, using: algorithm)
			sealed[sealed.count - 1] ^= 0x01
			XCTAssertThrowsError(
				try SecretArchive.open(
					sealed, with: key, aad: aad, using: algorithm)
			) { XCTAssertEqual($0 as? SecretArchiveError, .authenticationFailure) }
		}
	}

	func testTruncatedCiphertextRejectedAsMalformed() throws {
		for algorithm in algorithms {
			let sealed = try SecretArchive(encoding: try sample())
				.seal(with: key, aad: aad, using: algorithm)
			// Below the 28-byte minimum AEAD container.
			XCTAssertThrowsError(
				try SecretArchive.open(
					Data(sealed.prefix(20)), with: key, aad: aad,
					using: algorithm)
			) { XCTAssertEqual($0 as? SecretArchiveError, .malformedCiphertext) }
		}
	}

	/// The algorithm is not encoded in the output, so seal and open must agree;
	/// a mismatch must fail authentication rather than silently decode.
	func testCrossAlgorithmDoesNotOpen() throws {
		let sealed = try SecretArchive(encoding: try sample())
			.seal(with: key, aad: aad, using: .chaChaPoly)
		XCTAssertThrowsError(
			try SecretArchive.open(sealed, with: key, aad: aad, using: .aesGCM)
		) { XCTAssertEqual($0 as? SecretArchiveError, .authenticationFailure) }
	}
}

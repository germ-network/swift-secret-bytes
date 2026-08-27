import Foundation
import XCTest

@testable import SecretBytes

final class SecretArchiveSealTests: XCTestCase {
	private let key = SecretBytes(bytes: [UInt8](repeating: 0x2B, count: 32))
	private let aad = Data("v1|epoch-archive".utf8)

	private func sampleEpoch() -> Epoch {
		Epoch(
			index: 42,
			flags: 7,
			key: SecretBytes(bytes: [UInt8](repeating: 0x5A, count: 32)),
			label: [1, 2, 3, 4],
			inner: Epoch.Inner(
				counter: 99,
				secret: SecretBytes(bytes: [UInt8](repeating: 0xA5, count: 16)))
		)
	}

	private let algorithms: [SecretArchive.SealAlgorithm] = [.chaChaPoly, .aesGCM]

	func testSealOpenRoundTrip() throws {
		for algorithm in algorithms {
			let epoch = sampleEpoch()
			let ciphertext = try SecretArchive(archiving: epoch).seal(
				with: key, aad: aad, using: algorithm)
			let restored = try SecretArchive.open(
				ciphertext, with: key, aad: aad, using: algorithm
			)
			.restore(Epoch.self)
			XCTAssertEqual(restored, epoch, "algorithm \(algorithm)")
		}
	}

	func testDefaultAlgorithmIsChaChaPoly() throws {
		let epoch = sampleEpoch()
		let ciphertext = try SecretArchive(archiving: epoch).seal(with: key, aad: aad)
		// Opening with an explicit ChaChaPoly must succeed on the default output.
		let restored = try SecretArchive.open(
			ciphertext, with: key, aad: aad, using: .chaChaPoly
		)
		.restore(Epoch.self)
		XCTAssertEqual(restored, epoch)
	}

	func testCiphertextIsNotPlaintextAndCarriesOverhead() throws {
		for algorithm in algorithms {
			let archive = SecretArchive(archiving: sampleEpoch())
			let plaintextLength = archive.withUnsafeBytes { $0.count }
			let ciphertext = try archive.seal(with: key, aad: aad, using: algorithm)
			// nonce(12) + tag(16) overhead over the plaintext.
			XCTAssertEqual(
				ciphertext.count, plaintextLength + 12 + 16,
				"algorithm \(algorithm)")
		}
	}

	func testWrongAADRejected() throws {
		for algorithm in algorithms {
			let ciphertext = try SecretArchive(archiving: sampleEpoch()).seal(
				with: key, aad: aad, using: algorithm)
			XCTAssertThrowsError(
				try SecretArchive.open(
					ciphertext, with: key, aad: Data("v2|other".utf8),
					using: algorithm)
			) { error in
				XCTAssertEqual(
					error as? SecretArchiveError, .authenticationFailure,
					"algorithm \(algorithm)")
			}
		}
	}

	func testWrongKeyRejected() throws {
		let otherKey = SecretBytes(bytes: [UInt8](repeating: 0x3C, count: 32))
		for algorithm in algorithms {
			let ciphertext = try SecretArchive(archiving: sampleEpoch()).seal(
				with: key, aad: aad, using: algorithm)
			XCTAssertThrowsError(
				try SecretArchive.open(
					ciphertext, with: otherKey, aad: aad, using: algorithm)
			) { error in
				XCTAssertEqual(
					error as? SecretArchiveError, .authenticationFailure,
					"algorithm \(algorithm)")
			}
		}
	}

	func testTamperedCiphertextRejected() throws {
		for algorithm in algorithms {
			var ciphertext = try SecretArchive(archiving: sampleEpoch()).seal(
				with: key, aad: aad, using: algorithm)
			ciphertext[ciphertext.count - 1] ^= 0x01  // flip a tag bit
			XCTAssertThrowsError(
				try SecretArchive.open(
					ciphertext, with: key, aad: aad, using: algorithm)
			) { error in
				XCTAssertEqual(
					error as? SecretArchiveError, .authenticationFailure,
					"algorithm \(algorithm)")
			}
		}
	}

	func testTruncatedCiphertextRejectedAsMalformed() throws {
		for algorithm in algorithms {
			let ciphertext = try SecretArchive(archiving: sampleEpoch()).seal(
				with: key, aad: aad, using: algorithm)
			// 20 bytes is below the 28-byte minimum AEAD container.
			let truncated = ciphertext.prefix(20)
			XCTAssertThrowsError(
				try SecretArchive.open(
					Data(truncated), with: key, aad: aad, using: algorithm)
			) { error in
				XCTAssertEqual(
					error as? SecretArchiveError, .malformedCiphertext,
					"algorithm \(algorithm)")
			}
		}
	}

	func testCrossAlgorithmDoesNotOpen() throws {
		// Sealed with ChaChaPoly, opened as AES-GCM: same combined shape, but
		// authentication must fail rather than silently decode.
		let ciphertext = try SecretArchive(archiving: sampleEpoch()).seal(
			with: key, aad: aad, using: .chaChaPoly)
		XCTAssertThrowsError(
			try SecretArchive.open(ciphertext, with: key, aad: aad, using: .aesGCM)
		) { error in
			XCTAssertEqual(error as? SecretArchiveError, .authenticationFailure)
		}
	}
}

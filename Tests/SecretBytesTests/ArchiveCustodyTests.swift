import Crypto
import Foundation
import Testing

@testable import SecretBytes

/// The custody guarantees: secrets reach the archive and nothing else, for
/// every `Value` type and at every nesting position.
@Suite struct ArchiveCustodyTests {

	// MARK: The tripwire

	/// A secret-bearing type handed to a foreign coder must throw *before*
	/// writing anything — for every `Value`, since the carrier's `Codable`
	/// conformance is unconditional in `Value` precisely so genericity cannot
	/// weaken it.
	@Test func tripwireFiresForEverySecretType() throws {
		struct AsSecret: Codable { @SecretField var k: SecretBytes }
		struct AsKey: Codable { @SecretField var k: SymmetricKey }

		#expect(throws: (any Error).self) {
			try JSONEncoder().encode(AsSecret(k: try SecretBytes(bytes: [1, 2, 3])))
		}
		#expect(throws: (any Error).self) {
			try JSONEncoder().encode(AsKey(k: SymmetricKey(size: .bits256)))
		}
	}

	/// The tripwire must not have written a partial document containing the
	/// secret before throwing.
	@Test func foreignEncoderWritesNoSecretBytes() throws {
		struct Holder: Codable {
			var before = "x"
			@SecretField var k: SecretBytes
		}
		let secret: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
		do {
			_ = try JSONEncoder().encode(Holder(k: try SecretBytes(bytes: secret)))
			Issue.record("expected the tripwire to fire")
		} catch {
			#expect(error as? SecretArchiveError == .secretOutsideSecretArchive)
		}
	}

	@Test func tripwireOnDecodeToo() throws {
		struct Holder: Codable { @SecretField var k: SecretBytes }
		#expect(throws: (any Error).self) {
			try JSONDecoder().decode(Holder.self, from: Data(#"{"k":"AAAA"}"#.utf8))
		}
	}

	// MARK: Funnel reachability

	/// Interception happens in the coder's funnel, so it must compose through
	/// every container shape without special-casing.
	@Test func secretsRoundTripAtEveryNestingPosition() throws {
		struct Deep: Codable, Equatable {
			@SecretField var top: SecretBytes
			var optional: SecretField<SecretBytes>?
			var absent: SecretField<SecretBytes>?
			var array: [SecretField<SecretBytes>]
			var dictionary: [String: SecretField<SecretBytes>]
			var nested: Nested
			var payload: Payload

			struct Nested: Codable, Equatable { @SecretField var inner: SymmetricKey }
			enum Payload: Codable, Equatable { case some(SecretField<SecretBytes>) }
		}

		let s = { try SecretBytes(bytes: [UInt8](repeating: 0x7C, count: 16)) }
		let value = Deep(
			top: try s(),
			optional: SecretField(wrappedValue: try s()),
			absent: nil,
			array: [SecretField(wrappedValue: try s())],
			dictionary: ["a": SecretField(wrappedValue: try s())],
			nested: .init(inner: SymmetricKey(size: .bits256)),
			payload: .some(SecretField(wrappedValue: try s())))

		let restored = try SecretArchive(encoding: value).decode(Deep.self)
		#expect(restored == value)
		#expect(restored.absent == nil)
	}

	/// A plain value must not be intercepted — pins the seam's negative space.
	@Test func plainValuesAreNotIntercepted() throws {
		struct Plain: Codable, Equatable {
			var n: Int
			var s: String
			var d: Data
		}
		let value = Plain(n: -7, s: "hello", d: Data([1, 2, 3]))
		#expect(try SecretArchive(encoding: value).decode(Plain.self) == value)
	}

	// MARK: Per-type restore invariants

	/// Zero-length secrets are a *Value* invariant, not a format rule. The wire
	/// permits a zero-length byte string; `SymmetricKey` accepts one and
	/// `SecretBytes` refuses, and the refusal propagates unmasked.
	@Test func emptySecretIsAValueInvariant() throws {
		struct AsKey: Codable { @SecretField var k: SymmetricKey }
		struct AsSecret: Codable { @SecretField var k: SecretBytes }

		let archive = try SecretArchive(encoding: AsKey(k: SymmetricKey(data: Data())))
		#expect(try archive.decode(AsKey.self).k.withUnsafeBytes { $0.count } == 0)

		#expect(throws: SecretBytesError.emptySecret) {
			try archive.decode(AsSecret.self)
		}
	}

	// MARK: Embedded archives

	@Test func embeddedArchiveRoundTrips() throws {
		struct Inner: Codable, Equatable { @SecretField var k: SecretBytes }
		struct Outer: Codable {
			var name: String
			var inner: SecretArchive.Embedded
		}

		let inner = try SecretArchive(
			encoding: Inner(
				k: try SecretBytes(bytes: [UInt8](repeating: 0x3E, count: 32))))
		let outer = try SecretArchive(encoding: Outer(name: "x", inner: .init(inner)))

		let restored = try outer.decode(Outer.self)
		#expect(restored.name == "x")
		#expect(
			try restored.inner.archive.decode(Inner.self)
				== Inner(
					k: try SecretBytes(
						bytes: [UInt8](repeating: 0x3E, count: 32))))
	}

	/// `SecretArchive` crosses isolation domains in real adopters, so it must
	/// be `Sendable` — otherwise every crossing needs an escape hatch in app
	/// code. swift-crypto marks its own zeroizing store the same way.
	@Test func archiveAndCarrierAreSendable() {
		func requireSendable<T: Sendable>(_: T.Type) {}
		requireSendable(SecretArchive.self)
		requireSendable(SecretField<SecretBytes>.self)
		requireSendable(SecretField<SymmetricKey>.self)
	}
}

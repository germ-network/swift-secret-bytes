import Crypto
import Foundation
import XCTest

@testable import SecretBytes

/// Byte-exact vectors. These pin the wire format: one value, one encoding.
final class ArchiveVectorTests: XCTestCase {
	private func hex(_ archive: SecretArchive) -> String {
		archive.withUnsafeBytes { $0.map { String(format: "%02x", $0) }.joined() }
	}

	/// Integer `CodingKeys` yield a genuine COSE_Key map. `58 20` is the head
	/// for a 32-byte string; encoded-key sort `01 < 20 < 23` puts the keys in
	/// semantic order 1, -1, -4.
	func testCoseKeyIsByteExact() throws {
		struct CoseOKPPrivateKey: Codable {
			var kty = 1, crv = 6
			@SecretField var d: SecretBytes
			enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
				case kty = 1
				case crv = -1
				case d = -4
			}
		}
		let d = try SecretBytes(bytes: [UInt8](repeating: 0xAB, count: 32))
		let archive = try SecretArchive(encoding: CoseOKPPrivateKey(d: d))
		XCTAssertEqual(
			hex(archive),
			"a3" + "0101" + "2006" + "23" + "5820" + String(repeating: "ab", count: 32))
	}

	/// Negative keys sort *after* non-negative and in descending numeric order,
	/// because the sort is bytewise on the encoded key (-1 = 0x20, -2 = 0x21,
	/// -4 = 0x23). An implementer sorting semantically gets different bytes.
	func testNegativeKeyOrderingIsDescending() throws {
		struct Four: Codable {
			var kty = 1, crv = 6
			var x = Data([0x01]), d = Data([0x02])
			enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
				case kty = 1
				case crv = -1
				case x = -2
				case d = -4
			}
		}
		XCTAssertEqual(
			hex(try SecretArchive(encoding: Four())),
			"a4" + "0101" + "2006" + "21" + "4101" + "23" + "4102")
	}

	/// The silent-corruption case: the stdlib's dictionary coding key reports
	/// `intValue = Int(stringValue)`, so inferring integer keys from `intValue`
	/// alone would re-key "05" as 5. Text keys stay text.
	func testStringDictionaryKeysStayText() throws {
		struct S: Codable { var a: [String: Int] }
		//  a1 6161  {"a":            }
		//  a1 62 3035 1829  {"05": 41}
		XCTAssertEqual(
			hex(try SecretArchive(encoding: S(a: ["05": 41]))), "a16161a16230351829")
		XCTAssertEqual(
			hex(try SecretArchive(encoding: S(a: ["5": 41]))), "a16161a161351829")
	}

	/// Both `Value` types are indistinguishable on the wire: the concrete type
	/// is schema, not format, so re-typing a field later is not a migration.
	func testValueTypeLeavesNoWireTrace() throws {
		struct AsSecret: Codable { @SecretField var k: SecretBytes }
		struct AsKey: Codable { @SecretField var k: SymmetricKey }
		let raw = [UInt8](repeating: 0x11, count: 32)
		XCTAssertEqual(
			hex(try SecretArchive(encoding: AsSecret(k: try SecretBytes(bytes: raw)))),
			hex(try SecretArchive(encoding: AsKey(k: SymmetricKey(data: raw)))))
	}

	func testCanonicalNaNAndFloat64() throws {
		struct F: Codable { var v: Double }
		XCTAssertEqual(hex(try SecretArchive(encoding: F(v: .nan))), "a16176f97e00")
		XCTAssertEqual(
			hex(try SecretArchive(encoding: F(v: 1.5))), "a16176fb3ff8000000000000")
	}
}

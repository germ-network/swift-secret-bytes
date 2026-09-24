import Crypto
import Foundation
import Testing

@testable import SecretBytes

/// Byte-exact vectors. These pin the wire format: one value, one encoding.
@Suite struct ArchiveVectorTests {
	private func hex(_ archive: SecretArchive) -> String {
		archive.withUnsafeBytes { $0.map { String(format: "%02x", $0) }.joined() }
	}

	/// Integer `CodingKeys` yield a genuine COSE_Key map. `58 20` is the head
	/// for a 32-byte string; encoded-key sort `01 < 20 < 23` puts the keys in
	/// semantic order 1, -1, -4.
	@Test func coseKeyIsByteExact() throws {
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
		#expect(
			hex(archive)
				== "a3" + "0101" + "2006" + "23" + "5820"
				+ String(repeating: "ab", count: 32))
	}

	/// Negative keys sort *after* non-negative and in descending numeric order,
	/// because the sort is bytewise on the encoded key (-1 = 0x20, -2 = 0x21,
	/// -4 = 0x23). An implementer sorting semantically gets different bytes.
	@Test func negativeKeyOrderingIsDescending() throws {
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
		#expect(
			hex(try SecretArchive(encoding: Four()))
				== "a4" + "0101" + "2006" + "21" + "4101" + "23" + "4102")
	}

	/// The silent-corruption case: the stdlib's dictionary coding key reports
	/// `intValue = Int(stringValue)`, so inferring integer keys from `intValue`
	/// alone would re-key "05" as 5. Text keys stay text.
	@Test func stringDictionaryKeysStayText() throws {
		struct S: Codable { var a: [String: Int] }
		//  a1 6161  {"a":            }
		//  a1 62 3035 1829  {"05": 41}
		#expect(
			hex(try SecretArchive(encoding: S(a: ["05": 41]))) == "a16161a16230351829")
		#expect(
			hex(try SecretArchive(encoding: S(a: ["5": 41]))) == "a16161a161351829")
	}

	/// Both `Value` types are indistinguishable on the wire: the concrete type
	/// is schema, not format, so re-typing a field later is not a migration.
	@Test func valueTypeLeavesNoWireTrace() throws {
		struct AsSecret: Codable { @SecretField var k: SecretBytes }
		struct AsKey: Codable { @SecretField var k: SymmetricKey }
		let raw = [UInt8](repeating: 0x11, count: 32)
		#expect(
			hex(try SecretArchive(encoding: AsSecret(k: try SecretBytes(bytes: raw))))
				== hex(
					try SecretArchive(
						encoding: AsKey(k: SymmetricKey(data: raw)))))
	}

	@Test func canonicalNaNAndFloat64() throws {
		struct F: Codable { var v: Double }
		#expect(hex(try SecretArchive(encoding: F(v: .nan))) == "a16176f97e00")
		#expect(
			hex(try SecretArchive(encoding: F(v: 1.5))) == "a16176fb3ff8000000000000")
	}

	/// Declared out of wire order on purpose: "z" > "a" bytewise, but the
	/// struct declares `z` first. Every other vector in this file happens to
	/// declare its properties already in canonical order, so none of them
	/// would notice a broken sort — only a round-trip test would, and a
	/// self-consistently-wrong sort still round-trips.
	@Test func canonicalOrderReordersOutOfOrderTextKeys() throws {
		struct S: Codable {
			var z = 1
			var a = 2
		}
		//  a2  6161 02  617a 01   {"a": 2, "z": 1}
		#expect(
			hex(try SecretArchive(encoding: S())) == "a2" + "6161" + "02" + "617a"
				+ "01")
	}

	/// Same regression for integer wire keys: declared 5, -1, 2 but the
	/// canonical byte order is 2 (`02`) < 5 (`05`) < -1 (`20`).
	@Test func canonicalOrderReordersOutOfOrderIntegerKeys() throws {
		struct S: Codable {
			var five = "a", negOne = "b", two = "c"
			enum CodingKeys: Int, CodingKey, ArchiveIntegerCodingKey {
				case five = 5
				case negOne = -1
				case two = 2
			}
		}
		//  a3  02 6163  05 6161  20 6162   {2:"c", 5:"a", -1:"b"}
		#expect(
			hex(try SecretArchive(encoding: S()))
				== "a3" + "02" + "6163" + "05" + "6161" + "20" + "6162")
	}
}

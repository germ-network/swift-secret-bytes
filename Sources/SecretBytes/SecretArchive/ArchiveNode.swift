import Foundation

/// The encoder's intermediate representation.
///
/// **This is a reference type on purpose — do not "simplify" it to an enum.**
/// Encoding containers are structs passed by value, and
/// `nestedContainer(keyedBy:forKey:)` must return a container whose writes stay
/// visible to its parent *after the parent container struct has been copied*.
/// With a value-typed tree those writes land in a copy and the parent
/// serializes the empty pre-copy state. `JSONEncoder` uses reference boxes for
/// exactly this reason, and it is not a corner case here: SE-0295 enum
/// synthesis calls `nestedContainer(keyedBy:forKey:)` for the case payload
/// before encoding it, which is the shape real adopters use.
///
/// Secrets are held as the schema's own value, by shared zeroizing backing —
/// `SymmetricKey` wraps `SecureBytes`, `SecretBytes` wraps `SymmetricKey`, both
/// reference-counted — so the tree contains zero plaintext secret copies. Plain
/// values sit in ordinary memory, which is correct: they are not secrets.
final class ArchiveNode {
	enum Kind {
		case uint(UInt64)
		case negative(UInt64)  // encodes -1 - n; stores n
		case bytes(Data)
		case text(String)
		case bool(Bool)
		case null
		case float(Double)  // always float64 on the wire; see the format notes
		case array([ArchiveNode])
		case map([(key: MapKey, value: ArchiveNode)])
		case secret(any AnySecretField)
		case embedded(SecretArchive)
	}

	/// A CBOR map key. Integer keys are opt-in per `ArchiveIntegerCodingKey`;
	/// everything else keys by text.
	enum MapKey {
		case uint(UInt64)
		case negative(UInt64)
		case text(String)
	}

	var kind: Kind

	init(_ kind: Kind) { self.kind = kind }

	/// Integer values arrive as `Int64` from the Codable layer and split across
	/// CBOR's two integer majors here.
	static func integer(_ value: Int64) -> ArchiveNode {
		value < 0
			? ArchiveNode(.negative(UInt64(-1 - value)))
			: ArchiveNode(.uint(UInt64(value)))
	}

	static func integer(_ value: UInt64) -> ArchiveNode { ArchiveNode(.uint(value)) }
}

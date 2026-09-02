import Crypto
import SecretBytes

/// Fixture exercising every shape the archive must carry: plain scalars, a
/// secret restoring to the general type, a secret restoring to a concrete key
/// type, a plain byte blob, and a nested struct.
struct Epoch: Codable, Equatable {
	var index: UInt64
	var flags: UInt16
	@SecretField var key: SecretBytes
	@SecretField var sealingKey: SymmetricKey
	var label: [UInt8]
	var inner: Inner

	struct Inner: Codable, Equatable {
		var counter: UInt32
		@SecretField var secret: SecretBytes
	}
}

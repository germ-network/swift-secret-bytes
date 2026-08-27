import SecretBytes

/// A fixture with a mix of secret and non-secret fields, plus an embedded
/// archive, exercising every Writer/Reader path.
struct Epoch: SecretArchivable, Equatable {
	var index: UInt64
	var flags: UInt16
	var key: SecretBytes
	var label: [UInt8]
	var inner: Inner

	init(index: UInt64, flags: UInt16, key: SecretBytes, label: [UInt8], inner: Inner) {
		self.index = index
		self.flags = flags
		self.key = key
		self.label = label
		self.inner = inner
	}

	func archive(into writer: inout SecretArchive.Writer) {
		writer.write(index)
		writer.write(flags)
		writer.writeSecret(key)
		writer.writeBytes(label)
		writer.embed(SecretArchive(archiving: inner))
	}

	init(restoring reader: inout SecretArchive.Reader) throws {
		index = try reader.readUInt64()
		flags = try reader.readUInt16()
		key = try reader.readSecret()
		label = try reader.readBytes()
		inner = try reader.readArchive().restore(Inner.self)
	}

	/// A nested secret-bearing type, embedded into `Epoch`.
	struct Inner: SecretArchivable, Equatable {
		var counter: UInt32
		var secret: SecretBytes

		init(counter: UInt32, secret: SecretBytes) {
			self.counter = counter
			self.secret = secret
		}

		func archive(into writer: inout SecretArchive.Writer) {
			writer.write(counter)
			writer.writeSecret(secret)
		}

		init(restoring reader: inout SecretArchive.Reader) throws {
			counter = try reader.readUInt32()
			secret = try reader.readSecret()
		}
	}
}

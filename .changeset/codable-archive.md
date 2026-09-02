---
"@germ-network/swift-secret-bytes": minor
---

Replace the archive layer with a `Codable` one. A type with secret properties
now serializes into a `SecretArchive` and restores from it whole — plain
properties ride ordinary `Codable`, secret properties are declared
`@SecretField`, and the secret never exists as plain `Data` or `String` in
either direction. Previously every adopter hand-wrote positional serialization
for every secret-bearing type.

Secrets restore as **the concrete type the schema names**: `@SecretField var k:
SymmetricKey` comes back as a `SymmetricKey`, ready for an AEAD or KDF, rather
than as a general `SecretBytes` the caller must re-wrap. Types opt in by
conforming to `SecretRestorable`, which is only satisfiable by types that can
hold bytes in zeroizing storage in both directions — `SymmetricKey` and
`SecretBytes` do; CryptoKit's asymmetric private keys cannot, since they expose
bytes only as `rawRepresentation: Data`.

The wire format is now deterministic CBOR (RFC 8949 §4.2.1, with §4.2.2's
always-float64 profile). Integer `CodingKeys` — opt in via
`ArchiveIntegerCodingKey` — make an archive body a byte-for-byte COSE_Key map.
The decoder is strict: non-shortest heads, indefinite lengths, tags, unsorted or
duplicate map keys, invalid UTF-8 and over-deep nesting are all rejected, and
every malformed input throws rather than trapping.

`SecretArchive` is now `Sendable`, so it can cross isolation domains without an
escape hatch at each boundary.

**Breaking:** `SecretArchive.Writer`, `.Reader`, `SecretArchivable`,
`init(archiving:)` and `restore(_:)` are removed. Archives written by 0.1.0
cannot be read by 0.2.0 — the format has no shipped consumers, so no migration
path is provided.

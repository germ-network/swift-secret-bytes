---
"@germ-network/swift-secret-bytes": patch
---

Fix `SecretBytes` equality for zero-byte secrets. `SymmetricKey`'s
constant-time compare returns false for zero-length input, so an empty secret
compared unequal to itself — a violation of `Equatable`'s reflexivity
requirement. Zero-byte secrets are reachable through `init(bytes:)` and through
`SecretArchive.Reader.readSecret()` on a zero-length field. Comparisons where
both operands hold bytes still take the constant-time path; only the length
check, which was already public via `byteCount`, is short-circuited.

Also documents two `ContiguousBytes` interop points: which swift-crypto KDF
entry points accept a `SecretBytes` directly (`HKDF.expand`) versus which need
a `SymmetricKey` bridge (`HKDF.extract`, `HKDF.deriveKey`), and the hazard that
the conformance inherits every public `extension ContiguousBytes` in the
importing graph — including ones that can expose plaintext.

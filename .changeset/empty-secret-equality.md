---
"@germ-network/swift-secret-bytes": patch
---

Prohibit zero-byte secrets. `init(randomByteCount:)` has always asserted that a
`SecretBytes` holds at least one byte; `init(bytes:)` now enforces the same
invariant. A zero-byte secret is meaningless, and permitting one was not
harmless: `SymmetricKey`'s constant-time compare returns false for zero-length
input, so an empty secret compared unequal to itself, violating `Equatable`'s
reflexivity requirement.

Equality retains a zero-length guard as defense in depth — the state should now
be unconstructible, but the failure it prevents is silent. Decoding is the one
path that must not trap on untrusted bytes, so the archive layer rejects a
zero-length secret field with a thrown error rather than reaching an
initializer.

Also documents two `ContiguousBytes` interop points: which swift-crypto KDF
entry points accept a `SecretBytes` directly (`HKDF.expand`) versus which need a
`SymmetricKey` bridge (`HKDF.extract`, `HKDF.deriveKey`), and the hazard that
the conformance inherits every public `extension ContiguousBytes` in the
importing graph — including ones that can expose plaintext.

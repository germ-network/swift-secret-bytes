---
"@germ-network/swift-secret-bytes": minor
---

Reject zero-byte secrets. `init(bytes:)` is now **throwing** and rejects an
empty collection with `SecretBytesError.emptySecret`; `init(randomByteCount:)`
keeps its long-standing precondition. The asymmetry is deliberate: `bytes` is
caller data that may be attacker-influenced, so a decoder handing over a
zero-length field must surface an error rather than abort the process, whereas
a non-positive `count` is a length the programmer chose and so a programming
error.

A zero-byte secret was not harmless: `SymmetricKey`'s constant-time compare
returns false for zero-length input, so an empty secret compared unequal to
itself, violating `Equatable`'s reflexivity requirement. Equality retains a
zero-length guard as defense in depth — the state should now be unconstructible
through public API, but the failure it prevents is silent.

Also documents two `ContiguousBytes` interop points: which swift-crypto KDF
entry points accept a `SecretBytes` directly (`HKDF.expand`) versus which need a
`SymmetricKey` bridge (`HKDF.extract`, `HKDF.deriveKey`), and the hazard that
the conformance inherits every public `extension ContiguousBytes` in the
importing graph — including ones that can expose plaintext.

**Breaking:** `SecretBytes(bytes:)` now requires `try`.

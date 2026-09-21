---
"@germ-network/swift-secret-bytes": minor
---

Add `SecretBytes.init(signedBytes: [Int8])` — an ingress for secrets arriving
as `[Int8]`. `jextract`/JNI maps a Java `byte[]` to `[Int8]`, and `[Int8]` is
not `ContiguousBytes`, so a secret crossing that bridge could previously only
be adopted via an unscrubbed intermediate (`Data(int8s)` or
`.map { UInt8(bitPattern:) }`). The new initializer reinterprets each `Int8`
as its raw byte and copies straight into `SymmetricKey`'s zeroizing backing,
with no intermediate — mirroring `init(bytes:)`, including rejecting empty
input the same way.

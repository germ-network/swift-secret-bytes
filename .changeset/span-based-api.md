---
"@germ-network/swift-secret-bytes": minor
---

Add `SecretBytes.init(copyingWithZeroing:)` and
`init(byteCount:initializingWith:)`, adopting CryptoKit's OS 27 span-based
`SymmetricKey` API behind availability gates. Additive; the deployment floor
is unchanged and Linux keeps the existing portable path.

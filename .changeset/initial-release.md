---
"@germ-network/swift-secret-bytes": minor
---

Initial release: `SecretBytes` (a zeroizing held-secret newtype over
`SymmetricKey`) and `SecretArchive` with a `Writer`/`Reader` pair and an AEAD
`seal`/`open` exit (ChaChaPoly by default, AES-GCM optional).

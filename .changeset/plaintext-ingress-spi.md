---
"@germ-network/swift-secret-bytes": minor
---

Add `SecretArchive.init(decodingPlaintext:)` — the one plaintext ingress to the
custody chain. It wraps already-plaintext archive bytes (another
implementation's migration export) into a `SecretArchive` so `decode` can read
them back, copying them into zeroizing storage. A deliberate hole, justified
only for ingesting a trusted cross-implementation export; the bytes are
validated on `decode` (the same up-front pass sealed archives get), not at
ingress. Unblocks migrating a group into swift-mls from a peer implementation's
plaintext format-1 export (shipped in #9).

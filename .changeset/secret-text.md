---
"@germ-network/swift-secret-bytes": minor
---

Add a UTF-8 text bridge to `SecretBytes`: `init(utf8:)` to wrap a string into
zeroizing custody, and `utf8String()` to materialize one — the one deliberate
text exit from the type, documented as a transient plaintext copy the caller
must contain. Adds `SecretBytesError.notUTF8` for a read whose bytes are not
valid UTF-8.

This is the shared home for the `SecretBytes`↔`String` conversion adopters
(e.g. oauth4swift) were otherwise each writing for themselves.

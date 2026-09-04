---
"@germ-network/swift-secret-bytes": patch
---

Fix `SecretArchive` decode: a text key or value with a leading U+FEFF (BOM)
was silently stripped by Foundation's `String(bytes:encoding:.utf8)`, which
the encoder's stdlib `String(decoding:as:)` never does. Consequences ranged
from a silent key rename (`{"\u{FEFF}x": 1}` decoded as `["x": 1]`) to a
well-formed archive throwing `.malformedArchive` on every decode (a
BOM-prefixed key alongside its bare form collided after stripping) to
`keyNotFound` on a keyed-container lookup for a `CodingKey` whose
`stringValue` legitimately started with U+FEFF.

Fixed by validating UTF-8 without Foundation's encoding-detection behavior:
decode with the stdlib codec, then confirm re-encoding reproduces the exact
input bytes. (Swift 6's `String(validating:as:)` does this natively but needs
macOS 15+, above this package's macOS 13 floor.)

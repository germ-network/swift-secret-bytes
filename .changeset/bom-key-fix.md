---
"@germ-network/swift-secret-bytes": minor
---

Fix `SecretArchive` decode: a text key or value with a leading U+FEFF (BOM)
was silently stripped by Foundation's `String(bytes:encoding:.utf8)`, which
the encoder's stdlib `String(decoding:as:)` never does. Consequences ranged
from a silent key rename (`{"\u{FEFF}x": 1}` decoded as `["x": 1]`) to a
well-formed archive throwing `.malformedArchive` on every decode (a
BOM-prefixed key alongside its bare form collided after stripping) to
`keyNotFound` on a keyed-container lookup for a `CodingKey` whose
`stringValue` legitimately started with U+FEFF.

Fixed with stdlib's `String(validating:as:)`, which validates UTF-8 exactly
like the Foundation initializer without its BOM-stripping behavior.

**Breaking:** raises the deployment floor to macOS 15 / iOS 18 —
`String(validating:as:)` needs it. The alternative (hand-rolling the same
validation at the previous macOS 13 / iOS 16 floor) was rejected in favor of
depending on the platform's own implementation of a property this exact
library exists to get right.

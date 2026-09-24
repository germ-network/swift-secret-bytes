---
"@germ-network/swift-secret-bytes": patch
---

Keyed-container decode lookups were a linear scan of the map's entries per
key, so decoding an N-key map via `allKeys` + `decode(forKey:)` — the shape
every keyed-container consumer, including Swift's own `[String: V]` decoding,
actually uses — was quadratic: 100k keys took minutes. Lookups now go through
a hashed index built once per container, so decode time is linear in the
number of keys again.

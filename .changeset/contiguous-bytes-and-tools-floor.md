---
"@germ-network/swift-secret-bytes": patch
---

Conform `SecretBytes` to `ContiguousBytes` so a secret can be passed directly
to swift-crypto's KDFs, AEADs, and `SymmetricKey.init(data:)` with no
intermediate `Data`. The conformance adds no capability — its only requirement
is `withUnsafeBytes`, which was already public — but it removes the ergonomic
pressure toward `withUnsafeBytes { Data($0) }`, which mints an unscrubbed copy
per call on hot paths.

Lower `swift-tools-version` from 6.2 to 6.1. The manifest used no 6.2-only
features, and Swift 6 language mode is unaffected. A 6.1 toolchain refuses a
6.2 manifest at resolution time — before target-graph pruning — so the higher
floor blocked adopters whose CI pins 6.1 even when no target used the package.

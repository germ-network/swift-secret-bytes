---
"@germ-network/swift-secret-bytes": minor
---

Adopt swift-crypto 5.0 and its cross-platform span surface; decrypt archives
in place.

- `SecretArchive.open` now runs the AEAD **in place** over the archive's own
  zeroizing buffer wherever the span-based API exists (non-CryptoKit
  platforms, via swift-crypto 5; Darwin at runtime on OS 27 or newer built
  against the Xcode 27 or newer SDK), eliminating the transient plaintext
  `Data` on those paths — see `SECURITY.md` / the README Security section.
  Everywhere else (Darwin built against an older SDK, or running below
  OS 27) `open` keeps the previous decrypt-and-scrub behavior unchanged.
- `SecretBytes.init(copyingWithZeroing:)` and
  `SecretBytes.init(byteCount:initializingWith:)` are now available on
  non-CryptoKit platforms (previously Darwin-only via CryptoKit), with the
  same OS-27 availability on Darwin.

**Breaking:** raises the toolchain floor to Swift 6.2 — swift-crypto 5.0
requires it. On Darwin, the span-based surface additionally requires a
Swift 6.4 compiler with the Xcode 27 (or newer) SDK; older toolchains compile
the package without it. The macOS 15 / iOS 18 deployment floor is unchanged.

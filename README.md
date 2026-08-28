# swift-secret-bytes

[![Apple](https://github.com/germ-network/swift-secret-bytes/actions/workflows/ci-apple.yml/badge.svg)](https://github.com/germ-network/swift-secret-bytes/actions/workflows/ci-apple.yml)
[![Linux](https://github.com/germ-network/swift-secret-bytes/actions/workflows/ci-linux.yml/badge.svg)](https://github.com/germ-network/swift-secret-bytes/actions/workflows/ci-linux.yml)

Zeroizing custody types for secret bytes, built on
[swift-crypto](https://github.com/apple/swift-crypto)'s `SymmetricKey`:

- **`SecretBytes`** — a held secret. Byte access is confined to two deliberate
  escape hatches (`withUnsafeBytes` for in-process interop, and sealing a
  `SecretArchive`); there is no `Codable`, no `var data`, and reflection is
  redacted.
- **`SecretArchive`** — serializes secret-bearing state entirely in zeroizing
  storage. A `Writer`/`Reader` pair makes the secret vs. non-secret split
  visible at every call site, and the only exit to ordinary `Data` is an AEAD
  `seal(with:aad:)` — so the `Data` that finally exists is ciphertext by
  construction. `open` is the mirror.

Plaintext secret bytes live only inside zeroizing storage, from the moment they
are produced to the moment they are encrypted.

Zeroization narrows the window for same-process exposure — heap
over-reads, core dumps, swap, later disclosure of memory once occupied by a secret.
Cross-process isolation is not its job; the OS already zeroes pages
between processes.

Swift compiler optimizations make it hard to express fine control over memory
buffers. This control is already implemented by the `SecureBytes` storage
underlying `SymmetricKey` (when not compiling for Darwin). The closed-source
CryptoKit implementation on Darwin, we can infer, has similar properties.

To get similar security properties for memory buffers containing secrets, we build
this primitive around `SymmetricKey`.

## Security

This library narrows exposure windows; it closes none. It is defense-in-depth
and must never be described as a guarantee.

- **Zeroization is best-effort.** On Linux it rests on swift-crypto's
  `SecureBytes`, whose scrub is `OPENSSL_cleanse` — a memset behind an
  optimizer barrier that BoringSSL itself describes as best-effort. On
  Apple platforms the same types resolve to CryptoKit, whose behavior is
  closed-source.
- **Compiler copies are out of reach.** Swift value semantics permit
  implicit copies, register spills, and optimizer-materialized
  temporaries.
- **Memory is not locked.** Nothing prevents pages reaching swap or a
  hibernation image.
- **`open` transits one plaintext `Data`.** swift-crypto's only public
  AEAD decrypt returns `Data`; the library copies it into zeroizing
  storage and scrubs the transient while uniquely referenced, which is —
  again — best-effort.

**Span-based API (OS 27):** the OS 27 SDKs add `SymmetricKey` API that
addresses parts of this ceiling directly, and `SecretBytes` adopts it behind
availability gates —
[`init(copyingWithZeroing:)`](https://developer.apple.com/documentation/cryptokit/symmetrickey/init(copyingwithzeroing:))
(creates a key and zeroes the source buffer) and
[`init(size:initializingWith:)`](https://developer.apple.com/documentation/cryptokit/symmetrickey/init(size:initializingwith:))
(writes key material directly into zeroizing storage, no staging buffer). The
deployment floor is unchanged; the members exist when building with the
Xcode 27 SDK and are `@available` from OS 27. They are CryptoKit-only —
swift-crypto has no counterpart yet, so Linux keeps the portable path.
`SymmetricKey.bytes: RawSpan` is not forwarded: returning a non-escapable
type still requires an experimental language feature.

To report a suspected vulnerability, see [SECURITY.md](./SECURITY.md).

## Requirements

- Swift 6.2+, macOS 13+, iOS 16+
- Depends only on swift-crypto (`SymmetricKey` and AEAD)

## Contributing

We welcome contributions! Please follow our
[guidelines for contributing code](./CONTRIBUTING.md).

Germ has adopted the [Contributor Covenant](./CODE_OF_CONDUCT.md) as its code of
conduct.

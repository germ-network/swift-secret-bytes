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

## Security

This library narrows exposure windows; it closes none. It is defense-in-depth
and must never be described as a guarantee — see [SECURITY.md](./SECURITY.md)
for the full ceiling (best-effort zeroization, compiler copies out of reach,
unlocked memory, and the one plaintext transient at `open`).

## Requirements

- Swift 6.2+, macOS 13+, iOS 16+
- Depends only on swift-crypto (`SymmetricKey` and AEAD)

## Contributing

We welcome contributions! Please follow our
[guidelines for contributing code](./CONTRIBUTING.md).

Germ has adopted the [Contributor Covenant](./CODE_OF_CONDUCT.md) as its code of
conduct.

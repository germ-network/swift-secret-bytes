# swift-secret-bytes

[![Apple](https://github.com/germ-network/swift-secret-bytes/actions/workflows/ci-apple.yml/badge.svg)](https://github.com/germ-network/swift-secret-bytes/actions/workflows/ci-apple.yml)
[![Linux](https://github.com/germ-network/swift-secret-bytes/actions/workflows/ci-linux.yml/badge.svg)](https://github.com/germ-network/swift-secret-bytes/actions/workflows/ci-linux.yml)
[![Android](https://github.com/germ-network/swift-secret-bytes/actions/workflows/ci-android.yml/badge.svg)](https://github.com/germ-network/swift-secret-bytes/actions/workflows/ci-android.yml)

Zeroizing custody types for secret bytes, built on
[swift-crypto](https://github.com/apple/swift-crypto)'s `SymmetricKey`:

- **`SecretBytes`** — a held secret. Byte access is confined to two deliberate
  escape hatches (`withUnsafeBytes` for in-process interop, and sealing a
  `SecretArchive`); there is no `Codable`, no `var data`, and reflection is
  redacted.
- **`SecretArchive`** — serializes secret-bearing state entirely in zeroizing
  storage, driven by ordinary `Codable`. Plain properties encode normally;
  secret properties are declared `@SecretField`, and the only exit to ordinary
  `Data` is an AEAD `seal(with:aad:)` — so the `Data` that finally exists is
  ciphertext by construction. `open` is the mirror.

```swift
struct SessionSecrets: Codable {
    @SecretField var sealingKey: SymmetricKey      // restores AS a SymmetricKey
    @SecretField var exporterSecret: SecretBytes   // no key role — stays general
    var epoch: UInt64
}

let sealed = try SecretArchive(encoding: secrets).seal(with: storageKey, aad: aad)
let restored = try SecretArchive.open(sealed, with: storageKey, aad: aad)
    .decode(SessionSecrets.self)
```

A secret restores as the concrete type the schema names, so a symmetric key
arrives ready to hand to an AEAD or KDF rather than needing to be re-wrapped.
Handing a secret-bearing type to any *other* coder — `JSONEncoder`, say — throws
before a single byte is written, rather than base64-ing a private key into an
immortal `String`.

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
(exposed as `SecretBytes.init(copyingWithZeroing:)`: creates a key and zeroes
the source buffer — note the scrub covers only the span's own storage, so a
source that was copied to produce the span, e.g. a `CoW`-shared `Array`,
leaves its original allocation untouched) and
[`init(size:initializingWith:)`](https://developer.apple.com/documentation/cryptokit/symmetrickey/init(size:initializingwith:))
(exposed as `SecretBytes.init(byteCount:initializingWith:)`: writes key
material directly into zeroizing storage, no staging buffer — a callback that
doesn't fill the span traps). The deployment floor is unchanged; the gate
checks CryptoKit's module version, so the members must actually be present in
the SDK the package is compiled against — not just a Swift 6.4 toolchain. They
are CryptoKit-only — swift-crypto has no counterpart yet, so Linux keeps the
portable path. `SymmetricKey.bytes: RawSpan` is not forwarded: returning a non-escapable
type still requires an experimental language feature.

To report a suspected vulnerability, see [SECURITY.md](./SECURITY.md).

## Requirements

- Swift 6.1+, macOS 13+, iOS 16+
- Depends only on swift-crypto (`SymmetricKey` and AEAD)

## Contributing

We welcome contributions! Please follow our
[guidelines for contributing code](./CONTRIBUTING.md).

Germ has adopted the [Contributor Covenant](./CODE_OF_CONDUCT.md) as its code of
conduct.

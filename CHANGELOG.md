# @germ-network/swift-secret-bytes

## 0.4.0

### Minor Changes

- [#10](https://github.com/germ-network/swift-secret-bytes/pull/10) [`149ede8`](https://github.com/germ-network/swift-secret-bytes/commit/149ede8690388d329d7d9e2068028db21733c83a) Thanks [@germ-mark](https://github.com/germ-mark)! - Add `SecretArchive.init(decodingPlaintext:)` — the one plaintext ingress to the
  custody chain. It wraps already-plaintext archive bytes (another
  implementation's migration export) into a `SecretArchive` so `decode` can read
  them back, copying them into zeroizing storage. A deliberate hole, justified
  only for ingesting a trusted cross-implementation export; the bytes are
  validated on `decode` (the same up-front pass sealed archives get), not at
  ingress. Unblocks migrating a group into swift-mls from a peer implementation's
  plaintext format-1 export (shipped in [#9](https://github.com/germ-network/swift-secret-bytes/issues/9)).

## 0.3.0

### Minor Changes

- [#5](https://github.com/germ-network/swift-secret-bytes/pull/5) [`163ef25`](https://github.com/germ-network/swift-secret-bytes/commit/163ef25c87c0fe1f60369de102eb9ae30be2c0cf) Thanks [@germ-mark](https://github.com/germ-mark)! - Add an Android CI leg (`aarch64`/`x86_64-unknown-linux-android28`, Swift 6.3.3
  SDK), and fix a real portability bug it caught: `gsb_secure_zero`'s scrub
  barrier assumed Bionic exposes `explicit_bzero` the same way glibc and musl do.
  It doesn't — checked every NDK API level 21 through 35, neither declared in
  `<string.h>` nor linked in `libc.so` on any of them — so the package failed to
  compile for Android at all. Bionic now falls through to the `volatile`
  byte-loop fallback, same as every other platform without a native scrub
  primitive.

  Build-only for now (no on-device/emulator test execution). **Correction
  (2026-09-03):** this entry originally claimed the existing `ZeroizationTests`
  suite already pins the Bionic fallback's correctness on Linux — false. The
  `volatile` byte-loop only compiles on Bionic; Linux and Apple both take a
  different branch (`explicit_bzero`/`memset_s`), so no CI leg has ever
  actually run the code path Android takes. The loop itself is correct
  (verified by force-compiling it natively and testing byte-exact zeroing at
  -O0/-O3), but that verification did not happen through `ZeroizationTests` on
  CI as claimed.

## 0.2.0

### Minor Changes

- [#4](https://github.com/germ-network/swift-secret-bytes/pull/4) [`b575c31`](https://github.com/germ-network/swift-secret-bytes/commit/b575c3199cb2d880bdba9deaa58660c016f62609) Thanks [@germ-mark](https://github.com/germ-mark)! - Replace the archive layer with a `Codable` one. A type with secret properties
  now serializes into a `SecretArchive` and restores from it whole — plain
  properties ride ordinary `Codable`, secret properties are declared
  `@SecretField`, and the secret never exists as plain `Data` or `String` in
  either direction. Previously every adopter hand-wrote positional serialization
  for every secret-bearing type.

  Secrets restore as **the concrete type the schema names**: `@SecretField var k:
SymmetricKey` comes back as a `SymmetricKey`, ready for an AEAD or KDF, rather
  than as a general `SecretBytes` the caller must re-wrap. Types opt in by
  conforming to `SecretRestorable`, which is only satisfiable by types that can
  hold bytes in zeroizing storage in both directions — `SymmetricKey` and
  `SecretBytes` do; CryptoKit's asymmetric private keys cannot, since they expose
  bytes only as `rawRepresentation: Data`.

  The wire format is now deterministic CBOR (RFC 8949 §4.2.1, with §4.2.2's
  always-float64 profile). Integer `CodingKeys` — opt in via
  `ArchiveIntegerCodingKey` — make an archive body a byte-for-byte COSE_Key map.
  The decoder is strict: non-shortest heads, indefinite lengths, tags, unsorted or
  duplicate map keys, invalid UTF-8 and over-deep nesting are all rejected, and
  every malformed input throws rather than trapping.

  `SecretArchive` is now `Sendable`, so it can cross isolation domains without an
  escape hatch at each boundary.

  **Breaking:** `SecretArchive.Writer`, `.Reader`, `SecretArchivable`,
  `init(archiving:)` and `restore(_:)` are removed. Archives written by 0.1.0
  cannot be read by 0.2.0 — the format has no shipped consumers, so no migration
  path is provided.

- [#3](https://github.com/germ-network/swift-secret-bytes/pull/3) [`127fe21`](https://github.com/germ-network/swift-secret-bytes/commit/127fe21d471764d118e424929f13f707e010bf4c) Thanks [@germ-mark](https://github.com/germ-mark)! - Reject zero-byte secrets. `init(bytes:)` is now **throwing** and rejects an
  empty collection with `SecretBytesError.emptySecret`; `init(randomByteCount:)`
  keeps its long-standing precondition. The asymmetry is deliberate: `bytes` is
  caller data that may be attacker-influenced, so a decoder handing over a
  zero-length field must surface an error rather than abort the process, whereas
  a non-positive `count` is a length the programmer chose and so a programming
  error.

  A zero-byte secret was not harmless: `SymmetricKey`'s constant-time compare
  returns false for zero-length input, so an empty secret compared unequal to
  itself, violating `Equatable`'s reflexivity requirement. Equality retains a
  zero-length guard as defense in depth — the state should now be unconstructible
  through public API, but the failure it prevents is silent.

  Also documents two `ContiguousBytes` interop points: which swift-crypto KDF
  entry points accept a `SecretBytes` directly (`HKDF.expand`) versus which need a
  `SymmetricKey` bridge (`HKDF.extract`, `HKDF.deriveKey`), and the hazard that
  the conformance inherits every public `extension ContiguousBytes` in the
  importing graph — including ones that can expose plaintext.

  **Breaking:** `SecretBytes(bytes:)` now requires `try`.

- [`c9e1a6d`](https://github.com/germ-network/swift-secret-bytes/commit/c9e1a6dbf65567d31d19541bef936119cce7dbd0) Thanks [@germ-mark](https://github.com/germ-mark)! - Add `SecretBytes.init(copyingWithZeroing:)` and
  `init(byteCount:initializingWith:)`, adopting CryptoKit's OS 27 span-based
  `SymmetricKey` API behind availability gates. Additive; the deployment floor
  is unchanged and Linux keeps the existing portable path.

### Patch Changes

- [`ba3befb`](https://github.com/germ-network/swift-secret-bytes/commit/ba3befb6c4ed6bc2d4dbef3a1c8f73a40216f038) Thanks [@germ-mark](https://github.com/germ-mark)! - Conform `SecretBytes` to `ContiguousBytes` so a secret can be passed directly
  to swift-crypto's KDFs, AEADs, and `SymmetricKey.init(data:)` with no
  intermediate `Data`. The conformance adds no capability — its only requirement
  is `withUnsafeBytes`, which was already public — but it removes the ergonomic
  pressure toward `withUnsafeBytes { Data($0) }`, which mints an unscrubbed copy
  per call on hot paths.

  Lower `swift-tools-version` from 6.2 to 6.1. The manifest used no 6.2-only
  features, and Swift 6 language mode is unaffected. A 6.1 toolchain refuses a
  6.2 manifest at resolution time — before target-graph pruning — so the higher
  floor blocked adopters whose CI pins 6.1 even when no target used the package.

## 0.1.0

### Minor Changes

- [`6c63617`](https://github.com/germ-network/swift-secret-bytes/commit/6c63617ef3d5f2c5ec76f3fa2899a96a22347e46) Thanks [@germ-mark](https://github.com/germ-mark)! - Initial release: `SecretBytes` (a zeroizing held-secret newtype over
  `SymmetricKey`) and `SecretArchive` with a `Writer`/`Reader` pair and an AEAD
  `seal`/`open` exit (ChaChaPoly by default, AES-GCM optional).

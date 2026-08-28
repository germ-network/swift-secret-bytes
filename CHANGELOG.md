# @germ-network/swift-secret-bytes

## 0.1.0

### Minor Changes

- [`6c63617`](https://github.com/germ-network/swift-secret-bytes/commit/6c63617ef3d5f2c5ec76f3fa2899a96a22347e46) Thanks [@germ-mark](https://github.com/germ-mark)! - Initial release: `SecretBytes` (a zeroizing held-secret newtype over
  `SymmetricKey`) and `SecretArchive` with a `Writer`/`Reader` pair and an AEAD
  `seal`/`open` exit (ChaChaPoly by default, AES-GCM optional).

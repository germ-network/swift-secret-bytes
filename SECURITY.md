# Security policy

## Reporting

Please do not report suspected vulnerabilities through public GitHub issues.

- Preferred: [GitHub private vulnerability reporting](https://github.com/germ-network/swift-secret-bytes/security/advisories/new)
- Alternatively: security@germ.network

This is a small project: reports are read, but no response timeline is
promised, and there is no bug bounty.

## Scope

**In scope:** anything with concrete security impact — a path by which
bytes held in `SecretBytes`/`SecretArchive` become readable outside the
two documented escape hatches, a `seal`/`open` authentication or
confidentiality break, plaintext reaching ordinary `Data` on a path this
library controls and documents as protected.

**Out of scope:** hardening suggestions without concrete impact (ordinary
issues welcome), and the documented residues below — they are disclosed
limits, not vulnerabilities.

## The ceiling, stated plainly

This library narrows windows; it closes none. It is defense-in-depth and
must never be described as a guarantee.

- **Zeroization is best-effort.** On Linux it rests on swift-crypto's
  `SecureBytes`, whose scrub is `OPENSSL_cleanse` — a memset behind an
  optimizer barrier that BoringSSL itself describes as best-effort. On
  Apple platforms the same types resolve to CryptoKit, whose behavior is
  closed-source: we can state the design, not verify it.
- **Compiler copies are out of reach.** Swift value semantics permit
  implicit copies, register spills, and optimizer-materialized
  temporaries; no library can scrub them.
- **Memory is not locked.** Nothing prevents pages reaching swap or a
  hibernation image.
- **`open` transits one plaintext `Data`.** swift-crypto's only public
  AEAD decrypt returns `Data`; the library copies it into zeroizing
  storage and scrubs the transient while uniquely referenced, which is —
  again — best-effort.
- **What zeroization is for:** same-process exposure (heap over-reads,
  core dumps, swap, later memory disclosure). It adds nothing against
  another process; the OS already zeroes pages between processes.

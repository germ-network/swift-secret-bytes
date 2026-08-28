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
issues welcome), and the residues documented in the
[README's Security section](./README.md#security) — they are disclosed
limits, not vulnerabilities.

---
"@germ-network/swift-secret-bytes": minor
---

Add an Android CI leg (`aarch64`/`x86_64-unknown-linux-android28`, Swift 6.3.3
SDK), and fix a real portability bug it caught: `gsb_secure_zero`'s scrub
barrier assumed Bionic exposes `explicit_bzero` the same way glibc and musl do.
It doesn't — checked every NDK API level 21 through 35, neither declared in
`<string.h>` nor linked in `libc.so` on any of them — so the package failed to
compile for Android at all. Bionic now falls through to the `volatile`
byte-loop fallback, same as every other platform without a native scrub
primitive.

Build-only for now (no on-device/emulator test execution); the existing
`ZeroizationTests` suite already pins the fallback's correctness on Linux.

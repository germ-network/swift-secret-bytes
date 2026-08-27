#ifndef GSB_ZEROIZE_H
#define GSB_ZEROIZE_H

#include <stddef.h>

/// Best-effort, optimizer-resistant zeroization of `len` bytes at `ptr`.
///
/// Routes to the platform's own scrub barrier so the compiler cannot elide the
/// write as dead: `memset_s` (C11 Annex K / Darwin), `explicit_bzero` (glibc,
/// Bionic, musl), or a `volatile` byte loop as a last resort. No-ops when
/// `ptr` is NULL or `len` is 0.
void gsb_secure_zero(void *ptr, size_t len);

#endif /* GSB_ZEROIZE_H */

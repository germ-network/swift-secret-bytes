/* These must precede every system header so the scrub declarations are
   visible regardless of the -std the C importer passes: __STDC_WANT_LIB_EXT1__
   gates memset_s (C11 Annex K), _DEFAULT_SOURCE gates explicit_bzero (glibc). */
#define __STDC_WANT_LIB_EXT1__ 1
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include "gsb_zeroize.h"
#include <string.h>

void gsb_secure_zero(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return;
    }
#if defined(__STDC_LIB_EXT1__) || defined(__APPLE__)
    memset_s(ptr, len, 0, len);
#elif !defined(__BIONIC__) && (defined(__GLIBC__) || defined(__linux__))
    /* Bionic is excluded here even though it defines __linux__: it does not
       declare or link explicit_bzero on any NDK API level (checked 21-35),
       despite carrying it in some upstream AOSP source trees. Falls through
       to the volatile loop below. */
    explicit_bzero(ptr, len);
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
#endif
}

/* OSSL_PARAM layout probe (WP-0.8, ADR 0123).
 *
 * DDS.DARE builds OSSL_PARAM arrays by hand (src/dds-dare/openssl-ffi.lisp, %SET-OSSL-PARAM-SLOT), so the
 * struct size, the field offsets and the data-type selectors it writes must come from the headers of the
 * OpenSSL it loads, never from memory. This program prints them from <openssl/core.h> (struct ossl_param_st
 * and the OSSL_PARAM_* defines) as one machine-checkable line. scripts/build-openssl.sh compiles it against
 * the freshly installed headers and refuses the install if the line differs from the layout the Lisp code
 * assumes. It needs only the headers, not the library.
 *
 *   cc -I"$PREFIX/include" -o ossl-param-layout scripts/probes/ossl-param-layout.c && ./ossl-param-layout
 */
#include <stddef.h>
#include <stdio.h>
#include <openssl/core.h>
#include <openssl/opensslv.h>

int main(void)
{
    printf("openssl=%s sizeof=%zu key=%zu data_type=%zu data=%zu data_size=%zu return_size=%zu"
           " INTEGER=%d UNSIGNED_INTEGER=%d UTF8_STRING=%d OCTET_STRING=%d\n",
           OPENSSL_VERSION_STR,
           sizeof(OSSL_PARAM),
           offsetof(OSSL_PARAM, key),
           offsetof(OSSL_PARAM, data_type),
           offsetof(OSSL_PARAM, data),
           offsetof(OSSL_PARAM, data_size),
           offsetof(OSSL_PARAM, return_size),
           OSSL_PARAM_INTEGER, OSSL_PARAM_UNSIGNED_INTEGER,
           OSSL_PARAM_UTF8_STRING, OSSL_PARAM_OCTET_STRING);
    return 0;
}

/* dlfcn constants and Dl_info layout probe (WP-0.9, ADR 0123).
 *
 * src/dds-pal/pal-dl.lisp calls dlopen(3), dlsym(3), dladdr(3) and realpath(3) through CFFI, so the mode
 * bits and the Dl_info layout it uses must come from this host's <dlfcn.h>, never from memory. Prints them
 * as one machine-checkable line. _GNU_SOURCE is required for dladdr/Dl_info (dlfcn.h, __USE_GNU).
 *
 *   cc -o dlfcn-layout scripts/probes/dlfcn-layout.c && ./dlfcn-layout
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>

int main(void)
{
    printf("RTLD_NOW=%d RTLD_LOCAL=%d RTLD_NOLOAD=%d sizeof_Dl_info=%zu dli_fname=%zu dli_fbase=%zu"
           " dli_sname=%zu dli_saddr=%zu\n",
           RTLD_NOW, RTLD_LOCAL, RTLD_NOLOAD, sizeof(Dl_info),
           offsetof(Dl_info, dli_fname), offsetof(Dl_info, dli_fbase),
           offsetof(Dl_info, dli_sname), offsetof(Dl_info, dli_saddr));
    return 0;
}

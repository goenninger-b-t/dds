/* Read-only observation probe for a SysV shared-memory segment.
 * Attaches with SHM_RDONLY, so it cannot perturb the observed process.
 *   shmprobe <keyhex> dump [offset] [len]     hexdump a window
 *   shmprobe <keyhex> find <hexbytes>         report every offset of a needle
 *   shmprobe <keyhex> stat                    size / attach count only
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>

static int hexparse(const char *s, unsigned char *out, int max) {
    int n = 0;
    while (*s && n < max) {
        if (*s == ':' || *s == ' ' || *s == '-') { s++; continue; }
        unsigned v;
        if (sscanf(s, "%2x", &v) != 1) return -1;
        out[n++] = (unsigned char)v;
        s += 2;
    }
    return n;
}

static void hexdump(const unsigned char *p, size_t off, size_t len) {
    for (size_t i = 0; i < len; i += 16) {
        printf("%08zx  ", off + i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) printf("%02x ", p[off + i + j]); else printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            unsigned char c = p[off + i + j];
            putchar((c >= 32 && c < 127) ? c : '.');
        }
        printf("|\n");
    }
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: shmprobe <keyhex> stat|dump|find ...\n"); return 2; }
    key_t key = (key_t)strtoul(argv[1], NULL, 16);

    int id = shmget(key, 0, 0);
    if (id < 0) { fprintf(stderr, "shmget(0x%x): %s\n", (unsigned)key, strerror(errno)); return 1; }

    struct shmid_ds ds;
    if (shmctl(id, IPC_STAT, &ds) < 0) { fprintf(stderr, "shmctl: %s\n", strerror(errno)); return 1; }
    size_t size = (size_t)ds.shm_segsz;

    void *p = shmat(id, NULL, SHM_RDONLY);
    if (p == (void *)-1) { fprintf(stderr, "shmat: %s\n", strerror(errno)); return 1; }
    const unsigned char *b = (const unsigned char *)p;

    if (!strcmp(argv[2], "stat")) {
        printf("key=0x%08x id=%d size=%zu nattch=%lu cpid=%d lpid=%d\n",
               (unsigned)key, id, size, (unsigned long)ds.shm_nattch, ds.shm_cpid, ds.shm_lpid);
    } else if (!strcmp(argv[2], "dump")) {
        size_t off = (argc > 3) ? strtoul(argv[3], NULL, 0) : 0;
        size_t len = (argc > 4) ? strtoul(argv[4], NULL, 0) : 256;
        if (off > size) off = size;
        if (off + len > size) len = size - off;
        printf("# key=0x%08x size=%zu window=[%zu,%zu)\n", (unsigned)key, size, off, off + len);
        hexdump(b, off, len);
    } else if (!strcmp(argv[2], "find")) {
        if (argc < 4) { fprintf(stderr, "find needs hex bytes\n"); return 2; }
        unsigned char needle[64];
        int nlen = hexparse(argv[3], needle, sizeof needle);
        if (nlen <= 0) { fprintf(stderr, "bad needle\n"); return 2; }
        int hits = 0;
        for (size_t i = 0; i + (size_t)nlen <= size; i++) {
            if (!memcmp(b + i, needle, (size_t)nlen)) { printf("hit @ 0x%zx (%zu)\n", i, i); hits++; }
        }
        printf("# %d hit(s) for %d-byte needle in %zu bytes of key 0x%08x\n",
               hits, nlen, size, (unsigned)key);
    }
    shmdt(p);
    return 0;
}

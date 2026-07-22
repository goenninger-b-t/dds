/* Read-only observation probe for a System V semaphore set (ADR 0081 SS4: RTI keys its shared-memory
 * semaphore at 0x800000+port and its mutex at 0xB00000+port).
 *
 *   semprobe <keyhex>          value / waiter counts for every semaphore in the set
 *
 * Only semctl GET* queries are issued: they read state and never modify it, so a live Connext peer
 * cannot be perturbed. The set size is discovered by probing indices until EINVAL rather than by
 * marshalling `struct semid_ds`, whose layout differs between Darwin and Linux — the same reason
 * the shared-memory probe avoids `struct shmid_ds`.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/sem.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: semprobe <keyhex>\n"); return 2; }
    key_t key = (key_t)strtoul(argv[1], NULL, 16);

    int id = semget(key, 0, 0);
    if (id < 0) { printf("key=0x%08x : no such semaphore set (%s)\n", (unsigned)key, strerror(errno)); return 1; }

    printf("key=0x%08x id=%d\n", (unsigned)key, id);
    for (int i = 0; i < 64; i++) {
        errno = 0;
        int v = semctl(id, i, GETVAL);
        if (v < 0 && errno == EINVAL) { if (i == 0) printf("  (set is empty?)\n"); break; }
        if (v < 0) { printf("  [%d] GETVAL failed: %s\n", i, strerror(errno)); break; }
        int ncnt = semctl(id, i, GETNCNT);   /* processes blocked waiting for it to INCREASE */
        int zcnt = semctl(id, i, GETZCNT);   /* processes blocked waiting for it to reach ZERO */
        printf("  [%d] val=%-6d waiting-for-increase=%-3d waiting-for-zero=%-3d\n", i, v, ncnt, zcnt);
    }
    return 0;
}

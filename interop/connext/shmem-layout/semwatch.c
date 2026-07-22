/* Catch a System V semaphore while it is HELD.
 *
 *   semwatch <keyhex> <seconds>
 *
 * Observing a mutex at rest proves nothing about whether it is used; a critical section measured in
 * hundreds of nanoseconds is invisible to shell-rate sampling. This polls GETVAL/GETNCNT in a tight
 * loop and reports how many samples caught a value other than the resting one, plus the minimum value
 * and maximum waiter count seen. If a mutex is taken on the data path at all, enough traffic and a
 * fast enough poll will land inside the critical section eventually.
 *
 * semctl GET* only: reads state, never modifies it, so a live peer is not perturbed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/ipc.h>
#include <sys/sem.h>

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: semwatch <keyhex> <seconds>\n"); return 2; }
    key_t key = (key_t)strtoul(argv[1], NULL, 16);
    double secs = atof(argv[2]);

    int id = semget(key, 0, 0);
    if (id < 0) { fprintf(stderr, "semget(0x%x): %s\n", (unsigned)key, strerror(errno)); return 1; }

    long long samples = 0, nonrest = 0;
    int vmin = 1 << 30, vmax = -(1 << 30), nmax = 0, rest = semctl(id, 0, GETVAL);
    double t0 = now_s();
    while (now_s() - t0 < secs) {
        for (int i = 0; i < 512; i++) {          /* batch, so the clock is not the bottleneck */
            int v = semctl(id, 0, GETVAL);
            if (v < 0) { fprintf(stderr, "GETVAL: %s\n", strerror(errno)); return 1; }
            samples++;
            if (v < vmin) vmin = v;
            if (v > vmax) vmax = v;
            if (v != rest) {
                nonrest++;
                int n = semctl(id, 0, GETNCNT);
                if (n > nmax) nmax = n;
            }
        }
    }
    double dt = now_s() - t0;
    printf("key=0x%08x  resting=%d  samples=%lld (%.0f/s over %.1fs)\n",
           (unsigned)key, rest, samples, samples / dt, dt);
    printf("  caught off-resting: %lld  (%.4f%% of samples)\n", nonrest, 100.0 * (double)nonrest / (double)samples);
    printf("  value range seen:   min=%d max=%d   max waiters seen while off-resting: %d\n", vmin, vmax, nmax);
    return 0;
}

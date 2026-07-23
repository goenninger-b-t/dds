#!/usr/sbin/dtrace -qs
/*
 * ADR 0081 SS5.0 — the semop/semctl ORDER, obtained without copyin.
 *
 * The semop-only trace showed the producer brackets its ring write in a mutex (131092) take/release but
 * NEVER touches the data semaphore (131093) via semop — yet the consumer's wait on 131093 unblocks,
 * phase-locked to the producer's write. So the wake goes through a different call. This adds semctl,
 * whose command number (arg2) is a scalar needing no copyin: SETVAL is 8. If the producer posts by
 * semctl(131093, 0, SETVAL), it will show here.
 *
 * RUN (root; REAL rtiddsping binary PIDs, publisher then subscriber):
 *
 *     sudo dtrace -qs trace-semop.d <publisher-pid> <subscriber-pid>
 *
 * semid 131092 = mutex (0xB04DC7), 131093 = data semaphore (0x804DC7). semctl cmd 8=SETVAL 5=GETVAL.
 */

pid$1:libsystem_kernel.dylib:semop:entry,
pid$2:libsystem_kernel.dylib:semop:entry
/arg0 == 131092 || arg0 == 131093/
{
    self->w = arg0 + 1;
    printf("%-12llu pid=%-6d semop  ENTRY semid=%-7d %s\n",
           (unsigned long long)(timestamp / 1000), pid, (int)arg0,
           arg0 == 131092 ? "MUTEX" : "DATASEM");
}

pid$1:libsystem_kernel.dylib:semop:return,
pid$2:libsystem_kernel.dylib:semop:return
/self->w/
{
    printf("%-12llu pid=%-6d semop  ret   semid=%-7d %-8s rc=%d\n",
           (unsigned long long)(timestamp / 1000), pid, (int)(self->w - 1),
           (self->w - 1) == 131092 ? "MUTEX" : "DATASEM", (int)arg1);
    self->w = 0;
}

pid$1:libsystem_kernel.dylib:semctl:entry,
pid$2:libsystem_kernel.dylib:semctl:entry
/arg0 == 131092 || arg0 == 131093/
{
    printf("%-12llu pid=%-6d semctl ENTRY semid=%-7d %-8s cmd=%d%s val=%d\n",
           (unsigned long long)(timestamp / 1000), pid, (int)arg0,
           arg0 == 131092 ? "MUTEX" : "DATASEM", (int)arg2,
           arg2 == 8 ? " (SETVAL)" : (arg2 == 5 ? " (GETVAL)" : ""), (int)arg3);
}

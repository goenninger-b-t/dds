#!/usr/sbin/dtrace -qs
/*
 * The one remaining unmeasured piece of ADR 0081 SS5.0: the semop sequence.
 *
 * Everything else about RTI's shared-memory ring was established by observing state — cursors,
 * semaphore values, segment bytes. The ORDER of operations cannot be seen that way: whether the
 * producer posts the data semaphore before or after releasing the mutex, and by what mechanism it
 * avoids stacking posts, are only visible in the syscalls themselves.
 *
 * This needs root, which is why it is a script for the owner to run rather than something the
 * reconstruction could obtain for itself:
 *
 *     sudo dtrace -qs interop/connext/shmem-layout/trace-semop.d
 *
 * while a Connext publisher/subscriber pair is exchanging over shared memory — e.g.
 *
 *     rtiddsping -domainId 50 -subscriber &
 *     rtiddsping -domainId 50 -publisher -sendPeriod 0.5 &
 *
 * A `sem_op` of -1 is a take (mutex lock, or a consumer waiting on the data semaphore); +1 is a
 * release or a post. `sem_flg` carries IPC_NOWAIT (0x800 on Darwin) and SEM_UNDO (0x1000), and
 * IPC_NOWAIT on the data-semaphore post would explain the observed "posts once, does not stack"
 * behaviour directly.
 *
 * Correlate the semid values printed here against `ipcs -s`: 0x800000+port is the data semaphore
 * and 0xB00000+port is the mutex (ADR 0081 SS4).
 */

syscall::semop:entry
/execname == "rtiddsping" || execname == "shapes_pub" || execname == "shapes_sub"/
{
    self->semid = arg0;
    self->buf   = arg1;
    self->nsops = arg2;
}

syscall::semop:return
/self->buf/
{
    /* struct sembuf on Darwin: unsigned short sem_num; short sem_op; short sem_flg; */
    this->num = *(unsigned short *)copyin(self->buf, 2);
    this->op  = *(short *)copyin(self->buf + 2, 2);
    this->flg = *(short *)copyin(self->buf + 4, 2);
    printf("%-14s semid=%-8d nsops=%-2d  sem_num=%-2d sem_op=%-3d sem_flg=0x%04x  rc=%d\n",
           execname, self->semid, self->nsops, this->num, this->op, this->flg, (int)arg0);
    self->buf = 0;
    self->semid = 0;
}

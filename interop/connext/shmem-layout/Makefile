# Observation harness for ADR 0081. Not wired into `make interop` — these are instruments, not gated legs.
CFLAGS ?= -O1 -Wall -Wextra

all: shmprobe semprobe

shmprobe: shmprobe.c
	$(CC) $(CFLAGS) -o $@ $<

semprobe: semprobe.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f shmprobe semprobe

.PHONY: all clean

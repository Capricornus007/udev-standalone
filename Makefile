CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c99

udevd: src/udevd.c
	$(CC) $(CFLAGS) -o udevd src/udevd.c

clean:
	rm -f udevd

.PHONY: clean

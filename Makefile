CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c99

udev: src/udev.c
	$(CC) $(CFLAGS) -o udev src/udev.c

clean:
	rm -f udev

.PHONY: clean

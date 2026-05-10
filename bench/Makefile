CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -I../common

.PHONY: all clean

all: calibrate

calibrate: calibrate.c ../common/probe.h
	$(CC) $(CFLAGS) -o $@ calibrate.c

clean:
	rm -f calibrate

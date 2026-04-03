CC      = gcc
NASM    = nasm
CFLAGS  = -Wall -Wextra -g
NASMFLAGS = -f elf64

TARGETS = main calibrate
ASM_OBJS = gadgets.o

.PHONY: all clean

all: $(TARGETS)

main: main.o $(ASM_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

calibrate: calibrate.o $(ASM_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.asm
	$(NASM) $(NASMFLAGS) -o $@ $<

clean:
	rm -f main calibrate main.o calibrate.o $(ASM_OBJS)

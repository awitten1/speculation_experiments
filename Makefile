CC      = gcc
NASM    = nasm
CFLAGS  = -Wall -Wextra -g -IPTEditor
NASMFLAGS = -f elf64

TARGETS = main calibrate
ASM_OBJS = gadgets.o
PTEDITOR_OBJS = PTEditor/ptedit.o

.PHONY: all clean pteditor

all: $(TARGETS)

pteditor:
	$(MAKE) -C PTEditor

all: pteditor

main: main.o $(ASM_OBJS) $(PTEDITOR_OBJS) | pteditor
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

calibrate: calibrate.o $(ASM_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.asm
	$(NASM) $(NASMFLAGS) -o $@ $<

clean:
	$(MAKE) -C PTEditor clean
	rm -f main calibrate main.o calibrate.o $(ASM_OBJS)

CC      = gcc
NASM    = nasm
CFLAGS  = -Wall -Wextra -g -IPTEditor
NASMFLAGS = -f elf64

# Timing source (AMD Zen 2+ only; crashes on unsupported CPUs):
#   make USE_RDPRU=1       — RDPRU MPERF (ECX=0, max frequency clock)
#   make USE_RDPRU_APERF=1 — RDPRU APERF (ECX=1, actual performance frequency clock)
#   default                — RDTSC
ifdef USE_RDPRU_APERF
CFLAGS += -DUSE_RDPRU_APERF
else ifdef USE_RDPRU
CFLAGS += -DUSE_RDPRU
endif

TARGETS = main calibrate print_vsyscall
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

print_vsyscall: print_vsyscall.o $(ASM_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.asm
	$(NASM) $(NASMFLAGS) -o $@ $<

clean:
	$(MAKE) -C PTEditor clean
	rm -f main calibrate print_vsyscall main.o calibrate.o print_vsyscall.o $(ASM_OBJS)

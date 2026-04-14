#define _GNU_SOURCE

#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

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

#define CACHE_LINE_SIZE 64
#define PAGE_SIZE 4096
#define PARENT_CPU 0
#define HELPER_CPU 2
#define DEFAULT_SAMPLES 20000
#define L1_EVICT_SIZE (64 * 1024)

typedef struct {
    sem_t request;
    sem_t done;
    void *target;
} llc_worker_t;

typedef struct {
    const char *name;
    long *samples;
    int count;
} sample_set_t;

static int pin_to_cpu(int cpu) {
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof(set), &set);
}

static void flush_cache_line(void *ptr) {
    asm volatile("clflush (%0)" : : "r"(ptr) : "memory");
}

static void touch_lines(char *buf, size_t size) {
    volatile char sink = 0;

    for (size_t i = 0; i < size; i += CACHE_LINE_SIZE) {
        sink ^= buf[i];
    }

    if (sink == 0x7f) {
        puts("unreachable");
    }
}

static int compare_long(const void *a, const void *b) {
    long aa = *(const long *)a;
    long bb = *(const long *)b;

    if (aa < bb) return -1;
    if (aa > bb) return 1;
    return 0;
}

static long percentile(const long *sorted, int count, double p) {
    int index = (int)(p * (count - 1));

    if (index < 0) index = 0;
    if (index >= count) index = count - 1;
    return sorted[index];
}

static void print_stats(const sample_set_t *set) {
    printf(
        "%-4s min=%4ld p10=%4ld p50=%4ld p90=%4ld max=%4ld\n",
        set->name,
        set->samples[0],
        percentile(set->samples, set->count, 0.10),
        percentile(set->samples, set->count, 0.50),
        percentile(set->samples, set->count, 0.90),
        set->samples[set->count - 1]
    );
}

// This is a thread which responds to requests to read a cache line into cache.
static void *llc_worker_main(void *arg) {
    llc_worker_t *worker = arg;

    if (pin_to_cpu(HELPER_CPU) != 0) {
        perror("sched_setaffinity helper");
        exit(1);
    }

    for (;;) {
        sem_wait(&worker->request);
        if (worker->target == NULL) {
            sem_post(&worker->done);
            return NULL;
        }

        *(volatile uint64_t *)worker->target;
        sem_post(&worker->done);
    }
}

static long measure_l1(void *target) {
    *(volatile uint64_t *)target;
    return TIME_LOAD(target);
}

static long measure_l2(void *target, char *l1_evict_buf) {
    *(volatile uint64_t *)target;
    touch_lines(l1_evict_buf, L1_EVICT_SIZE);
    return TIME_LOAD(target);
}

static long measure_llc(void *target, llc_worker_t *worker) {
    flush_cache_line(target);
    worker->target = target;
    sem_post(&worker->request);
    sem_wait(&worker->done);
    return TIME_LOAD(target);
}

static long measure_ram(void *target) {
    flush_cache_line(target);
    return TIME_LOAD(target);
}

int main(int argc, char **argv) {
    int samples = DEFAULT_SAMPLES;
    pthread_t helper;
    llc_worker_t worker;
    long *l1_samples;
    long *l2_samples;
    long *llc_samples;
    long *ram_samples;
    sample_set_t sets[4];
    char *target_buf;
    char *target;
    char *l1_evict_buf;

    if (argc > 1) {
        samples = atoi(argv[1]);
    }
    if (samples <= 0) {
        fprintf(stderr, "usage: %s [samples]\n", argv[0]);
        return 1;
    }

    if (pin_to_cpu(PARENT_CPU) != 0) {
        perror("sched_setaffinity parent");
        return 1;
    }

    target_buf = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    l1_evict_buf = mmap(NULL, L1_EVICT_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    l1_samples = malloc((size_t)samples * sizeof(long));
    l2_samples = malloc((size_t)samples * sizeof(long));
    llc_samples = malloc((size_t)samples * sizeof(long));
    ram_samples = malloc((size_t)samples * sizeof(long));
    if (target_buf == MAP_FAILED || l1_evict_buf == MAP_FAILED ||
        l1_samples == NULL || l2_samples == NULL ||
        llc_samples == NULL || ram_samples == NULL) {
        fprintf(stderr, "allocation failure\n");
        return 1;
    }

    memset(target_buf, 1, PAGE_SIZE);
    memset(l1_evict_buf, 1, L1_EVICT_SIZE);
    target = target_buf;

    sem_init(&worker.request, 0, 0);
    sem_init(&worker.done, 0, 0);
    worker.target = NULL;

    if (pthread_create(&helper, NULL, llc_worker_main, &worker) != 0) {
        fprintf(stderr, "pthread_create failed\n");
        return 1;
    }

    for (int i = 0; i < samples; i++) {
        l1_samples[i] = measure_l1(target);
        l2_samples[i] = measure_l2(target, l1_evict_buf);
        llc_samples[i] = measure_llc(target, &worker);
        ram_samples[i] = measure_ram(target);
    }

    worker.target = NULL;
    sem_post(&worker.request);
    sem_wait(&worker.done);
    pthread_join(helper, NULL);

    qsort(l1_samples, (size_t)samples, sizeof(long), compare_long);
    qsort(l2_samples, (size_t)samples, sizeof(long), compare_long);
    qsort(llc_samples, (size_t)samples, sizeof(long), compare_long);
    qsort(ram_samples, (size_t)samples, sizeof(long), compare_long);

    sets[0] = (sample_set_t){ .name = "L1", .samples = l1_samples, .count = samples };
    sets[1] = (sample_set_t){ .name = "L2", .samples = l2_samples, .count = samples };
    sets[2] = (sample_set_t){ .name = "LLC", .samples = llc_samples, .count = samples };
    sets[3] = (sample_set_t){ .name = "RAM", .samples = ram_samples, .count = samples };

    printf("pinned parent to cpu %d and helper to cpu %d\n", PARENT_CPU, HELPER_CPU);
    printf("samples per class: %d\n", samples);
    for (int i = 0; i < 4; i++) {
        print_stats(&sets[i]);
    }

    printf(
        "suggested thresholds: <=%ld L1, <=%ld L2, <=%ld LLC, >%ld RAM\n",
        (percentile(l1_samples, samples, 0.50) + percentile(l2_samples, samples, 0.50)) / 2,
        (percentile(l2_samples, samples, 0.50) + percentile(llc_samples, samples, 0.50)) / 2,
        (percentile(llc_samples, samples, 0.50) + percentile(ram_samples, samples, 0.50)) / 2,
        (percentile(llc_samples, samples, 0.50) + percentile(ram_samples, samples, 0.50)) / 2
    );

    sem_destroy(&worker.request);
    sem_destroy(&worker.done);
    munmap(target_buf, PAGE_SIZE);
    munmap(l1_evict_buf, L1_EVICT_SIZE);
    free(l1_samples);
    free(l2_samples);
    free(llc_samples);
    free(ram_samples);
    return 0;
}

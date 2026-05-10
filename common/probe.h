#ifndef SPECEXP_PROBE_H
#define SPECEXP_PROBE_H

#define _GNU_SOURCE
#include <emmintrin.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <x86intrin.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SPECEXP_PAGE_SIZE
#define SPECEXP_PAGE_SIZE 4096
#endif
#define SPECEXP_CACHELINE_SIZE 64
#define SPECEXP_NUM_PAGES 256
#define SPECEXP_PROBE_SKIP_LOW 1

static inline long specexp_time_load(const void *ptr) {
    unsigned int junk = 0;
    unsigned long long start = __rdtscp(&junk);
    (void)*(volatile const unsigned char *)ptr;
    unsigned long long end = __rdtscp(&junk);
    return (long)(end - start);
}

static inline void specexp_flush_buffer(void *buf, size_t bufsz) {
    char *p = (char *)buf;
    for (size_t i = 0; i < bufsz; i += SPECEXP_CACHELINE_SIZE) {
        _mm_clflush(p + i);
    }
    _mm_mfence();
}

static inline unsigned int specexp_lcg_next(unsigned int s) {
    return s * 1664525u + 1013904223u;
}

static inline int specexp_probe_argmin(const void *buf, int num_slots, int threshold,
                                       int skip_low, int *order, unsigned int *lcg_state) {
    for (int i = 0; i < num_slots; ++i) {
        order[i] = i;
    }
    for (int i = num_slots - 1; i > 0; --i) {
        *lcg_state = specexp_lcg_next(*lcg_state);
        int j = (int)(*lcg_state % (unsigned int)(i + 1));
        int t = order[i];
        order[i] = order[j];
        order[j] = t;
    }

    int best = -1;
    long best_lat = 0;
    for (int i = 0; i < num_slots; ++i) {
        int slot = order[i];
        if (slot < skip_low) {
            continue;
        }
        const char *ptr = (const char *)buf + (size_t)slot * SPECEXP_PAGE_SIZE;
        long lat = specexp_time_load(ptr);
        if (lat < threshold && (best < 0 || lat < best_lat)) {
            best = slot;
            best_lat = lat;
        }
    }
    return best;
}

static int specexp_cmp_long(const void *a, const void *b) {
    long la = *(const long *)a;
    long lb = *(const long *)b;
    return (la > lb) - (la < lb);
}

static inline int specexp_calibrate_threshold(void) {
    enum { REPS = 2048 };
    static long hit[REPS];
    static long miss[REPS];
    static unsigned char buf[SPECEXP_CACHELINE_SIZE * 4];
    unsigned char *p = (unsigned char *)(((uintptr_t)buf + SPECEXP_CACHELINE_SIZE - 1) &
                                          ~(uintptr_t)(SPECEXP_CACHELINE_SIZE - 1));
    *p = 1;
    for (int i = 0; i < 256; ++i) {
        (void)*(volatile unsigned char *)p;
    }

    for (int i = 0; i < REPS; ++i) {
        (void)*(volatile unsigned char *)p;
        _mm_lfence();
        hit[i] = specexp_time_load(p);

        _mm_clflush(p);
        _mm_mfence();
        miss[i] = specexp_time_load(p);
    }

    qsort(hit, REPS, sizeof(long), specexp_cmp_long);
    qsort(miss, REPS, sizeof(long), specexp_cmp_long);
    long hit_med = hit[REPS / 2];
    long miss_med = miss[REPS / 2];
    long thresh = hit_med + (miss_med - hit_med) / 2;
    fprintf(stderr, "calibrate: hit_med=%ld miss_med=%ld threshold=%ld\n",
            hit_med, miss_med, thresh);
    return (int)thresh;
}

static inline void *specexp_alloc_probe_buf(int num_pages) {
    size_t sz = (size_t)num_pages * SPECEXP_PAGE_SIZE;
    void *buf = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (buf == MAP_FAILED) {
        perror("mmap probe");
        exit(1);
    }
    memset(buf, 1, sz);
    return buf;
}

static inline void specexp_pin_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        perror("sched_setaffinity");
        exit(1);
    }
}

static inline const char *specexp_outcome(int found, int target) {
    if (found < 0) {
        return "unknown";
    }
    if (found == target) {
        return "correct";
    }
    return "wrong";
}

#ifdef __cplusplus
}
#endif

#endif

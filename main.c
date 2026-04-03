#define _GNU_SOURCE

#include <limits.h>
#include <errno.h>
#include <semaphore.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern void spec_ret_gadget(void *ptr);
extern long time_memory_load(void *ptr);

#define PAGE_SIZE 4096
#define CACHE_LINE_SIZE 64
#define HIT_THRESHOLD_LLC 350
#define HIT_THRESHOLD_L1 100
#define DEFAULT_PRIVATE_CPU 0
#define DEFAULT_LLC_PARENT_CPU 0
#define DEFAULT_LLC_CHILD_CPU 2

typedef enum {
    ACCESS_NON_TRANSIENT,
    ACCESS_TRANSIENT,
} access_mode_t;

typedef enum {
    CACHE_PRIVATE,
    CACHE_LLC,
} cache_mode_t;

typedef struct {
    sem_t trial_ready;
    sem_t probe_done;
    int target;
} shared_t;

typedef struct {
    int slots;
    int num_trials;
    access_mode_t access_mode;
    cache_mode_t cache_mode;
    int parent_cpu;
    int child_cpu;
} experiment_config_t;

typedef struct {
    int hits;
    int unknown;
    int incorrect;
} probe_stats_t;

static const char *access_mode_name(access_mode_t mode) {
    return mode == ACCESS_TRANSIENT ? "transient" : "non-transient";
}

static const char *cache_mode_name(cache_mode_t mode) {
    return mode == CACHE_PRIVATE ? "private" : "llc";
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "usage: %s <slots> <trials> <n|t> <private|llc> [parent_cpu [child_cpu]]\n",
            argv0);
    fprintf(stderr, "  private mode defaults to parent_cpu=child_cpu=%d\n", DEFAULT_PRIVATE_CPU);
    fprintf(stderr, "  llc mode defaults to parent_cpu=%d child_cpu=%d\n",
            DEFAULT_LLC_PARENT_CPU, DEFAULT_LLC_CHILD_CPU);
}

static int pin_to_cpu(int cpu) {
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof(set), &set);
}

static void flush_from_cache(void *buf, size_t bufsz) {
    char *p = buf;
    size_t num_cache_lines = (bufsz + CACHE_LINE_SIZE - 1) / CACHE_LINE_SIZE;

    for (size_t i = 0; i < num_cache_lines; i++) {
        asm volatile("clflush (%0)" : : "r"(p + i * CACHE_LINE_SIZE) : "memory");
    }
}

static int probe(void *buf, int num_slots, int threshold) {
    int *order = malloc((size_t)num_slots * sizeof(int));
    int found = -1;

    if (order == NULL) {
        perror("malloc");
        exit(1);
    }

    for (int i = 0; i < num_slots; i++) {
        order[i] = i;
    }
    for (int i = num_slots - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int tmp = order[i];
        order[i] = order[j];
        order[j] = tmp;
    }

    for (int i = 0; i < num_slots; i++) {
        char *ptr = (char *)buf + order[i] * PAGE_SIZE;
        long load_time = time_memory_load(ptr);

        if (load_time < threshold) {
            found = order[i];
            break;
        }
    }

    free(order);
    return found;
}

static void execute_access(access_mode_t mode, void *ptr) {
    if (mode == ACCESS_TRANSIENT) {
        spec_ret_gadget(ptr);
        return;
    }

    *(volatile char *)ptr;
}

static void record_probe_result(probe_stats_t *stats, int expected, int found) {
    if (found == expected) {
        stats->hits++;
    } else if (found == -1) {
        stats->unknown++;
    } else {
        stats->incorrect++;
    }
}

static void print_summary(const experiment_config_t *config, const probe_stats_t *stats) {
    printf(
        "%s %s: hits %d/%d (%.1f%%) unknown %d/%d (%.1f%%) incorrect %d/%d (%.1f%%)\n",
        cache_mode_name(config->cache_mode),
        access_mode_name(config->access_mode),
        stats->hits,
        config->num_trials,
        100.0 * stats->hits / config->num_trials,
        stats->unknown,
        config->num_trials,
        100.0 * stats->unknown / config->num_trials,
        stats->incorrect,
        config->num_trials,
        100.0 * stats->incorrect / config->num_trials
    );
}

static void child_process(const experiment_config_t *config, shared_t *shared,
                          void *buf, size_t buf_size) {
    probe_stats_t stats = {0};

    if (pin_to_cpu(config->child_cpu) != 0) {
        perror("sched_setaffinity child");
        exit(1);
    }

    for (int t = 0; t < config->num_trials; t++) {
        sem_wait(&shared->trial_ready);
        record_probe_result(&stats, shared->target, probe(buf, config->slots,
            config->cache_mode == CACHE_LLC ? HIT_THRESHOLD_LLC : HIT_THRESHOLD_L1));
        flush_from_cache(buf, buf_size);
        sem_post(&shared->probe_done);
    }

    print_summary(config, &stats);
    exit(0);
}

static void parent_process(const experiment_config_t *config, shared_t *shared, void *buf) {
    for (int t = 0; t < config->num_trials; t++) {
        char *ptr;

        shared->target = rand() % config->slots;
        ptr = (char *)buf + shared->target * PAGE_SIZE;

        execute_access(config->access_mode, ptr);
        sem_post(&shared->trial_ready);
        sem_wait(&shared->probe_done);
    }
}

static void run_experiment(const experiment_config_t *config, void *buf) {
    size_t buf_size = (size_t)config->slots * PAGE_SIZE;
    shared_t *shared = mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE,
                            MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    pid_t pid;

    if (shared == MAP_FAILED) {
        perror("mmap shared");
        exit(1);
    }
    if (sem_init(&shared->trial_ready, 1, 0) != 0 ||
        sem_init(&shared->probe_done, 1, 0) != 0) {
        perror("sem_init");
        exit(1);
    }

    flush_from_cache(buf, buf_size);
    printf("cache mode %s, access mode %s, parent cpu %d, child cpu %d\n",
           cache_mode_name(config->cache_mode),
           access_mode_name(config->access_mode),
           config->parent_cpu,
           config->child_cpu);
    fflush(stdout);

    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }
    if (pid == 0) {
        child_process(config, shared, buf, buf_size);
    }

    if (pin_to_cpu(config->parent_cpu) != 0) {
        perror("sched_setaffinity parent");
        wait(NULL);
        exit(1);
    }

    parent_process(config, shared, buf);
    wait(NULL);
    sem_destroy(&shared->trial_ready);
    sem_destroy(&shared->probe_done);
    munmap(shared, sizeof(*shared));
}

static access_mode_t parse_access_mode(const char *arg) {
    if (strcmp(arg, "t") == 0) {
        return ACCESS_TRANSIENT;
    }
    if (strcmp(arg, "n") == 0) {
        return ACCESS_NON_TRANSIENT;
    }

    fprintf(stderr, "invalid access mode: %s\n", arg);
    usage("main");
    exit(1);
}

static cache_mode_t parse_cache_mode(const char *arg) {
    if (strcmp(arg, "private") == 0) {
        return CACHE_PRIVATE;
    }
    if (strcmp(arg, "llc") == 0) {
        return CACHE_LLC;
    }

    fprintf(stderr, "invalid cache mode: %s\n", arg);
    usage("main");
    exit(1);
}

static void initialize_cpu_defaults(experiment_config_t *config) {
    if (config->cache_mode == CACHE_PRIVATE) {
        config->parent_cpu = DEFAULT_PRIVATE_CPU;
        config->child_cpu = DEFAULT_PRIVATE_CPU;
        return;
    }

    config->parent_cpu = DEFAULT_LLC_PARENT_CPU;
    config->child_cpu = DEFAULT_LLC_CHILD_CPU;
}

static void parse_positive_int_arg(const char *name, const char *arg, int *value) {
    char *end = NULL;
    long parsed = strtol(arg, &end, 10);

    if (end == arg || *end != '\0' || parsed <= 0 || parsed > INT_MAX) {
        fprintf(stderr, "invalid %s: %s\n", name, arg);
        exit(1);
    }

    *value = (int)parsed;
}

static void parse_cpu_arg(const char *name, const char *arg, int *value) {
    char *end = NULL;
    long parsed = strtol(arg, &end, 10);

    if (end == arg || *end != '\0' || parsed < 0 || parsed > INT_MAX) {
        fprintf(stderr, "invalid %s: %s\n", name, arg);
        exit(1);
    }

    *value = (int)parsed;
}

static experiment_config_t parse_config(int argc, char **argv) {
    experiment_config_t config;

    if (argc < 5 || argc > 7) {
        usage(argv[0]);
        exit(1);
    }

    parse_positive_int_arg("slots", argv[1], &config.slots);
    parse_positive_int_arg("trials", argv[2], &config.num_trials);
    config.access_mode = parse_access_mode(argv[3]);
    config.cache_mode = parse_cache_mode(argv[4]);
    initialize_cpu_defaults(&config);

    if (argc >= 6) {
        parse_cpu_arg("parent_cpu", argv[5], &config.parent_cpu);
    }
    if (argc >= 7) {
        parse_cpu_arg("child_cpu", argv[6], &config.child_cpu);
    } else if (argc == 6 && config.cache_mode == CACHE_PRIVATE) {
        config.child_cpu = config.parent_cpu;
    }

    return config;
}

int main(int argc, char **argv) {
    experiment_config_t config = parse_config(argc, argv);
    size_t buf_size = (size_t)config.slots * PAGE_SIZE;
    void *buf;

    srand((unsigned int)time(NULL));
    printf("allocating %.2f mb\n", (double)buf_size / (1024.0 * 1024.0));

    buf = mmap(NULL, buf_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (buf == MAP_FAILED) {
        perror("mmap buf");
        return 1;
    }
    memset(buf, 0, buf_size);

    run_experiment(&config, buf);
    munmap(buf, buf_size);
    return 0;
}

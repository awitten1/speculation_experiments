#define _GNU_SOURCE

#include <getopt.h>
#include <limits.h>
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

#include "ptedit.h"

extern void spec_ret_gadget(void *ptr);
extern void spec_ret_gadget_burst(void *ptr);
extern void spec_ret_store_gadget(void *ptr);
extern void spec_read_gadget(void *secret, void *probe_array);
extern long time_memory_load(void *ptr);

static const char secret[] = "this is my super secret value!";

#define NUM_BYTE_SLOTS 256

#define PAGE_SIZE 4096
#define CACHE_LINE_SIZE 64
#define HIT_THRESHOLD_LLC 350
#define HIT_THRESHOLD_L1 100
#define DEFAULT_PRIVATE_CPU 0
#define DEFAULT_LLC_PARENT_CPU 0
#define DEFAULT_LLC_CHILD_CPU 2
#define STACK_PTE_FLUSH_LEVELS \
    (PTEDIT_FLUSH_LEVEL_PGD | PTEDIT_FLUSH_LEVEL_P4D | PTEDIT_FLUSH_LEVEL_PUD | \
     PTEDIT_FLUSH_LEVEL_PMD | PTEDIT_FLUSH_LEVEL_PTE)

typedef enum {
    ACCESS_NON_TRANSIENT,
    ACCESS_TRANSIENT,
} access_mode_t;

typedef enum {
    GADGET_LOAD,
    GADGET_LOAD_BURST,
    GADGET_STORE_THEN_LOAD,
} gadget_mode_t;

typedef enum {
    CACHE_PRIVATE,
    CACHE_LLC,
} cache_mode_t;

typedef enum {
    PROBE_FORKED,
    PROBE_SAME_THREAD,
} probe_mode_t;

typedef struct {
    sem_t trial_ready;
    sem_t probe_done;
    int target;
} shared_t;

typedef struct {
    int slots;
    int num_trials;
    access_mode_t access_mode;
    gadget_mode_t gadget_mode;
    cache_mode_t cache_mode;
    probe_mode_t probe_mode;
    int flush_stack_ptes;
    int parent_cpu;
    int child_cpu;
    int read_secret;
    int cpu;
} experiment_config_t;

typedef struct {
    int hits;
    int unknown;
    int incorrect;
} probe_stats_t;

static const char *access_mode_name(access_mode_t mode) {
    return mode == ACCESS_TRANSIENT ? "transient" : "non-transient";
}

static const char *gadget_mode_name(gadget_mode_t mode) {
    switch (mode) {
    case GADGET_LOAD:
        return "load";
    case GADGET_LOAD_BURST:
        return "load-burst";
    case GADGET_STORE_THEN_LOAD:
        return "store";
    }

    return "unknown";
}

static const char *cache_mode_name(cache_mode_t mode) {
    return mode == CACHE_PRIVATE ? "private" : "llc";
}

static const char *probe_mode_name(probe_mode_t mode) {
    return mode == PROBE_SAME_THREAD ? "same-thread" : "forked";
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "usage: %s --slots N --trials N --access <n|non-transient|t|transient> "
            "--cache <private|llc> [options]\n",
            argv0);
    fprintf(stderr, "  --gadget <load|load-burst|store> transient gadget variant\n");
    fprintf(stderr, "  --probe <forked|same-thread> probe from child process or current thread\n");
    fprintf(stderr, "  --parent-cpu N         override parent CPU affinity\n");
    fprintf(stderr, "  --child-cpu N          override child CPU affinity\n");
    fprintf(stderr, "  --flush-stack-ptes     flush stack page-table entries before transient access\n");
    fprintf(stderr, "  --help                 show this message\n");
    fprintf(stderr, "  private defaults to parent_cpu=child_cpu=%d\n", DEFAULT_PRIVATE_CPU);
    fprintf(stderr, "  llc defaults to parent_cpu=%d child_cpu=%d\n",
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

static int probe(void *buf, int num_slots, int threshold, int *order) {
    int found = -1;

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

    return found;
}

static void flush_stack_ptes(void) {
    volatile char stack_marker = 0;

    if (ptedit_flush_address_cache((void *)&stack_marker, 0, STACK_PTE_FLUSH_LEVELS, 0) != 0) {
        fprintf(stderr, "ptedit_flush_address_cache failed for stack address\n");
        exit(1);
    }
}

static void execute_access(const experiment_config_t *config, void *ptr) {
    if (config->flush_stack_ptes) {
        flush_stack_ptes();
    }

    if (config->access_mode == ACCESS_TRANSIENT) {
        switch (config->gadget_mode) {
        case GADGET_LOAD:
            spec_ret_gadget(ptr);
            break;
        case GADGET_LOAD_BURST:
            spec_ret_gadget_burst(ptr);
            break;
        case GADGET_STORE_THEN_LOAD:
            spec_ret_store_gadget(ptr);
            break;
        }
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
        "%s %s %s %s: hits %d/%d (%.1f%%) unknown %d/%d (%.1f%%) incorrect %d/%d (%.1f%%)\n",
        cache_mode_name(config->cache_mode),
        access_mode_name(config->access_mode),
        gadget_mode_name(config->gadget_mode),
        probe_mode_name(config->probe_mode),
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
    int *order = malloc((size_t)config->slots * sizeof(int));

    if (order == NULL) {
        perror("malloc");
        exit(1);
    }

    if (pin_to_cpu(config->child_cpu) != 0) {
        perror("sched_setaffinity child");
        free(order);
        exit(1);
    }

    for (int t = 0; t < config->num_trials; t++) {
        sem_wait(&shared->trial_ready);
        record_probe_result(&stats, shared->target, probe(buf, config->slots,
            config->cache_mode == CACHE_LLC ? HIT_THRESHOLD_LLC : HIT_THRESHOLD_L1, order));
        flush_from_cache(buf, buf_size);
        sem_post(&shared->probe_done);
    }

    free(order);
    print_summary(config, &stats);
    exit(0);
}

static void parent_process(const experiment_config_t *config, shared_t *shared, void *buf) {
    for (int t = 0; t < config->num_trials; t++) {
        char *ptr;

        shared->target = rand() % config->slots;
        ptr = (char *)buf + shared->target * PAGE_SIZE;

        execute_access(config, ptr);
        sem_post(&shared->trial_ready);
        sem_wait(&shared->probe_done);
    }
}

static int probe_threshold(const experiment_config_t *config) {
    return config->cache_mode == CACHE_LLC ? HIT_THRESHOLD_LLC : HIT_THRESHOLD_L1;
}

static void run_same_thread_experiment(const experiment_config_t *config, void *buf) {
    size_t buf_size = (size_t)config->slots * PAGE_SIZE;
    probe_stats_t stats = {0};
    int *order = malloc((size_t)config->slots * sizeof(int));

    if (order == NULL) {
        perror("malloc");
        exit(1);
    }

    if (pin_to_cpu(config->parent_cpu) != 0) {
        perror("sched_setaffinity parent");
        free(order);
        exit(1);
    }

    for (int t = 0; t < config->num_trials; t++) {
        int target = rand() % config->slots;
        char *ptr = (char *)buf + target * PAGE_SIZE;
        int found;

        execute_access(config, ptr);
        found = probe(buf, config->slots, probe_threshold(config), order);
        record_probe_result(&stats, target, found);
        flush_from_cache(buf, buf_size);
    }

    free(order);
    print_summary(config, &stats);
}

static void run_secret_experiment(int num_trials, int cpu) {
    size_t probe_size = (size_t)NUM_BYTE_SLOTS * PAGE_SIZE;
    void *probe_array = mmap(NULL, probe_size, PROT_READ | PROT_WRITE,
                             MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    int secret_len = (int)strlen(secret);

    if (probe_array == MAP_FAILED) {
        perror("mmap probe_array");
        return;
    }
    memset(probe_array, 0, probe_size);
    if (pin_to_cpu(cpu) != 0)
        perror("sched_setaffinity");
    printf("running on cpu %d\n", sched_getcpu());
    char guessed[sizeof(secret)] = {0};
    int *order = malloc(NUM_BYTE_SLOTS * sizeof(int));

    if (order == NULL) {
        perror("malloc");
        munmap(probe_array, probe_size);
        return;
    }

    for (int i = 0; i < secret_len; i++) {
        int hits[NUM_BYTE_SLOTS] = {0};

        for (int t = 0; t < num_trials; t++) {
            flush_from_cache(probe_array, probe_size);
            spec_read_gadget((char *)secret + i, probe_array);
            int found = probe(probe_array, NUM_BYTE_SLOTS, HIT_THRESHOLD_L1, order);
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

        guessed[i] = best >= 0 ? (char)best : '_';
        printf("secret[%2d]: hit_rate=%.1f%%\n", i, 100.0 * best_count / num_trials);
    }

    printf("expected: %s\n", secret);
    printf("received: %s\n", guessed);
    free(order);
    munmap(probe_array, probe_size);
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
    printf("cache mode %s, access mode %s, gadget %s, probe mode %s, parent cpu %d, child cpu %d, running on cpu %d\n",
           cache_mode_name(config->cache_mode),
           access_mode_name(config->access_mode),
           gadget_mode_name(config->gadget_mode),
           probe_mode_name(config->probe_mode),
           config->parent_cpu,
           config->child_cpu,
           sched_getcpu());
    if (config->flush_stack_ptes) {
        printf("transient stack PTE flushing enabled\n");
    }
    fflush(stdout);

    if (config->probe_mode == PROBE_SAME_THREAD) {
        run_same_thread_experiment(config, buf);
        munmap(shared, sizeof(*shared));
        return;
    }

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
    if (strcmp(arg, "t") == 0 || strcmp(arg, "transient") == 0) {
        return ACCESS_TRANSIENT;
    }
    if (strcmp(arg, "n") == 0 || strcmp(arg, "non-transient") == 0) {
        return ACCESS_NON_TRANSIENT;
    }

    fprintf(stderr, "invalid access mode: %s\n", arg);
    usage("main");
    exit(1);
}

static gadget_mode_t parse_gadget_mode(const char *arg) {
    if (strcmp(arg, "load") == 0) {
        return GADGET_LOAD;
    }
    if (strcmp(arg, "load-burst") == 0) {
        return GADGET_LOAD_BURST;
    }
    if (strcmp(arg, "store") == 0) {
        return GADGET_STORE_THEN_LOAD;
    }

    fprintf(stderr, "invalid gadget mode: %s\n", arg);
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

static probe_mode_t parse_probe_mode(const char *arg) {
    if (strcmp(arg, "forked") == 0) {
        return PROBE_FORKED;
    }
    if (strcmp(arg, "same-thread") == 0) {
        return PROBE_SAME_THREAD;
    }

    fprintf(stderr, "invalid probe mode: %s\n", arg);
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

static int parse_required_int(const char *name, const char *arg, int *value, int allow_zero) {
    char *end = NULL;
    long parsed = strtol(arg, &end, 10);

    if (end == arg || *end != '\0' || parsed > INT_MAX || (!allow_zero && parsed <= 0) ||
        (allow_zero && parsed < 0)) {
        fprintf(stderr, "invalid %s: %s\n", name, arg);
        return -1;
    }

    *value = (int)parsed;
    return 0;
}

static experiment_config_t parse_config(int argc, char **argv) {
    experiment_config_t config;
    int have_slots = 0;
    int have_trials = 0;
    int have_access = 0;
    int have_gadget = 0;
    int have_cache = 0;
    int have_parent_cpu = 0;
    int have_child_cpu = 0;
    int option_index = 0;
    int opt;
    static const struct option long_options[] = {
        {"slots", required_argument, NULL, 's'},
        {"trials", required_argument, NULL, 'n'},
        {"access", required_argument, NULL, 'a'},
        {"gadget", required_argument, NULL, 'g'},
        {"cache", required_argument, NULL, 'c'},
        {"probe", required_argument, NULL, 'r'},
        {"parent-cpu", required_argument, NULL, 'p'},
        {"child-cpu", required_argument, NULL, 'q'},
        {"flush-stack-ptes", no_argument, NULL, 'f'},
        {"read-secret", no_argument, NULL, 'x'},
        {"cpu", required_argument, NULL, 'u'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0},
    };

    memset(&config, 0, sizeof(config));
    config.flush_stack_ptes = 0;
    config.probe_mode = PROBE_FORKED;
    config.gadget_mode = GADGET_LOAD;
    opterr = 0;

    while ((opt = getopt_long(argc, argv, "s:n:a:g:c:r:p:q:u:fxh", long_options, &option_index)) != -1) {
        switch (opt) {
        case 's':
            if (parse_required_int("slots", optarg, &config.slots, 0) != 0) {
                exit(1);
            }
            have_slots = 1;
            break;
        case 'n':
            if (parse_required_int("trials", optarg, &config.num_trials, 0) != 0) {
                exit(1);
            }
            have_trials = 1;
            break;
        case 'a':
            config.access_mode = parse_access_mode(optarg);
            have_access = 1;
            break;
        case 'g':
            config.gadget_mode = parse_gadget_mode(optarg);
            have_gadget = 1;
            break;
        case 'c':
            config.cache_mode = parse_cache_mode(optarg);
            have_cache = 1;
            break;
        case 'r':
            config.probe_mode = parse_probe_mode(optarg);
            break;
        case 'p':
            if (parse_required_int("parent_cpu", optarg, &config.parent_cpu, 1) != 0) {
                exit(1);
            }
            have_parent_cpu = 1;
            break;
        case 'q':
            if (parse_required_int("child_cpu", optarg, &config.child_cpu, 1) != 0) {
                exit(1);
            }
            have_child_cpu = 1;
            break;
        case 'f':
            config.flush_stack_ptes = 1;
            break;
        case 'x':
            config.read_secret = 1;
            break;
        case 'u':
            if (parse_required_int("cpu", optarg, &config.cpu, 1) != 0)
                exit(1);
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            usage(argv[0]);
            exit(1);
        }
    }

    if (optind != argc) {
        fprintf(stderr, "unexpected positional argument: %s\n", argv[optind]);
        usage(argv[0]);
        exit(1);
    }
    if (config.read_secret) {
        if (!have_trials) {
            usage(argv[0]);
            exit(1);
        }
        return config;
    }
    if (!have_slots || !have_trials || !have_access || !have_cache) {
        usage(argv[0]);
        exit(1);
    }

    if (!have_parent_cpu && !have_child_cpu) {
        initialize_cpu_defaults(&config);
    } else if (config.cache_mode == CACHE_PRIVATE) {
        if (!have_parent_cpu && have_child_cpu) {
            config.parent_cpu = config.child_cpu;
        } else if (have_parent_cpu && !have_child_cpu) {
            config.child_cpu = config.parent_cpu;
        }
    } else {
        if (!have_parent_cpu) {
            config.parent_cpu = DEFAULT_LLC_PARENT_CPU;
        }
        if (!have_child_cpu) {
            config.child_cpu = DEFAULT_LLC_CHILD_CPU;
        }
    }

    if (config.cache_mode == CACHE_PRIVATE && config.parent_cpu != config.child_cpu) {
        fprintf(stderr, "private mode requires the same parent and child CPU\n");
        exit(1);
    }
    if (config.probe_mode == PROBE_SAME_THREAD) {
        config.child_cpu = config.parent_cpu;
    } else if (config.cache_mode == CACHE_PRIVATE && !have_child_cpu) {
        config.child_cpu = config.parent_cpu;
    }
    if (config.cache_mode == CACHE_LLC && config.probe_mode == PROBE_SAME_THREAD) {
        fprintf(stderr, "llc cache mode requires --probe forked\n");
        exit(1);
    }
    if (config.access_mode == ACCESS_NON_TRANSIENT && have_gadget) {
        fprintf(stderr, "--gadget only applies to transient mode\n");
        exit(1);
    }
    if (config.flush_stack_ptes && config.access_mode != ACCESS_TRANSIENT) {
        fprintf(stderr, "flush-stack-ptes requires transient mode\n");
        exit(1);
    }

    return config;
}

int main(int argc, char **argv) {
    experiment_config_t config = parse_config(argc, argv);
    size_t buf_size = (size_t)config.slots * PAGE_SIZE;
    void *buf;

    srand((unsigned int)time(NULL));
    printf("allocating %.2f mb\n", (double)buf_size / (1024.0 * 1024.0));

    if (config.read_secret) {
        run_secret_experiment(config.num_trials, config.cpu);
        return 0;
    }

    buf = mmap(NULL, buf_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (buf == MAP_FAILED) {
        perror("mmap buf");
        return 1;
    }
    memset(buf, 0, buf_size);

    if (config.flush_stack_ptes && ptedit_init() != 0) {
        fprintf(stderr, "ptedit_init failed; is the PTEditor module loaded?\n");
        munmap(buf, buf_size);
        return 1;
    }

    run_experiment(&config, buf);
    if (config.flush_stack_ptes) {
        ptedit_cleanup();
    }
    munmap(buf, buf_size);
    return 0;
}

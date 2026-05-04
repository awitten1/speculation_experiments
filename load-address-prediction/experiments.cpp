#include <algorithm>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#if defined(__APPLE__)
#include <pthread.h>
#include "apple_arm_events.h"
#elif defined(__linux__)
#include <x86intrin.h>
#include <sched.h>
#endif

#include "setup.h"

static const size_t kArraySizeBytes = 1 << 15;
static const int kMinIters = 10;
static const int kMaxIters = 1000;
static const int kIterStep = 10;
static const int kReps = 1000;

class CounterSource {
 public:
  bool setup(void) {
#if defined(__APPLE__)
    use_cycles_ = apple_events_.setup_performance_counters();
    return use_cycles_;
#elif defined(__linux__)
    use_cycles_ = true;
    return true;
#else
    return false;
#endif
  }

  const char* unit(void) const {
    return use_cycles_ ? "cycles" : "ns";
  }

  uint64_t now(void) {
#if defined(__APPLE__)
    if (use_cycles_) {
      return static_cast<uint64_t>(apple_events_.get_counters().cycles);
    }
#elif defined(__linux__)
    if (use_cycles_) {
      return __rdtsc();
    }
#endif
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull +
           static_cast<uint64_t>(ts.tv_nsec);
  }

 private:
  bool use_cycles_ = false;
#if defined(__APPLE__)
  AppleEvents apple_events_;
#endif
};

enum AccessPattern {
  PATTERN_RANDOM,
  PATTERN_STRIDED,
  PATTERN_SA_RV,
};

static const char* access_pattern_name(enum AccessPattern pattern) {
  switch (pattern) {
    case PATTERN_RANDOM:  return "random";
    case PATTERN_STRIDED: return "strided";
    case PATTERN_SA_RV:   return "sa_rv";
  }
  return "unknown";
}

static const char* default_core_kind_name(void) {
#if defined(__linux__) && defined(__x86_64__)
  return "amd64";
#elif defined(__linux__)
  return "linux";
#else
  return "generic";
#endif
}

static int current_cpu(void) {
#if defined(__APPLE__)
  size_t cpu = 0;
  pthread_cpu_number_np(&cpu);
  return static_cast<int>(cpu);
#elif defined(__linux__)
  return sched_getcpu();
#else
  return -1;
#endif
}

static uint64_t time_chase(CounterSource* counter, volatile int* arr, int iters) {
  volatile int dep = 0;
  for (int i = 0; i < iters; ++i) {
    dep = arr[dep];
  }

  dep = 0;
  uint64_t start = counter->now();
  for (int i = 0; i < iters; ++i) {
    dep = arr[dep];
  }
  uint64_t end = counter->now();
  return end - start;
}

static uint64_t time_sa_rv(CounterSource* counter, volatile int* arr, int iters) {
  volatile int dep = 0;
  for (int i = 0; i < iters; ++i) {
    const int v = arr[dep];
    dep += v < kStride ? v : kStride;
  }

  dep = 0;
  uint64_t start = counter->now();
  for (int i = 0; i < iters; ++i) {
    const int v = arr[dep];
    dep += v < kStride ? v : kStride;
  }
  uint64_t end = counter->now();
  return end - start;
}

static void run(CounterSource* counter, enum AccessPattern pattern,
                const char* core_kind, bool write) {
  const size_t array_size = kArraySizeBytes / sizeof(int);
  int* arr = new int[array_size];

  switch (pattern) {
    case PATTERN_RANDOM:  init_random_array(arr, array_size); break;
    case PATTERN_STRIDED: init_strided_array(arr, array_size); break;
    case PATTERN_SA_RV:   init_sa_rv_array(arr, array_size); break;
  }

  uint64_t* samples = new uint64_t[kReps];

  for (int iters = kMinIters; iters <= kMaxIters; iters += kIterStep) {
    int cpu = current_cpu();
    for (int r = 0; r < kReps; ++r) {
      if (pattern == PATTERN_SA_RV) {
        samples[r] = time_sa_rv(counter, arr, iters);
      } else {
        samples[r] = time_chase(counter, arr, iters);
      }
    }
    std::sort(samples, samples + kReps);
    const uint64_t median_s = samples[kReps / 2];
    if (write) {
      printf("%s,%s,%d,%d,%llu,%s\n",
             access_pattern_name(pattern),
             core_kind,
             cpu,
             iters,
             (unsigned long long)median_s,
             counter->unit());
      fflush(stdout);
    }
  }

  delete[] samples;
  delete[] arr;
}

static void run_suite(CounterSource* counter, const char* core_kind) {
  run(counter, PATTERN_SA_RV,   core_kind, false);
  run(counter, PATTERN_SA_RV,   core_kind, true);
  run(counter, PATTERN_STRIDED, core_kind, false);
  run(counter, PATTERN_STRIDED, core_kind, true);
  run(counter, PATTERN_RANDOM,  core_kind, false);
  run(counter, PATTERN_RANDOM,  core_kind, true);
}

int main(void) {
  CounterSource counter;
  const bool have_cycles = counter.setup();
  fprintf(stderr, "timing unit: %s\n", counter.unit());
  if (!have_cycles) {
    fprintf(stderr, "cycle counter unavailable; falling back to CLOCK_MONOTONIC\n");
  }
  printf("pattern,core_kind,cpu,iters,median,unit\n");

#if defined(__APPLE__)
  if (pthread_set_qos_class_self_np(QOS_CLASS_BACKGROUND, 0) != 0) {
    fprintf(stderr, "failed to set qos class\n");
    return EXIT_FAILURE;
  }
  run_suite(&counter, "ecore");

  if (pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0) != 0) {
    fprintf(stderr, "failed to set qos class\n");
    return EXIT_FAILURE;
  }
  run_suite(&counter, "pcore");
#else
  run_suite(&counter, default_core_kind_name());
#endif
  return 0;
}

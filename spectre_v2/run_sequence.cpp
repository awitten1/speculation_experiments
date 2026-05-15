#include "run_sequence.h"
#include <cstdint>

#ifndef N 
#define N 73
#endif
__attribute__((noinline))
void run_sequence(FuncPtr *funcs, void *buf) {
    for (int i = 0; i < ARRAY_SIZE; ++i) {
        if (i == ARRAY_SIZE - 1) {
            volatile uint64_t dummy = (uint64_t)buf;

            #pragma unroll(0)
            for (int k = 0; k < N; ++k) {
                dummy = dummy * 1664525u + 1013904223u;
            }
        }
	funcs[i](buf);
    }
}

#include "run_sequence.h"

__attribute__((noinline))
void run_sequence(FuncPtr *funcs, void *buf) {
    for (int i = 0; i < ARRAY_SIZE; ++i) {
        funcs[i](buf);
    }
}

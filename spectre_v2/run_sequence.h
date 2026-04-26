#ifndef RUN_SEQUENCE_H
#define RUN_SEQUENCE_H

#ifndef ARRAY_SIZE
#define ARRAY_SIZE 32
#endif

using FuncPtr = int(*)(void*);

void run_sequence(FuncPtr *funcs, void *buf);

#endif

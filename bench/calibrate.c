#include "../common/probe.h"

int main(void) {
    int t = specexp_calibrate_threshold();
    printf("%d\n", t);
    return 0;
}

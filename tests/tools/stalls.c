// Stall probe: spins on one CPU reading CLOCK_MONOTONIC and prints every gap
// longer than a threshold. A loop that never sleeps can only be held up by
// something outside it (interrupts, the hypervisor pausing the VM), so gaps
// seen at the same moment on several CPUs mean the whole machine stopped.
//
//     stalls SECS [LABEL] [THRESHOLD_MS]      (pin it with taskset)
//
// Output, one line per gap: LABEL START_SECONDS LENGTH_MS. START_SECONDS is on
// CLOCK_MONOTONIC, the clock Python's time.perf_counter() uses on Linux, so it
// lines up with timestamps taken there.
//
// Build: cc -O2 -o stalls stalls.c

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s SECS [LABEL] [THRESHOLD_MS]\n", argv[0]);
        return 2;
    }
    const char *label = argc > 2 ? argv[2] : "stall";
    double threshold = (argc > 3 ? atof(argv[3]) : 5.0) / 1e3;
    double end = now() + atof(argv[1]);
    double prev = now();
    setvbuf(stdout, NULL, _IOLBF, 0);
    while (prev < end) {
        double t = now();
        if (t - prev > threshold)
            printf("%s %.6f %.3f\n", label, prev, (t - prev) * 1e3);
        prev = t;
    }
    return 0;
}

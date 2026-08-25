// Phase-0 spike: prove a minimal SanitizerCoverage instrumented build works on
// a pinned nightly with the cargo-fuzz-derived flag set. Written to a temp dir
// and compiled via `rustc +<nightly>` directly, then executed.
//
// This file is NOT part of the crate. It lives in .phase0/spikes/.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// --- minimal sancov runtime (inline 8-bit counters + trace-cmp) ---
static uint8_t *g_counters = 0;
static size_t g_counters_len = 0;

__attribute__((no_sanitize("coverage")))
void __sanitizer_cov_8bit_counters_init(uint8_t *start, uint8_t *stop) {
    g_counters = start;
    g_counters_len = (size_t)(stop - start);
    fprintf(stderr, "[runtime] counters registered: %zu bytes\n", g_counters_len);
}

// Comparison callbacks just count invocations so the spike can prove they fire.
static volatile uint64_t g_cmp4_calls = 0;
__attribute__((no_sanitize("coverage")))
void __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b) {
    (void)a; (void)b; g_cmp4_calls++;
}

static volatile uint64_t g_constcmp4_calls = 0;
__attribute__((no_sanitize("coverage")))
void __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b) {
    (void)a; (void)b; g_constcmp4_calls++;
}

// --- target code with a magic-value gate ---
static uint32_t nonzero_counter_count(void) {
    uint32_t n = 0;
    for (size_t i = 0; i < g_counters_len; i++) {
        if (g_counters[i] != 0) n++;
    }
    return n;
}

__attribute__((noinline))
static int magic_gate(uint32_t x) {
    if (x == 0xDEADBEEF) {          // const cmp: traced by trace_const_cmp4
        return 1;
    }
    if (x > 1000 && x < 2000) {     // range cmp: traced by trace_cmp4
        return 2;
    }
    return 0;
}

int main(int argc, char **argv) {
    uint32_t v = argc > 1 ? (uint32_t)strtoul(argv[1], 0, 0) : 0;
    fprintf(stderr, "[spike] counters before exec: %u\n", nonzero_counter_count());
    int r = magic_gate(v);
    fprintf(stderr, "[spike] magic_gate(%u) = %d\n", v, r);
    fprintf(stderr, "[spike] nonzero counters after exec: %u\n", nonzero_counter_count());
    fprintf(stderr, "[spike] cmp4 calls: %llu  constcmp4 calls: %llu\n",
            (unsigned long long)g_cmp4_calls, (unsigned long long)g_constcmp4_calls);
    return 0;
}

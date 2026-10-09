/* DETERMINISTIC UNIT TEST ONLY: fake getrandom, never link into a service.
 * Build in an isolated directory: cc -std=c11 -Wall -Wextra -Werror
 *   /path/to/scripts/security_rng_boundary_test.c -lm -o rng_boundary_test
 * Exit 1 means one or more assertions failed (including float upper bound).
 * No real entropy, keys, network, or production writes are used.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <float.h>
#include <sys/random.h>

static unsigned char stream[8192];
static size_t stream_len, stream_pos, chunk_size;
static unsigned calls;
static int interrupt_once, fail_errno, return_zero;

static ssize_t test_getrandom(void *buf, size_t n, unsigned int flags) {
    ++calls;
    if (flags != 0) { errno = EINVAL; return -1; }
    if (interrupt_once) { interrupt_once = 0; errno = EINTR; return -1; }
    if (fail_errno) { errno = fail_errno; return -1; }
    if (return_zero) return 0;
    if (stream_pos == stream_len) { errno = EIO; return -1; }
    if (n > stream_len - stream_pos) n = stream_len - stream_pos;
    if (chunk_size && n > chunk_size) n = chunk_size;
    memcpy(buf, stream + stream_pos, n);
    stream_pos += n;
    return (ssize_t)n;
}

#define getrandom test_getrandom
#include "../otp_rng.h"
#undef getrandom

static unsigned checks, failures;
static void reset(const void *data, size_t len) {
    memset(stream, 0, sizeof(stream));
    if (len) memcpy(stream, data, len);
    stream_len = len; stream_pos = 0; chunk_size = 0; calls = 0;
    interrupt_once = 0; fail_errno = 0; return_zero = 0;
}
static void check(const char *name, long long actual, long long expected) {
    int pass = actual == expected;
    ++checks; failures += !pass;
    printf("{\"case\":\"%s\",\"actual\":%lld,\"expected\":%lld,\"pass\":%s}\n",
           name, actual, expected, pass ? "true" : "false");
}
static void float_case(const char *name, uint32_t word, float expected) {
    float out = 99.0f;
    reset(&word, sizeof(word));
    int rc = otp_fill_uniform(&out, 1, 0.5f);
    check("float_fill_return", rc, 0);
    ++checks;
    int pass = out == expected;
    failures += !pass;
    printf("{\"case\":\"%s\",\"actual\":%.9g,\"expected\":%.9g,\"pass\":%s}\n",
           name, (double)out, (double)expected, pass ? "true" : "false");
    ++checks;
    pass = out >= -0.5f && out < 0.5f;
    failures += !pass;
    printf("{\"case\":\"%s_half_open_range\",\"actual\":%.9g,"
           "\"expected\":\"-0.5 <= value < 0.5\",\"pass\":%s}\n",
           name, (double)out, pass ? "true" : "false");
}
static void mod_case(uint16_t q, const char *label) {
    const uint64_t limit = ((UINT64_C(1) << 32) / q) * q;
    uint32_t words[256] = {0};
    uint16_t out[6] = {0};
    char name[96];
    /* Rejected words are followed by distinctive accepted residues. */
    words[0] = (uint32_t)(limit - 1);
    words[1] = (uint32_t)limit;
    words[2] = UINT32_MAX;
    words[3] = 0; words[4] = q - 1; words[5] = q; words[6] = q + 1;
    words[7] = 7;
    const uint16_t expected[6] = {(uint16_t)(q - 1), 0, (uint16_t)(q - 1), 0, 1, 7};
    reset(words, sizeof(words));
    snprintf(name, sizeof(name), "%s_return", label);
    check(name, otp_fill_mod_u16(out, 6, q), 0);
    for (unsigned i = 0; i < 6; ++i) {
        snprintf(name, sizeof(name), "%s_residue_%u", label, i);
        check(name, out[i], expected[i]);
    }
    snprintf(name, sizeof(name), "%s_draw_calls", label);
    check(name, calls, 1);
    printf("{\"case\":\"%s_boundary_inputs\",\"q\":%u,\"limit\":%llu,"
           "\"accepted_last\":%u,\"rejected_first\":%u,\"rejected_max\":%u}\n",
           label, (unsigned)q, (unsigned long long)limit, words[0], words[1], words[2]);
}
int main(void) {
    puts("{\"test_only\":true,\"entropy\":\"deterministic getrandom stub; NOT a randomness quality test\"}");
    unsigned char input[9] = {0,1,2,3,4,5,6,7,8}, out[9] = {0};
    reset(input, sizeof(input)); interrupt_once = 1; chunk_size = 2;
    check("eintr_and_short_reads_return", otp_random_bytes(out, sizeof(out)), 0);
    check("eintr_and_short_reads_exact_bytes", memcmp(out, input, sizeof(out)), 0);
    check("eintr_and_short_reads_call_count", calls, 6);
    reset(NULL, 0); fail_errno = EIO;
    check("permanent_error_return", otp_random_bytes(out, sizeof(out)), -1);
    check("permanent_error_no_retry", calls, 1);
    reset(NULL, 0); return_zero = 1;
    check("zero_read_return", otp_random_bytes(out, sizeof(out)), -1);
    check("zero_read_no_retry", calls, 1);
    reset(NULL, 0);
    check("empty_request_return", otp_random_bytes(out, 0), 0);
    check("empty_request_no_rng", calls, 0);
    float_case("float_zero_word", 0, -0.5f);
    float_case("float_midpoint_word", UINT32_C(2147483648), 0.0f);
    float_case("float_uint32_max_word", UINT32_MAX, 0.5f - 0x1p-24f);
    float_case("float_low_bits_same_grid", 255, -0.5f);
    float_case("float_first_grid_step", 256, -0.5f + 0x1p-24f);
    float_case("float_below_midpoint", UINT32_C(2147483647), -0x1p-24f);
    float_case("float_top_grid_start", UINT32_MAX - 255, 0.5f - 0x1p-24f);
    const float scales[] = {FLT_MIN, FLT_MAX, 0x1p-149f, 0.1f, 1.0f};
    for (unsigned i = 0; i < sizeof(scales) / sizeof(scales[0]); ++i) {
        uint32_t edge = UINT32_MAX;
        float value = 0;
        reset(&edge, sizeof(edge));
        check("positive_finite_scale_return", otp_fill_uniform(&value, 1, scales[i]), 0);
        check("positive_finite_scale_half_open", value >= -scales[i] && value < scales[i], 1);
    }
    mod_case(32749, "q0_32749"); mod_case(32719, "q1_32719");
    uint16_t residues[4] = {99,99,99,99};
    reset(NULL, 0);
    check("q_zero_rejected", otp_fill_mod_u16(residues, 4, 0), -1);
    check("q_zero_no_rng", calls, 0);
    uint32_t words[256];
    for (unsigned i = 0; i < 256; ++i) words[i] = UINT32_MAX;
    reset(words, sizeof(words));
    check("q_one_return", otp_fill_mod_u16(residues, 4, 1), 0);
    for (unsigned i = 0; i < 4; ++i) check("q_one_residue", residues[i], 0);
    reset(NULL, 0); fail_errno = EIO;
    float f = 99.0f;
    check("float_rng_error_propagated", otp_fill_uniform(&f, 1, 0.5f), -1);
    check("mod_rng_error_propagated", otp_fill_mod_u16(residues, 1, 32749), -1);
    uint32_t partial = UINT32_MAX;
    reset(&partial, sizeof(partial));
    float partial_out[2] = {99, 99};
    check("float_partial_read_error", otp_fill_uniform(partial_out, 2, 0.5f), -1);
    check("float_partial_read_no_output", partial_out[0] == 99 && partial_out[1] == 99, 1);
    reset(&partial, sizeof(partial));
    residues[0] = 99;
    check("mod_partial_read_error", otp_fill_mod_u16(residues, 1, 32749), -1);
    check("mod_partial_read_no_output", residues[0], 99);
    unsigned char guarded[34]; memset(guarded, 0xa5, sizeof(guarded));
    otp_secure_zero(guarded + 1, 32);
    unsigned nonzero = 0;
    for (unsigned i = 1; i <= 32; ++i) nonzero += guarded[i] != 0;
    check("secure_zero_nonzero_bytes", nonzero, 0);
    check("secure_zero_left_guard", guarded[0], 0xa5);
    check("secure_zero_right_guard", guarded[33], 0xa5);
    otp_secure_zero(guarded, 0);
    check("secure_zero_empty_preserves_guard", guarded[0], 0xa5);
    puts("{\"scope_note\":\"Zeroization checks cover explicit helper only, not internal stack lifetime, optimizer forensics, device or crash-path erasure.\"}");
    printf("{\"summary\":true,\"checks\":%u,\"passed\":%u,\"failed\":%u}\n",
           checks, checks - failures, failures);
    return failures ? 1 : 0;
}

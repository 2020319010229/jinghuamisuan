/* FEC-08 fault injection: does the密态 linear path abort on error, or does it
 * silently fall back?
 *
 * Runs as an independent process against the real W8A8 weights. The production
 * engine is never touched: every case either fails before any device access, or
 * only rewrites a copy of one weight row on the device and restores it right
 * after. No kernel is launched with an invalid pointer, because the NPUs are
 * shared with the live service.
 *
 * Cases
 *   1 shape_K_not_mult32     illegal activation width      expect ABORT
 *   2 shape_N_not_mult16     illegal output width          expect ABORT
 *   3 unsupported_split      N0<N with no second host span expect ABORT
 *   4 device_corrupt_M1      device weight != host weight, single row
 *   5 device_corrupt_M4      same corruption, 4-row batch
 *   6 csprng_failure         getrandom() fails (LD_PRELOAD) expect ABORT
 *
 * Cases 4 and 5 simulate an accelerator that returns wrong results without
 * reporting an error: the device copy of one output channel is flipped while
 * the trusted host copy stays intact.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>
#include "st35.h"
#include "q8_ops.h"

#define PREFIX "model.language_model.layers.3.self_attn.q_proj"
#define ARM_FILE "/tmp/otp_fault_arm"

static void ref_w8a8(const float *x, int M, int K, const int8_t *w,
                     const float *wscale, int N, float *out) {
    int8_t *xq = (int8_t *)malloc((size_t)M * K);
    float *xs = (float *)malloc(sizeof(float) * M);
    q8_quant_rows(x, M, K, xq, xs);
    for (int m = 0; m < M; m++)
        for (int n = 0; n < N; n++) {
            int32_t acc = 0;
            const int8_t *xr = xq + (size_t)m * K;
            const int8_t *wr = w + (size_t)n * K;
            for (int k = 0; k < K; k++) acc += (int32_t)xr[k] * (int32_t)wr[k];
            out[(size_t)m * N + n] = (float)acc * xs[m] * wscale[n];
        }
    free(xq); free(xs);
}

/* Largest |a-b| over the output channels that the corruption touches (n=0). */
static double col0_maxdiff(const float *a, const float *b, int M, int N) {
    double d = 0;
    for (int m = 0; m < M; m++) {
        double v = fabs((double)a[(size_t)m * N] - (double)b[(size_t)m * N]);
        if (v > d) d = v;
    }
    return d;
}

static void fill_x(float *x, int M, int K) {
    for (int m = 0; m < M; m++)
        for (int k = 0; k < K; k++)
            x[(size_t)m * K + k] = sinf((m * 7919 + k) * 0.0011f) * 0.5f;
}

static int n_pass = 0, n_fail = 0;
static char jbuf[8192];
static size_t jlen = 0;

static void emit(const char *name, int passed, const char *expected,
                 const char *observed) {
    jlen += (size_t)snprintf(jbuf + jlen, sizeof(jbuf) - jlen,
        "%s\n    {\"case\": \"%s\", \"passed\": %s, \"expected\": \"%s\", \"observed\": \"%s\"}",
        jlen ? "," : "", name, passed ? "true" : "false", expected, observed);
    if (passed) n_pass++; else n_fail++;
    fprintf(stderr, "[case] %-24s %s  %s\n", name, passed ? "PASS" : "FAIL", observed);
}

int main(int argc, char **argv) {
    const char *dir = (argc > 1) ? argv[1] : "/data/Qwen3.5-35B-A3B-w8a8-mtp";
    char obs[512];
    unlink(ARM_FILE);

    S35File f;
    if (s35_open(&f, dir) != 0) { fprintf(stderr, "open model failed\n"); return 2; }
    if (q8_init(0) != 0) { fprintf(stderr, "q8_init failed\n"); s35_close(&f); return 2; }

    Q8Weight w;
    if (q8_load_weight(&w, &f, PREFIX) != 0) {
        fprintf(stderr, "load weight failed\n"); q8_fini(); s35_close(&f); return 2;
    }
    const int N = (int)w.out_dim, K = (int)w.in_dim;
    fprintf(stderr, "[env] weight %s N=%d K=%d\n", PREFIX, N, K);

    const int MB = 4;
    float *x = (float *)malloc(sizeof(float) * (size_t)MB * K);
    float *out = (float *)malloc(sizeof(float) * (size_t)MB * N);
    float *ref = (float *)malloc(sizeof(float) * (size_t)MB * N);
    fill_x(x, MB, K);
    ref_w8a8(x, MB, K, w.host_w, w.host_scale, N, ref);

    /* ---- baseline: clean path must match the CPU reference ---- */
    int rc = q8_linear_otp_rns(x, 1, K, &w, N, out);
    double d1 = col0_maxdiff(out, ref, 1, N);
    snprintf(obs, sizeof(obs), "rc=%d col0_maxdiff=%.6g", rc, d1);
    emit("baseline_M1", rc == 0 && d1 < 1e-2, "rc=0 and matches CPU reference", obs);

    rc = q8_linear_otp_rns(x, MB, K, &w, N, out);
    double d4 = col0_maxdiff(out, ref, MB, N);
    snprintf(obs, sizeof(obs), "rc=%d col0_maxdiff=%.6g", rc, d4);
    emit("baseline_M4", rc == 0 && d4 < 1e-2, "rc=0 and matches CPU reference", obs);

    /* ---- 1/2/3: malformed or unsupported requests must be rejected ---- */
    rc = q8_linear_otp_rns_raw_split(x, 1, K - 1, w.w.dev, w.host_w, N, NULL,
                                     w.host_scale, N, out);
    snprintf(obs, sizeof(obs), "rc=%d", rc);
    emit("shape_K_not_mult32", rc != 0, "abort (rc!=0)", obs);

    rc = q8_linear_otp_rns_raw_split(x, 1, K, w.w.dev, w.host_w, N - 1, NULL,
                                     w.host_scale, N - 1, out);
    snprintf(obs, sizeof(obs), "rc=%d", rc);
    emit("shape_N_not_mult16", rc != 0, "abort (rc!=0)", obs);

    rc = q8_linear_otp_rns_raw_split(x, 1, K, w.w.dev, w.host_w, N / 2, NULL,
                                     w.host_scale, N, out);
    snprintf(obs, sizeof(obs), "rc=%d", rc);
    emit("unsupported_split", rc != 0, "abort (rc!=0)", obs);

    /* ---- 4/5: device returns wrong results without reporting an error ----
     * Flip one output channel of the DEVICE weight; the trusted host copy that
     * drives the CPU correction is left untouched. */
    const size_t chunk = (size_t)K;            /* output channel n=0 */
    int8_t *orig = (int8_t *)malloc(chunk);
    int8_t *bad = (int8_t *)malloc(chunk);
    memcpy(orig, w.host_w, chunk);
    for (size_t i = 0; i < chunk; i++) bad[i] = (int8_t)(orig[i] ^ 0x5A);

    if (qt_upload(&w.w, bad, chunk) != 0) {
        emit("device_corrupt_setup", 0, "device weight rewritten", "upload failed");
    } else {
        rc = q8_linear_otp_rns(x, 1, K, &w, N, out);
        d1 = col0_maxdiff(out, ref, 1, N);
        /* verify is on for M==1: the mismatch should be caught and corrected,
         * so the output still matches the CPU reference. */
        snprintf(obs, sizeof(obs), "rc=%d col0_maxdiff=%.6g (corrected back to CPU value)", rc, d1);
        emit("device_corrupt_M1", rc == 0 && d1 < 1e-2,
             "detected and corrected on trusted CPU", obs);

        rc = q8_linear_otp_rns(x, MB, K, &w, N, out);
        d4 = col0_maxdiff(out, ref, MB, N);
        /* verify is OFF for M>1 by default, so a silent wrong result is the
         * expected observation here. Passing means we reproduced the gap. */
        snprintf(obs, sizeof(obs),
                 "rc=%d col0_maxdiff=%.6g -> wrong result returned as success", rc, d4);
        emit("device_corrupt_M4_silent", rc == 0 && d4 > 1e-2,
             "reproduce: batch path does not cross-check", obs);

        if (qt_upload(&w.w, orig, chunk) != 0)
            fprintf(stderr, "[warn] restoring device weight FAILED\n");
        else
            fprintf(stderr, "[env] device weight restored\n");

        rc = q8_linear_otp_rns(x, MB, K, &w, N, out);
        d4 = col0_maxdiff(out, ref, MB, N);
        snprintf(obs, sizeof(obs), "rc=%d col0_maxdiff=%.6g", rc, d4);
        emit("restore_check_M4", rc == 0 && d4 < 1e-2,
             "device weight restored, output matches again", obs);
    }

    /* ---- 6: CSPRNG failure must abort, never compute without a mask ---- */
    int fd = open(ARM_FILE, O_CREAT | O_WRONLY, 0600);
    if (fd >= 0) close(fd);
    rc = q8_linear_otp_rns(x, 1, K, &w, N, out);
    unlink(ARM_FILE);
    snprintf(obs, sizeof(obs), "rc=%d (getrandom forced to fail)", rc);
    emit("csprng_failure", rc != 0, "abort (rc!=0), no unmasked computation", obs);

    rc = q8_linear_otp_rns(x, 1, K, &w, N, out);
    d1 = col0_maxdiff(out, ref, 1, N);
    snprintf(obs, sizeof(obs), "rc=%d col0_maxdiff=%.6g", rc, d1);
    emit("recover_after_csprng", rc == 0 && d1 < 1e-2,
         "normal operation resumes once the source works", obs);

    printf("{\n  \"pass\": %d,\n  \"fail\": %d,\n  \"cases\": [%s\n  ]\n}\n",
           n_pass, n_fail, jbuf);

    free(orig); free(bad); free(x); free(out); free(ref);
    q8_free_weight(&w); q8_fini(); s35_close(&f);
    return n_fail ? 1 : 0;
}

/*
 * leak_check.c — RSS-stable loop tests for SHA, AES-GCM, RSA, ECDSA.
 *
 * Pass criterion: VmRSS growth < 1 MB across each loop.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "go-src/src/crypto/internal/boring/goboringcrypto.h"

/* ── RSS helper ─────────────────────────────────────────────────────────── */

static long rss_kb(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) { perror("fopen /proc/self/status"); exit(1); }
    long kb = -1;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, " %ld", &kb);
            break;
        }
    }
    fclose(f);
    return kb;
}

/* ── Test ─────────────────────────────────────────────────────────────── */

static int pass_count = 0;
static int fail_count = 0;

#define PASS(name) do { printf("PASS %s\n", (name)); pass_count++; } while (0)
#define FAIL(name, ...) do { \
    printf("FAIL %s: ", (name)); \
    printf(__VA_ARGS__); \
    printf("\n"); \
    fail_count++; \
} while (0)

/* 100k SHA-256 Init → Update → Final cycles */
static void test_sha256_leak(void)
{
    const int N = 100000;
    const long limit_kb = 1024; /* 1 MB */

    long before = rss_kb();
    uint8_t digest[32];

    for (int i = 0; i < N; i++) {
        GO_SHA256_CTX ctx;
        _goboringcrypto_SHA256_Init(&ctx);
        _goboringcrypto_SHA256_Update(&ctx, "hello", 5);
        _goboringcrypto_SHA256_Final(digest, &ctx);
        _goboringcrypto_SHA256_Cleanup(&ctx);
    }
    (void)digest;

    long after = rss_kb();
    long delta = after - before;
    if (delta < limit_kb)
        PASS("sha256_leak");
    else
        FAIL("sha256_leak", "RSS grew %ld kB over %d iterations (limit %ld kB)",
             delta, N, limit_kb);
}

/* 100k AES-128-GCM init → seal → open → cleanup cycles */
static void test_aesgcm_leak(void)
{
    const int N = 100000;
    const long limit_kb = 1024;

    static const uint8_t key[16] = {0};
    static const uint8_t nonce[12] = {0};
    static const uint8_t plaintext[16] = "hello world!!!!";
    uint8_t sealed[32], opened[16];
    size_t sealed_len, opened_len;

    const GO_EVP_AEAD *aead = _goboringcrypto_EVP_aead_aes_128_gcm();
    long before = rss_kb();

    for (int i = 0; i < N; i++) {
        GO_EVP_AEAD_CTX ctx;
        _goboringcrypto_EVP_AEAD_CTX_zero(&ctx);
        _goboringcrypto_EVP_AEAD_CTX_init(&ctx, aead, key, 16, 0, NULL);

        sealed_len = sizeof(sealed);
        _goboringcrypto_EVP_AEAD_CTX_seal(&ctx,
            sealed, &sealed_len, sizeof(sealed),
            nonce, 12, plaintext, 16, NULL, 0);

        opened_len = sizeof(opened);
        _goboringcrypto_EVP_AEAD_CTX_open(&ctx,
            opened, &opened_len, sizeof(opened),
            nonce, 12, sealed, sealed_len, NULL, 0);

        _goboringcrypto_EVP_AEAD_CTX_cleanup(&ctx);
    }
    (void)sealed_len; (void)opened_len;

    long after = rss_kb();
    long delta = after - before;
    if (delta < limit_kb)
        PASS("aesgcm_leak");
    else
        FAIL("aesgcm_leak", "RSS grew %ld kB over %d iterations (limit %ld kB)",
             delta, N, limit_kb);
}

/* 1k RSA-2048 generate → sign → verify → free cycles */
static void test_rsa_leak(void)
{
    const int N = 1000;
    const long limit_kb = 1024;

    /* public exponent 65537 */
    static const uint8_t e65537[3] = {0x01, 0x00, 0x01};

    uint8_t digest[32];
    memset(digest, 0xab, sizeof(digest));

    long before = rss_kb();

    for (int i = 0; i < N; i++) {
        GO_RSA *rsa = _goboringcrypto_RSA_new();
        GO_BIGNUM *e = _goboringcrypto_BN_bin2bn(e65537, sizeof(e65537), NULL);

        if (_goboringcrypto_RSA_generate_key_ex(rsa, 2048, e, NULL) != 1) {
            _goboringcrypto_BN_free(e);
            _goboringcrypto_RSA_free(rsa);
            FAIL("rsa_leak", "RSA_generate_key_ex failed at iter %d", i);
            return;
        }
        _goboringcrypto_BN_free(e);

        uint8_t sig[256];
        unsigned int siglen = sizeof(sig);
        if (_goboringcrypto_RSA_sign(GO_NID_sha256, digest, sizeof(digest),
                                     sig, &siglen, rsa) != 1) {
            _goboringcrypto_RSA_free(rsa);
            FAIL("rsa_leak", "RSA_sign failed at iter %d", i);
            return;
        }

        if (_goboringcrypto_RSA_verify(GO_NID_sha256, digest, sizeof(digest),
                                       sig, siglen, rsa) != 1) {
            _goboringcrypto_RSA_free(rsa);
            FAIL("rsa_leak", "RSA_verify failed at iter %d", i);
            return;
        }

        _goboringcrypto_RSA_free(rsa);
    }

    long after = rss_kb();
    long delta = after - before;
    if (delta < limit_kb)
        PASS("rsa_leak");
    else
        FAIL("rsa_leak", "RSS grew %ld kB over %d iterations (limit %ld kB)",
             delta, N, limit_kb);
}

/* 10k ECDSA P-256 generate → sign → verify → free cycles */
static void test_ecdsa_leak(void)
{
    const int N = 10000;
    const long limit_kb = 1024;

    uint8_t digest[32];
    memset(digest, 0xcd, sizeof(digest));

    long before = rss_kb();

    for (int i = 0; i < N; i++) {
        GO_EC_KEY *key = _goboringcrypto_EC_KEY_new_by_curve_name(
            GO_NID_X9_62_prime256v1);
        if (!key) {
            FAIL("ecdsa_leak", "EC_KEY_new_by_curve_name failed at iter %d", i);
            return;
        }

        if (_goboringcrypto_EC_KEY_generate_key_fips(key) != 1) {
            _goboringcrypto_EC_KEY_free(key);
            FAIL("ecdsa_leak", "EC_KEY_generate_key_fips failed at iter %d", i);
            return;
        }

        size_t siglen = _goboringcrypto_ECDSA_size(key);
        uint8_t *sig = malloc(siglen);
        unsigned int used = (unsigned int)siglen;

        if (_goboringcrypto_ECDSA_sign(0, digest, sizeof(digest),
                                       sig, &used, key) != 1) {
            free(sig);
            _goboringcrypto_EC_KEY_free(key);
            FAIL("ecdsa_leak", "ECDSA_sign failed at iter %d", i);
            return;
        }

        if (_goboringcrypto_ECDSA_verify(0, digest, sizeof(digest),
                                         sig, used, key) != 1) {
            free(sig);
            _goboringcrypto_EC_KEY_free(key);
            FAIL("ecdsa_leak", "ECDSA_verify failed at iter %d", i);
            return;
        }

        free(sig);
        _goboringcrypto_EC_KEY_free(key);
    }

    long after = rss_kb();
    long delta = after - before;
    if (delta < limit_kb)
        PASS("ecdsa_leak");
    else
        FAIL("ecdsa_leak", "RSS grew %ld kB over %d iterations (limit %ld kB)",
             delta, N, limit_kb);
}

/* ── main ──────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("=== Leak checks: RSS-stable loops ===\n");
    test_sha256_leak();
    test_aesgcm_leak();
    test_rsa_leak();
    test_ecdsa_leak();

    printf("\n%d/%d tests passed.\n", pass_count, pass_count + fail_count);
    return fail_count == 0 ? 0 : 1;
}

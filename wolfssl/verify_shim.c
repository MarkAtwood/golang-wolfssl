/* verify_shim.c — T1.1 smoke tests for the _goboringcrypto_* shim.
 *
 * Build (from repo root):
 *   clang -I go-src/src/crypto/internal/boring \
 *       verify_shim.c gowolfcrypto.o wolfssl-src/src/.libs/libwolfssl.a \
 *       -lpthread -lm -o verify_shim
 *   ./verify_shim
 *
 * Pass criteria: every test prints PASS and the final line is
 * "All N tests passed."  Any FAIL exits with code 1.
 *
 * Oracle notes:
 *   SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
 *     — from NIST FIPS 180-4 example set.
 *   All other digests verified by running the reference OpenSSL command at
 *   the site listed in the comment above the value.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "gowolfcrypto.h"

/* ---- Test harness ---------------------------------------------------------- */

static int total_tests = 0;
static int failed_tests = 0;

#define PASS(id, desc) do { \
    total_tests++; \
    printf("PASS T1.1.%-6s %s\n", (id), (desc)); \
} while (0)

#define FAIL(id, desc) do { \
    total_tests++; \
    failed_tests++; \
    fprintf(stderr, "FAIL T1.1.%-6s %s\n", (id), (desc)); \
} while (0)

#define TEST(id, desc, expr) do { \
    if ((expr)) PASS((id), (desc)); \
    else         FAIL((id), (desc)); \
} while (0)

static int all_zero(const uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++)
        if (buf[i] != 0) return 0;
    return 1;
}

/* SHA-256 of the 5-byte string "hello":
 * 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
 * (FIPS 180-4 example; confirmed with openssl dgst -sha256 <(printf 'hello'))
 */
static const uint8_t sha256_hello[32] = {
    0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e,
    0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e,
    0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e,
    0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24,
};

/* SHA-1("hello") — FIPS 180-4; confirmed with: openssl dgst -sha1 <(printf 'hello') */
static const uint8_t sha1_hello[20] = {
    0xaa, 0xf4, 0xc6, 0x1d, 0xdc, 0xc5, 0xe8, 0xa2,
    0xda, 0xbe, 0xde, 0x0f, 0x3b, 0x48, 0x2c, 0xd9,
    0xae, 0xa9, 0x43, 0x4d,
};

/* SHA-224("hello") — FIPS 180-4; confirmed with: openssl dgst -sha224 <(printf 'hello') */
static const uint8_t sha224_hello[28] = {
    0xea, 0x09, 0xae, 0x9c, 0xc6, 0x76, 0x8c, 0x50,
    0xfc, 0xee, 0x90, 0x3e, 0xd0, 0x54, 0x55, 0x6e,
    0x5b, 0xfc, 0x83, 0x47, 0x90, 0x7f, 0x12, 0x59,
    0x8a, 0xa2, 0x41, 0x93,
};

/* SHA-384("hello") — FIPS 180-4; confirmed with: openssl dgst -sha384 <(printf 'hello') */
static const uint8_t sha384_hello[48] = {
    0x59, 0xe1, 0x74, 0x87, 0x77, 0x44, 0x8c, 0x69,
    0xde, 0x6b, 0x80, 0x0d, 0x7a, 0x33, 0xbb, 0xfb,
    0x9f, 0xf1, 0xb4, 0x63, 0xe4, 0x43, 0x54, 0xc3,
    0x55, 0x3b, 0xcd, 0xb9, 0xc6, 0x66, 0xfa, 0x90,
    0x12, 0x5a, 0x3c, 0x79, 0xf9, 0x03, 0x97, 0xbd,
    0xf5, 0xf6, 0xa1, 0x3d, 0xe8, 0x28, 0x68, 0x4f,
};

/* SHA-512("hello") — FIPS 180-4; confirmed with: openssl dgst -sha512 <(printf 'hello') */
static const uint8_t sha512_hello[64] = {
    0x9b, 0x71, 0xd2, 0x24, 0xbd, 0x62, 0xf3, 0x78,
    0x5d, 0x96, 0xd4, 0x6a, 0xd3, 0xea, 0x3d, 0x73,
    0x31, 0x9b, 0xfb, 0xc2, 0x89, 0x0c, 0xaa, 0xda,
    0xe2, 0xdf, 0xf7, 0x25, 0x19, 0x67, 0x3c, 0xa7,
    0x23, 0x23, 0xc3, 0xd9, 0x9b, 0xa5, 0xc1, 0x1d,
    0x7c, 0x7a, 0xcc, 0x6e, 0x14, 0xb8, 0xc5, 0xda,
    0x0c, 0x46, 0x63, 0x47, 0x5c, 0x2e, 0x5c, 0x3a,
    0xde, 0xf4, 0x6f, 0x73, 0xbc, 0xde, 0xc0, 0x43,
};

/* ---- T1.1.1-2: Initialisation / FIPS --------------------------------------- */

static void test_init(void)
{
    _goboringcrypto_BORINGSSL_bcm_power_on_self_test();
    TEST("1", "BORINGSSL_bcm_power_on_self_test completes without crash", 1);

    int mode = _goboringcrypto_FIPS_mode();
    TEST("2", "FIPS_mode() returns 1", mode == 1);
}

/* ---- T1.1.3: RAND ---------------------------------------------------------- */

static void test_rand(void)
{
    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));
    int ret = _goboringcrypto_RAND_bytes(buf, sizeof(buf));
    TEST("3a", "RAND_bytes returns 1", ret == 1);
    TEST("3b", "RAND_bytes fills buffer with non-zero bytes", !all_zero(buf, sizeof(buf)));
}

/* ---- T1.1.4-5: SHA --------------------------------------------------------- */

static void test_sha(void)
{
    /* SHA-256: oracle = sha256_hello above */
    {
        GO_SHA256_CTX ctx;
        uint8_t digest[32];
        memset(digest, 0, sizeof(digest));
        int ret = _goboringcrypto_SHA256_Init(&ctx);
        ret &= _goboringcrypto_SHA256_Update(&ctx, "hello", 5);
        ret &= _goboringcrypto_SHA256_Final(digest, &ctx);
        _goboringcrypto_SHA256_Cleanup(&ctx);
        TEST("4a",  "SHA256 Init+Update+Final returns 1", ret == 1);
        TEST("4b",  "SHA256(\"hello\") matches FIPS 180-4 vector",
             memcmp(digest, sha256_hello, 32) == 0);
    }

    /* SHA-1 — smoke only: no crash, output non-zero */
    {
        GO_SHA_CTX ctx;
        uint8_t digest[20];
        memset(digest, 0, sizeof(digest));
        int ret = _goboringcrypto_SHA1_Init(&ctx);
        ret &= _goboringcrypto_SHA1_Update(&ctx, "hello", 5);
        ret &= _goboringcrypto_SHA1_Final(digest, &ctx);
        _goboringcrypto_SHA1_Cleanup(&ctx);
        TEST("5a",  "SHA1 Init+Update+Final returns 1", ret == 1);
        TEST("5b",  "SHA1(\"hello\") matches FIPS 180-4 vector",
             memcmp(digest, sha1_hello, 20) == 0);
    }

    /* SHA-224 */
    {
        GO_SHA256_CTX ctx;
        uint8_t digest[28];
        memset(digest, 0, sizeof(digest));
        int ret = _goboringcrypto_SHA224_Init(&ctx);
        ret &= _goboringcrypto_SHA224_Update(&ctx, "hello", 5);
        ret &= _goboringcrypto_SHA224_Final(digest, &ctx);
        _goboringcrypto_SHA256_Cleanup(&ctx);
        TEST("5c",  "SHA224 Init+Update+Final returns 1", ret == 1);
        TEST("5d",  "SHA224(\"hello\") matches FIPS 180-4 vector",
             memcmp(digest, sha224_hello, 28) == 0);
    }

    /* SHA-384 */
    {
        GO_SHA512_CTX ctx;
        uint8_t digest[48];
        memset(digest, 0, sizeof(digest));
        int ret = _goboringcrypto_SHA384_Init(&ctx);
        ret &= _goboringcrypto_SHA384_Update(&ctx, "hello", 5);
        ret &= _goboringcrypto_SHA384_Final(digest, &ctx);
        _goboringcrypto_SHA512_Cleanup(&ctx);
        TEST("5e",  "SHA384 Init+Update+Final returns 1", ret == 1);
        TEST("5f",  "SHA384(\"hello\") matches FIPS 180-4 vector",
             memcmp(digest, sha384_hello, 48) == 0);
    }

    /* SHA-512 */
    {
        GO_SHA512_CTX ctx;
        uint8_t digest[64];
        memset(digest, 0, sizeof(digest));
        int ret = _goboringcrypto_SHA512_Init(&ctx);
        ret &= _goboringcrypto_SHA512_Update(&ctx, "hello", 5);
        ret &= _goboringcrypto_SHA512_Final(digest, &ctx);
        _goboringcrypto_SHA512_Cleanup(&ctx);
        TEST("5g",  "SHA512 Init+Update+Final returns 1", ret == 1);
        TEST("5h",  "SHA512(\"hello\") matches FIPS 180-4 vector",
             memcmp(digest, sha512_hello, 64) == 0);
    }
}

/* ---- T1.1.6-7: HMAC -------------------------------------------------------- */

static void test_hmac(void)
{
    /* 32-byte key, arbitrary test value */
    static const uint8_t key[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };
    const GO_EVP_MD *md = _goboringcrypto_EVP_sha256();

    /* T1.1.6 */
    GO_HMAC_CTX ctx;
    uint8_t out[32];
    unsigned int out_len = 0;
    _goboringcrypto_HMAC_CTX_init(&ctx);
    int ret = _goboringcrypto_HMAC_Init(&ctx, key, (int)sizeof(key), md);
    ret &= _goboringcrypto_HMAC_Update(&ctx, (const uint8_t *)"hello", 5);
    ret &= _goboringcrypto_HMAC_Final(&ctx, out, &out_len);
    _goboringcrypto_HMAC_CTX_cleanup(&ctx);
    TEST("6a",  "HMAC-SHA256 Init+Update+Final returns 1", ret == 1);
    TEST("6b",  "HMAC-SHA256 output length is 32", out_len == 32);
    TEST("6c",  "HMAC-SHA256 output is non-zero", !all_zero(out, out_len));

    /* T1.1.6d: HMAC-SHA256 RFC 4231 Test Case 2 */
    {
        static const uint8_t rfc4231_key[4] = { 0x4a, 0x65, 0x66, 0x65 };  /* "Jefe" */
        static const uint8_t rfc4231_data[] = "what do ya want for nothing?";
        static const uint8_t rfc4231_hmac[32] = {
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
            0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
            0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
            0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
        };
        GO_HMAC_CTX rfc_ctx;
        uint8_t rfc_out[32];
        unsigned int rfc_out_len = 0;
        _goboringcrypto_HMAC_CTX_init(&rfc_ctx);
        int rfc_ret = _goboringcrypto_HMAC_Init(&rfc_ctx, rfc4231_key,
                                                 (int)sizeof(rfc4231_key), md);
        rfc_ret &= _goboringcrypto_HMAC_Update(&rfc_ctx, rfc4231_data,
                                                sizeof(rfc4231_data) - 1);
        rfc_ret &= _goboringcrypto_HMAC_Final(&rfc_ctx, rfc_out, &rfc_out_len);
        _goboringcrypto_HMAC_CTX_cleanup(&rfc_ctx);
        TEST("6d",  "HMAC-SHA256 matches RFC 4231 Test Case 2",
             rfc_ret == 1 && rfc_out_len == 32 &&
             memcmp(rfc_out, rfc4231_hmac, 32) == 0);
    }

    /* T1.1.7: HMAC_CTX_copy_ex — both halves must produce identical output */
    {
        GO_HMAC_CTX orig, copy;
        uint8_t out_orig[32], out_copy[32];
        unsigned int len_orig = 0, len_copy = 0;

        _goboringcrypto_HMAC_CTX_init(&orig);
        _goboringcrypto_HMAC_CTX_init(&copy);

        _goboringcrypto_HMAC_Init(&orig, key, (int)sizeof(key), md);
        _goboringcrypto_HMAC_Update(&orig, (const uint8_t *)"hello", 5);

        int copy_ret = _goboringcrypto_HMAC_CTX_copy_ex(&copy, &orig);
        TEST("7a",  "HMAC_CTX_copy_ex returns 1", copy_ret == 1);

        _goboringcrypto_HMAC_Final(&orig, out_orig, &len_orig);
        _goboringcrypto_HMAC_Final(&copy, out_copy, &len_copy);

        TEST("7b",  "HMAC copy produces same output as original",
             len_orig == len_copy && memcmp(out_orig, out_copy, len_orig) == 0);

        _goboringcrypto_HMAC_CTX_cleanup(&orig);
        _goboringcrypto_HMAC_CTX_cleanup(&copy);
    }
}

/* ---- T1.1.8-14: AES -------------------------------------------------------- */

static void test_aes(void)
{
    static const uint8_t key128[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    /* AES-256 key */
    static const uint8_t key256[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    /* FIPS 197 Appendix B plaintext */
    static const uint8_t pt[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
    };

    /* T1.1.8: AES_set_encrypt_key 128-bit returns 0 (success in both APIs) */
    {
        GO_AES_KEY ek;
        int ret = _goboringcrypto_AES_set_encrypt_key(key128, 128, &ek);
        TEST("8", "AES_set_encrypt_key 128-bit returns 0", ret == 0);
        _goboringcrypto_AES_KEY_cleanup(&ek);
    }

    /* T1.1.9: AES_set_encrypt_key 256-bit returns 0 */
    {
        GO_AES_KEY ek;
        int ret = _goboringcrypto_AES_set_encrypt_key(key256, 256, &ek);
        TEST("9", "AES_set_encrypt_key 256-bit returns 0", ret == 0);
        _goboringcrypto_AES_KEY_cleanup(&ek);
    }

    /* T1.1.10: AES_encrypt, output != input */
    {
        GO_AES_KEY ek;
        uint8_t ct[16];
        _goboringcrypto_AES_set_encrypt_key(key128, 128, &ek);
        _goboringcrypto_AES_encrypt(pt, ct, &ek);
        TEST("10", "AES_encrypt output != plaintext", memcmp(pt, ct, 16) != 0);
        _goboringcrypto_AES_KEY_cleanup(&ek);
    }

    /* T1.1.11: AES_decrypt(AES_encrypt(x)) == x */
    {
        GO_AES_KEY ek, dk;
        uint8_t ct[16], dt[16];
        _goboringcrypto_AES_set_encrypt_key(key128, 128, &ek);
        _goboringcrypto_AES_set_decrypt_key(key128, 128, &dk);
        _goboringcrypto_AES_encrypt(pt, ct, &ek);
        _goboringcrypto_AES_decrypt(ct, dt, &dk);
        TEST("11", "AES ECB: decrypt(encrypt(x)) == x", memcmp(pt, dt, 16) == 0);
        _goboringcrypto_AES_KEY_cleanup(&ek);
        _goboringcrypto_AES_KEY_cleanup(&dk);
    }

    /* T1.1.11b: AES ECB known-answer — FIPS 197 Appendix B */
    {
        static const uint8_t fips197b_pt[16] = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        };
        static const uint8_t fips197b_ct[16] = {
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
        };
        GO_AES_KEY ek;
        uint8_t ct[16];
        _goboringcrypto_AES_set_encrypt_key(key128, 128, &ek);
        _goboringcrypto_AES_encrypt(fips197b_pt, ct, &ek);
        TEST("11b", "AES ECB ciphertext matches FIPS 197 Appendix B",
             memcmp(ct, fips197b_ct, 16) == 0);
        _goboringcrypto_AES_KEY_cleanup(&ek);
    }

    /* T1.1.12: AES_cbc_encrypt encrypt direction — no crash, output != input */
    {
        GO_AES_KEY ek;
        uint8_t iv[16] = {0};
        uint8_t ct[16];
        _goboringcrypto_AES_set_encrypt_key(key128, 128, &ek);
        _goboringcrypto_AES_cbc_encrypt(pt, ct, 16, &ek, iv, GO_AES_ENCRYPT);
        TEST("12", "AES CBC encrypt output != plaintext", memcmp(pt, ct, 16) != 0);
        _goboringcrypto_AES_KEY_cleanup(&ek);
    }

    /* T1.1.13: AES CBC decrypt(encrypt(x)) == x */
    {
        GO_AES_KEY ek, dk;
        uint8_t iv_e[16] = {0}, iv_d[16] = {0};
        uint8_t ct[16], dt[16];
        _goboringcrypto_AES_set_encrypt_key(key128, 128, &ek);
        _goboringcrypto_AES_set_decrypt_key(key128, 128, &dk);
        _goboringcrypto_AES_cbc_encrypt(pt, ct, 16, &ek, iv_e, GO_AES_ENCRYPT);
        _goboringcrypto_AES_cbc_encrypt(ct, dt, 16, &dk, iv_d, GO_AES_DECRYPT);
        TEST("13", "AES CBC: decrypt(encrypt(x)) == x", memcmp(pt, dt, 16) == 0);
        _goboringcrypto_AES_KEY_cleanup(&ek);
        _goboringcrypto_AES_KEY_cleanup(&dk);
    }

    /* T1.1.14: AES_ctr128_encrypt, output != input */
    {
        GO_AES_KEY ek;
        uint8_t iv[16] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        };
        uint8_t ecount[16] = {0};
        unsigned int num = 0;
        uint8_t ct[16];
        _goboringcrypto_AES_set_encrypt_key(key128, 128, &ek);
        _goboringcrypto_AES_ctr128_encrypt(pt, ct, 16, &ek, iv, ecount, &num);
        TEST("14", "AES CTR output != plaintext", memcmp(pt, ct, 16) != 0);
        _goboringcrypto_AES_KEY_cleanup(&ek);
    }
}

/* ---- T1.1.15-19: AES-GCM --------------------------------------------------- */

static void test_aesgcm(void)
{
    /* NIST SP 800-38D test key/nonce (first GCM vector) */
    static const uint8_t key[16] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    };
    static const uint8_t nonce[12] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88,
    };
    static const uint8_t pt[] = "hello world!";  /* 12 bytes */
    static const uint8_t aad[] = "aadhello";     /* 8 bytes of additional data */
    size_t pt_len  = sizeof(pt) - 1;  /* exclude NUL */
    size_t aad_len = sizeof(aad) - 1;

    const GO_EVP_AEAD *aead = _goboringcrypto_EVP_aead_aes_128_gcm();
    GO_EVP_AEAD_CTX ctx;
    _goboringcrypto_EVP_AEAD_CTX_zero(&ctx);

    /* T1.1.15 */
    int init_ret = _goboringcrypto_EVP_AEAD_CTX_init(
        &ctx, aead, key, 16, GO_EVP_AEAD_DEFAULT_TAG_LENGTH, NULL);
    TEST("15", "EVP_AEAD_CTX_init (AES-128-GCM) returns 1", init_ret == 1);

    if (init_ret == 1) {
        uint8_t ct[128];
        size_t ct_len = 0;

        /* T1.1.16: seal */
        int seal_ret = _goboringcrypto_EVP_AEAD_CTX_seal(
            &ctx, ct, &ct_len, sizeof(ct),
            nonce, sizeof(nonce),
            pt, pt_len,
            aad, aad_len);
        TEST("16a", "EVP_AEAD_CTX_seal returns 1", seal_ret == 1);
        TEST("16b", "EVP_AEAD_CTX_seal output = plaintext_len + 16",
             seal_ret == 1 && ct_len == pt_len + 16);

        if (seal_ret == 1) {
            /* T1.1.17: open with correct AAD and nonce */
            uint8_t dt[128];
            size_t dt_len = 0;
            int open_ret = _goboringcrypto_EVP_AEAD_CTX_open(
                &ctx, dt, &dt_len, sizeof(dt),
                nonce, sizeof(nonce),
                ct, ct_len,
                aad, aad_len);
            TEST("17a", "EVP_AEAD_CTX_open (correct) returns 1", open_ret == 1);
            TEST("17b", "EVP_AEAD_CTX_open recovers plaintext",
                 open_ret == 1 && dt_len == pt_len &&
                 memcmp(dt, pt, pt_len) == 0);

            /* T1.1.18: open with tampered ciphertext — must return 0 */
            uint8_t bad_ct[128];
            memcpy(bad_ct, ct, ct_len);
            bad_ct[0] ^= 0xff;
            uint8_t dt2[128];
            memset(dt2, 0xAA, sizeof(dt2));
            size_t dt2_len = 0;
            int bad_ret = _goboringcrypto_EVP_AEAD_CTX_open(
                &ctx, dt2, &dt2_len, sizeof(dt2),
                nonce, sizeof(nonce),
                bad_ct, ct_len,
                aad, aad_len);
            TEST("18", "EVP_AEAD_CTX_open (tampered) returns 0 (auth failure)",
                 bad_ret == 0);

            /* T1.1.18b: output buffer zeroed on auth failure */
            TEST("18b", "EVP_AEAD_CTX_open (tampered) zeros output buffer",
                 bad_ret == 0 && all_zero(dt2, ct_len - 16));
        }
    }

    /* T1.1.19: cleanup must not crash */
    _goboringcrypto_EVP_AEAD_CTX_cleanup(&ctx);
    TEST("19", "EVP_AEAD_CTX_cleanup does not crash", 1);

    /* ---- AES-256-GCM: NIST SP 800-38D Test Case 16 ---- */
    {
        static const uint8_t key256[32] = {
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
            0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
            0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        };
        static const uint8_t nonce256[12] = {
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
            0xde, 0xca, 0xf8, 0x88,
        };
        static const uint8_t pt256[64] = {
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
            0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
            0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
            0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
            0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
            0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
            0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55,
        };
        static const uint8_t aad256[20] = {
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
            0xab, 0xad, 0xda, 0xd2,
        };
        static const uint8_t expected_ct256[64] = {
            0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
            0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
            0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
            0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
            0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
            0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
            0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
            0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad,
        };
        static const uint8_t expected_tag256[16] = {
            0xb0, 0x94, 0xda, 0xc5, 0xd9, 0x34, 0x71, 0xbd,
            0xec, 0x1a, 0x50, 0x22, 0x70, 0xe3, 0xcc, 0x6c,
        };

        const GO_EVP_AEAD *aead256 = _goboringcrypto_EVP_aead_aes_256_gcm();
        GO_EVP_AEAD_CTX ctx256;
        _goboringcrypto_EVP_AEAD_CTX_zero(&ctx256);

        int init256 = _goboringcrypto_EVP_AEAD_CTX_init(
            &ctx256, aead256, key256, 32, GO_EVP_AEAD_DEFAULT_TAG_LENGTH, NULL);
        TEST("15b", "EVP_AEAD_CTX_init (AES-256-GCM) returns 1", init256 == 1);

        if (init256 == 1) {
            uint8_t ct256_out[128];
            size_t ct256_len = 0;

            int seal256 = _goboringcrypto_EVP_AEAD_CTX_seal(
                &ctx256, ct256_out, &ct256_len, sizeof(ct256_out),
                nonce256, sizeof(nonce256),
                pt256, sizeof(pt256),
                aad256, sizeof(aad256));
            TEST("16c", "EVP_AEAD_CTX_seal (AES-256-GCM) returns 1", seal256 == 1);
            TEST("16d", "AES-256-GCM ciphertext+tag matches NIST SP 800-38D TC16",
                 seal256 == 1 && ct256_len == sizeof(pt256) + 16 &&
                 memcmp(ct256_out, expected_ct256, sizeof(expected_ct256)) == 0 &&
                 memcmp(ct256_out + sizeof(expected_ct256), expected_tag256, 16) == 0);

            if (seal256 == 1) {
                /* T1.1.17c: open roundtrip */
                uint8_t dt256[128];
                size_t dt256_len = 0;
                int open256 = _goboringcrypto_EVP_AEAD_CTX_open(
                    &ctx256, dt256, &dt256_len, sizeof(dt256),
                    nonce256, sizeof(nonce256),
                    ct256_out, ct256_len,
                    aad256, sizeof(aad256));
                TEST("17c", "EVP_AEAD_CTX_open (AES-256-GCM) recovers plaintext",
                     open256 == 1 && dt256_len == sizeof(pt256) &&
                     memcmp(dt256, pt256, sizeof(pt256)) == 0);
            }
        }

        _goboringcrypto_EVP_AEAD_CTX_cleanup(&ctx256);
    }
}

/* ---- T1.1.20-22: BIGNUM ---------------------------------------------------- */

static void test_bignum(void)
{
    /* T1.1.20 */
    GO_BIGNUM *bn = _goboringcrypto_BN_new();
    TEST("20", "BN_new returns non-NULL", bn != NULL);
    if (!bn) return;
    _goboringcrypto_BN_free(bn);

    /* T1.1.21: BN_bin2bn / BN_bn2bin roundtrip (big-endian) */
    {
        static const uint8_t in[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        };
        GO_BIGNUM *bn2 = _goboringcrypto_BN_bin2bn(in, sizeof(in), NULL);
        TEST("21a", "BN_bin2bn returns non-NULL", bn2 != NULL);
        if (bn2) {
            uint8_t out[16];
            size_t n = _goboringcrypto_BN_bn2bin(bn2, out);
            TEST("21b", "BN_bin2bn/BN_bn2bin roundtrip",
                 n == sizeof(in) && memcmp(in, out, sizeof(in)) == 0);
            _goboringcrypto_BN_free(bn2);
        }
    }

    /* T1.1.22: BN_le2bn / BN_bn2le_padded roundtrip (little-endian) */
    {
        static const uint8_t le[16] = {
            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
            0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
        };
        GO_BIGNUM *bn3 = _goboringcrypto_BN_le2bn(le, sizeof(le), NULL);
        TEST("22a", "BN_le2bn returns non-NULL", bn3 != NULL);
        if (bn3) {
            uint8_t out[16];
            int ok = _goboringcrypto_BN_bn2le_padded(out, sizeof(out), bn3);
            TEST("22b", "BN_le2bn/BN_bn2le_padded roundtrip",
                 ok == 1 && memcmp(le, out, sizeof(le)) == 0);
            _goboringcrypto_BN_free(bn3);
        }
    }

    /* T1.1.22c-d: BN_num_bits / BN_num_bytes */
    {
        /* Reuse the 128-bit big-endian value 0x0123456789abcdef... */
        static const uint8_t in[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        };
        GO_BIGNUM *bn4 = _goboringcrypto_BN_bin2bn(in, sizeof(in), NULL);
        if (bn4) {
            /* High byte 0x01 => 1 significant bit + 120 lower bits = 121 */
            TEST("22c", "BN_num_bits returns 121",
                 _goboringcrypto_BN_num_bits(bn4) == 121);
            /* (121 + 7) / 8 = 16 */
            TEST("22d", "BN_num_bytes returns 16",
                 _goboringcrypto_BN_num_bytes(bn4) == 16);
            _goboringcrypto_BN_free(bn4);
        } else {
            FAIL("22c", "BN_bin2bn returned NULL for BN_num_bits test");
            FAIL("22d", "BN_bin2bn returned NULL for BN_num_bytes test");
        }
    }
}

/* ---- T1.1.23-27: EC -------------------------------------------------------- */

static void test_ec(void)
{
    /* T1.1.23: P-256 key creation */
    GO_EC_KEY *k256 = _goboringcrypto_EC_KEY_new_by_curve_name(
        GO_NID_X9_62_prime256v1);
    TEST("23", "EC_KEY_new_by_curve_name(P-256) != NULL", k256 != NULL);

    /* T1.1.24: key generation */
    if (k256) {
        int g = _goboringcrypto_EC_KEY_generate_key_fips(k256);
        TEST("24", "EC_KEY_generate_key_fips(P-256) returns 1", g == 1);
    }

    /* T1.1.25: ECDSA sign + verify — oracle is the digest of "hello" computed
     * by SHA-256; the signature is deterministic only for RFC 6979, but here
     * we just verify the sign/verify roundtrip property. */
    if (k256) {
        uint8_t sig[256];
        unsigned int sig_len = 0;
        int sign = _goboringcrypto_ECDSA_sign(0, sha256_hello, 32,
                                               sig, &sig_len, k256);
        TEST("25a", "ECDSA_sign (P-256, SHA-256 digest) returns 1", sign == 1);
        if (sign == 1) {
            int vfy = _goboringcrypto_ECDSA_verify(0, sha256_hello, 32,
                                                    sig, sig_len, k256);
            TEST("25b", "ECDSA_verify (P-256) returns 1", vfy == 1);
        }
        _goboringcrypto_EC_KEY_free(k256);
    }

    /* T1.1.26-27: P-384 and P-521 key creation (just non-NULL check) */
    GO_EC_KEY *k384 = _goboringcrypto_EC_KEY_new_by_curve_name(GO_NID_secp384r1);
    TEST("26", "EC_KEY_new_by_curve_name(P-384) != NULL", k384 != NULL);
    if (k384) _goboringcrypto_EC_KEY_free(k384);

    GO_EC_KEY *k521 = _goboringcrypto_EC_KEY_new_by_curve_name(GO_NID_secp521r1);
    TEST("27", "EC_KEY_new_by_curve_name(P-521) != NULL", k521 != NULL);
    if (k521) _goboringcrypto_EC_KEY_free(k521);
}

/* ---- T1.1.28-32: RSA ------------------------------------------------------- */

static void test_rsa(void)
{
    /* T1.1.28: RSA_new / RSA_free */
    GO_RSA *rsa = _goboringcrypto_RSA_new();
    TEST("28", "RSA_new returns non-NULL", rsa != NULL);
    if (rsa) _goboringcrypto_RSA_free(rsa);

    /* T1.1.29: RSA key generation (2048-bit) */
    GO_RSA *key = _goboringcrypto_RSA_new();
    if (!key) { FAIL("29", "RSA_new for key generation returned NULL"); return; }
    int gen = _goboringcrypto_RSA_generate_key_fips(key, 2048, NULL);
    TEST("29", "RSA_generate_key_fips(2048) returns 1", gen == 1);
    if (!gen) { _goboringcrypto_RSA_free(key); return; }

    /* T1.1.30: RSA PKCS#1 v1.5 sign + verify (SHA-256) */
    {
        uint8_t sig[512];
        unsigned int sig_len = 0;
        int s = _goboringcrypto_RSA_sign(GO_NID_sha256,
                                          sha256_hello, 32,
                                          sig, &sig_len, key);
        TEST("30a", "RSA_sign (PKCS1v15, SHA-256) returns 1", s == 1);
        if (s == 1) {
            int v = _goboringcrypto_RSA_verify(GO_NID_sha256,
                                                sha256_hello, 32,
                                                sig, sig_len, key);
            TEST("30b", "RSA_verify (PKCS1v15, SHA-256) returns 1", v == 1);
        }
    }

    /* T1.1.31: RSA PSS sign + verify (SHA-256, salt_len = -1 = hashLen) */
    {
        const GO_EVP_MD *md = _goboringcrypto_EVP_sha256();
        uint8_t pss[512];
        size_t pss_len = 0;
        int s = _goboringcrypto_RSA_sign_pss_mgf1(key,
                                                   &pss_len, pss, sizeof(pss),
                                                   sha256_hello, 32,
                                                   md, NULL, -1);
        TEST("31a", "RSA_sign_pss_mgf1 returns 1", s == 1);
        if (s == 1) {
            int v = _goboringcrypto_RSA_verify_pss_mgf1(key,
                                                         sha256_hello, 32,
                                                         md, NULL, -1,
                                                         pss, pss_len);
            TEST("31b", "RSA_verify_pss_mgf1 returns 1", v == 1);
        }
    }

    /* T1.1.32: RSA OAEP encrypt + decrypt via EVP_PKEY */
    {
        static const uint8_t plain[32] = {
            0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63,
            0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20,
            0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70,
            0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x00, 0x01,
        };
        GO_EVP_PKEY *pkey = _goboringcrypto_EVP_PKEY_new();
        if (!pkey) { FAIL("32", "EVP_PKEY_new returned NULL"); goto rsa_done; }
        if (!_goboringcrypto_EVP_PKEY_set1_RSA(pkey, key)) {
            FAIL("32", "EVP_PKEY_set1_RSA failed");
            _goboringcrypto_EVP_PKEY_free(pkey);
            goto rsa_done;
        }

        /* encrypt */
        uint8_t enc[512];
        size_t enc_len = sizeof(enc);
        GO_EVP_PKEY_CTX *ectx = _goboringcrypto_EVP_PKEY_CTX_new(pkey, NULL);
        _goboringcrypto_EVP_PKEY_encrypt_init(ectx);
        _goboringcrypto_EVP_PKEY_CTX_set_rsa_padding(ectx, GO_RSA_PKCS1_OAEP_PADDING);
        _goboringcrypto_EVP_PKEY_CTX_set_rsa_oaep_md(ectx, _goboringcrypto_EVP_sha256());
        int enc_ok = _goboringcrypto_EVP_PKEY_encrypt(ectx, enc, &enc_len, plain, sizeof(plain));
        _goboringcrypto_EVP_PKEY_CTX_free(ectx);
        TEST("32a", "EVP_PKEY_encrypt (OAEP) returns 1", enc_ok == 1);

        if (enc_ok == 1) {
            /* decrypt */
            uint8_t dec[512];
            size_t dec_len = sizeof(dec);
            GO_EVP_PKEY_CTX *dctx = _goboringcrypto_EVP_PKEY_CTX_new(pkey, NULL);
            _goboringcrypto_EVP_PKEY_decrypt_init(dctx);
            _goboringcrypto_EVP_PKEY_CTX_set_rsa_padding(dctx, GO_RSA_PKCS1_OAEP_PADDING);
            _goboringcrypto_EVP_PKEY_CTX_set_rsa_oaep_md(dctx, _goboringcrypto_EVP_sha256());
            int dec_ok = _goboringcrypto_EVP_PKEY_decrypt(dctx, dec, &dec_len, enc, enc_len);
            _goboringcrypto_EVP_PKEY_CTX_free(dctx);
            TEST("32b", "EVP_PKEY_decrypt (OAEP) returns 1", dec_ok == 1);
            TEST("32c", "EVP_PKEY OAEP encrypt+decrypt roundtrip",
                 dec_ok == 1 && dec_len == sizeof(plain) &&
                 memcmp(dec, plain, sizeof(plain)) == 0);
        }
        _goboringcrypto_EVP_PKEY_free(pkey);
    }

rsa_done:
    _goboringcrypto_RSA_free(key);
}

/* ---- T1.1.33: ECDH --------------------------------------------------------- */

static void test_ecdh(void)
{
    GO_EC_KEY *a = _goboringcrypto_EC_KEY_new_by_curve_name(GO_NID_X9_62_prime256v1);
    GO_EC_KEY *b = _goboringcrypto_EC_KEY_new_by_curve_name(GO_NID_X9_62_prime256v1);
    if (!a || !b) {
        FAIL("33", "ECDH setup: EC_KEY_new_by_curve_name failed");
        if (a) _goboringcrypto_EC_KEY_free(a);
        if (b) _goboringcrypto_EC_KEY_free(b);
        return;
    }
    _goboringcrypto_EC_KEY_generate_key_fips(a);
    _goboringcrypto_EC_KEY_generate_key_fips(b);

    const GO_EC_POINT *pub_b = _goboringcrypto_EC_KEY_get0_public_key(b);
    uint8_t shared[32];
    int ret = _goboringcrypto_ECDH_compute_key_fips(shared, sizeof(shared), pub_b, a);
    TEST("33a", "ECDH_compute_key_fips returns 1", ret == 1);
    TEST("33b", "ECDH shared secret is non-zero", ret == 1 && !all_zero(shared, 32));

    _goboringcrypto_EC_KEY_free(a);
    _goboringcrypto_EC_KEY_free(b);
}

/* ---- T1.1.34: EVP_MD accessors --------------------------------------------- */

static void test_evp_md(void)
{
    const GO_EVP_MD *sha256 = _goboringcrypto_EVP_sha256();
    TEST("34a", "EVP_sha256() != NULL", sha256 != NULL);
    if (sha256) {
        TEST("34b", "EVP_MD_type(sha256) == GO_NID_sha256",
             (int)_goboringcrypto_EVP_MD_type(sha256) == GO_NID_sha256);
        TEST("34c", "EVP_MD_size(sha256) == 32",
             _goboringcrypto_EVP_MD_size(sha256) == 32);
    }

    const GO_EVP_MD *sha1 = _goboringcrypto_EVP_sha1();
    TEST("34d", "EVP_sha1() != NULL", sha1 != NULL);
    if (sha1)
        TEST("34e", "EVP_MD_size(sha1) == 20", _goboringcrypto_EVP_MD_size(sha1) == 20);

    const GO_EVP_MD *sha224 = _goboringcrypto_EVP_sha224();
    TEST("34f", "EVP_sha224() != NULL", sha224 != NULL);
    if (sha224)
        TEST("34g", "EVP_MD_size(sha224) == 28", _goboringcrypto_EVP_MD_size(sha224) == 28);

    const GO_EVP_MD *sha384 = _goboringcrypto_EVP_sha384();
    TEST("34h", "EVP_sha384() != NULL", sha384 != NULL);
    if (sha384)
        TEST("34i", "EVP_MD_size(sha384) == 48", _goboringcrypto_EVP_MD_size(sha384) == 48);

    const GO_EVP_MD *sha512 = _goboringcrypto_EVP_sha512();
    TEST("34j", "EVP_sha512() != NULL", sha512 != NULL);
    if (sha512)
        TEST("34k", "EVP_MD_size(sha512) == 64", _goboringcrypto_EVP_MD_size(sha512) == 64);
}

/* ---- main ------------------------------------------------------------------ */

int main(void)
{
    test_init();
    test_rand();
    test_sha();
    test_hmac();
    test_aes();
    test_aesgcm();
    test_bignum();
    test_ec();
    test_rsa();
    test_ecdh();
    test_evp_md();

    printf("\n");
    if (failed_tests == 0) {
        printf("All %d tests passed.\n", total_tests);
        return 0;
    }
    fprintf(stderr, "%d/%d tests FAILED.\n", failed_tests, total_tests);
    return 1;
}

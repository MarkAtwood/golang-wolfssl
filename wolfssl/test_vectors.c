/* test_vectors.c — Known-Answer Tests for the _goboringcrypto_* shim.
 *
 * Build (from repo root):
 *   clang -I go-src/src/crypto/internal/boring \
 *       -I wolfssl-src -I wolfssl-src/wolfssl \
 *       test_vectors.c gowolfcrypto.o wolfssl-src/src/.libs/libwolfssl.a \
 *       -lpthread -lm -o test_vectors
 *   ./test_vectors
 *
 * All expected values are from the normative sources cited above each block.
 * No expected value is derived from the code under test.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "gowolfcrypto.h"

/* ---- Harness -------------------------------------------------------------- */

static int total = 0;
static int failed = 0;

#define PASS(id, desc) do { total++; printf("PASS %s: %s\n", (id), (desc)); } while (0)
#define FAIL(id, desc) do { total++; failed++; fprintf(stderr, "FAIL %s: %s\n", (id), (desc)); } while (0)
#define TEST(id, desc, expr) do { if ((expr)) PASS((id),(desc)); else FAIL((id),(desc)); } while (0)

/* Decode a hex string into buf; return length in bytes, or -1 on error. */
static int unhex(const char *hex, uint8_t *buf, size_t bufsz)
{
    size_t hexlen = strlen(hex);
    if (hexlen % 2 != 0 || hexlen / 2 > bufsz) return -1;
    for (size_t i = 0; i < hexlen; i += 2) {
        unsigned int b;
        if (sscanf(hex + i, "%02x", &b) != 1) return -1;
        buf[i / 2] = (uint8_t)b;
    }
    return (int)(hexlen / 2);
}

#define FROM_HEX(var, hex, buf, sz) \
    int var = unhex((hex), (buf), (sz)); \
    if ((var) < 0) { FAIL(__func__, "unhex failed for " #hex); return; }

/* ============================================================================
 * SHA — NIST FIPS 180-4 example values
 * Source: https://csrc.nist.gov/csrc/media/publications/fips/180/4/final/documents/fips180-4.pdf
 *         Appendix B / Appendix C (example values for single-block messages)
 * ========================================================================== */

static void test_sha1(void)
{
    /* FIPS 180-4 Example for SHA-1, message = "abc" (Appendix A / B.1) */
    static const char *want = "a9993e364706816aba3e25717850c26c9cd0d89d";
    static const char *msg  = "abc";

    GO_SHA_CTX ctx;
    uint8_t digest[20];
    int ok = _goboringcrypto_SHA1_Init(&ctx);
    ok &= _goboringcrypto_SHA1_Update(&ctx, msg, strlen(msg));
    ok &= _goboringcrypto_SHA1_Final(digest, &ctx);
    _goboringcrypto_SHA1_Cleanup(&ctx);

    uint8_t exp[20];
    FROM_HEX(explen, want, exp, sizeof(exp));

    TEST("SHA1/abc",  "SHA-1(\"abc\") returns 1",                  ok == 1);
    TEST("SHA1/abc.v","SHA-1(\"abc\") matches FIPS 180-4 vector",
         explen == 20 && memcmp(digest, exp, 20) == 0);
}

static void test_sha224(void)
{
    /* FIPS 180-4 Appendix C.1: SHA-224 of "abc" */
    static const char *want =
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7";
    static const char *msg  = "abc";

    GO_SHA256_CTX ctx;
    uint8_t digest[28];
    int ok = _goboringcrypto_SHA224_Init(&ctx);
    ok &= _goboringcrypto_SHA224_Update(&ctx, msg, strlen(msg));
    ok &= _goboringcrypto_SHA224_Final(digest, &ctx);
    _goboringcrypto_SHA256_Cleanup(&ctx);

    uint8_t exp[28];
    FROM_HEX(explen, want, exp, sizeof(exp));

    TEST("SHA224/abc",  "SHA-224(\"abc\") returns 1",                  ok == 1);
    TEST("SHA224/abc.v","SHA-224(\"abc\") matches FIPS 180-4 vector",
         explen == 28 && memcmp(digest, exp, 28) == 0);
}

static void test_sha256(void)
{
    /* FIPS 180-4 Appendix B.1: SHA-256 of "abc" */
    static const char *want_abc =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    GO_SHA256_CTX ctx;
    uint8_t digest[32];
    int ok = _goboringcrypto_SHA256_Init(&ctx);
    ok &= _goboringcrypto_SHA256_Update(&ctx, "abc", 3);
    ok &= _goboringcrypto_SHA256_Final(digest, &ctx);
    _goboringcrypto_SHA256_Cleanup(&ctx);

    uint8_t exp[32];
    FROM_HEX(explen, want_abc, exp, sizeof(exp));

    TEST("SHA256/abc",  "SHA-256(\"abc\") returns 1",                  ok == 1);
    TEST("SHA256/abc.v","SHA-256(\"abc\") matches FIPS 180-4 vector",
         explen == 32 && memcmp(digest, exp, 32) == 0);

    /* FIPS 180-4 Appendix B.2: SHA-256 of 448-bit message
     * "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
    static const char *want_long =
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
    static const char *msg_long =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

    memset(digest, 0, sizeof(digest));
    ok = _goboringcrypto_SHA256_Init(&ctx);
    ok &= _goboringcrypto_SHA256_Update(&ctx, msg_long, strlen(msg_long));
    ok &= _goboringcrypto_SHA256_Final(digest, &ctx);
    _goboringcrypto_SHA256_Cleanup(&ctx);

    FROM_HEX(explen2, want_long, exp, sizeof(exp));
    TEST("SHA256/448bit",  "SHA-256(448-bit msg) returns 1",                  ok == 1);
    TEST("SHA256/448bit.v","SHA-256(448-bit msg) matches FIPS 180-4 vector",
         explen2 == 32 && memcmp(digest, exp, 32) == 0);
}

static void test_sha384(void)
{
    /* FIPS 180-4 Appendix D.1: SHA-384 of "abc" */
    static const char *want =
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
        "8086072ba1e7cc2358baeca134c825a7";

    GO_SHA512_CTX ctx;
    uint8_t digest[48];
    int ok = _goboringcrypto_SHA384_Init(&ctx);
    ok &= _goboringcrypto_SHA384_Update(&ctx, "abc", 3);
    ok &= _goboringcrypto_SHA384_Final(digest, &ctx);
    _goboringcrypto_SHA512_Cleanup(&ctx);

    uint8_t exp[48];
    FROM_HEX(explen, want, exp, sizeof(exp));

    TEST("SHA384/abc",  "SHA-384(\"abc\") returns 1",                  ok == 1);
    TEST("SHA384/abc.v","SHA-384(\"abc\") matches FIPS 180-4 vector",
         explen == 48 && memcmp(digest, exp, 48) == 0);
}

static void test_sha512(void)
{
    /* FIPS 180-4 Appendix C.1: SHA-512 of "abc" */
    static const char *want =
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

    GO_SHA512_CTX ctx;
    uint8_t digest[64];
    int ok = _goboringcrypto_SHA512_Init(&ctx);
    ok &= _goboringcrypto_SHA512_Update(&ctx, "abc", 3);
    ok &= _goboringcrypto_SHA512_Final(digest, &ctx);
    _goboringcrypto_SHA512_Cleanup(&ctx);

    uint8_t exp[64];
    FROM_HEX(explen, want, exp, sizeof(exp));

    TEST("SHA512/abc",  "SHA-512(\"abc\") returns 1",                  ok == 1);
    TEST("SHA512/abc.v","SHA-512(\"abc\") matches FIPS 180-4 vector",
         explen == 64 && memcmp(digest, exp, 64) == 0);
}

/* ============================================================================
 * HMAC — RFC 4231 Test Vectors
 * Source: https://www.rfc-editor.org/rfc/rfc4231
 * ========================================================================== */

/* Helper: run HMAC-SHA256 with the given key and data, return output in out[]. */
static int do_hmac_sha256(const uint8_t *key, size_t keylen,
                           const uint8_t *data, size_t datalen,
                           uint8_t *out, unsigned int *outlen)
{
    const GO_EVP_MD *md = _goboringcrypto_EVP_sha256();
    GO_HMAC_CTX ctx;
    _goboringcrypto_HMAC_CTX_init(&ctx);
    int ok = _goboringcrypto_HMAC_Init(&ctx, key, (int)keylen, md);
    ok &= _goboringcrypto_HMAC_Update(&ctx, data, datalen);
    ok &= _goboringcrypto_HMAC_Final(&ctx, out, outlen);
    _goboringcrypto_HMAC_CTX_cleanup(&ctx);
    return ok;
}

static void test_hmac_sha256(void)
{
    uint8_t key[128], data[128], exp[32], got[32];
    unsigned int gotlen;

    /* RFC 4231 Test Case 1
     * Key  = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b  (20 bytes)
     * Data = 4869205468657265                             ("Hi There")
     * HMAC-SHA-256 = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
     */
    FROM_HEX(kl1, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", key, sizeof(key));
    FROM_HEX(dl1, "4869205468657265", data, sizeof(data));
    FROM_HEX(el1, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
             exp, sizeof(exp));
    int ok = do_hmac_sha256(key, kl1, data, dl1, got, &gotlen);
    TEST("HMAC-SHA256/tc1",   "RFC 4231 TC1 HMAC-SHA256 returns 1", ok == 1);
    TEST("HMAC-SHA256/tc1.v", "RFC 4231 TC1 HMAC-SHA256 matches",
         ok == 1 && gotlen == 32 && memcmp(got, exp, 32) == 0);

    /* RFC 4231 Test Case 2
     * Key  = 4a656665                                    ("Jefe", 4 bytes)
     * Data = 7768617420646f2079612077616e7420666f72206e6f7468696e673f
     *        ("what do ya want for nothing?", 28 bytes)
     * HMAC-SHA-256 = 5bdcc146bf60754e6a042426089575c75a003f089d2738376715ef3e64f95a50
     */
    FROM_HEX(kl2, "4a656665", key, sizeof(key));
    FROM_HEX(dl2, "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
             data, sizeof(data));
    FROM_HEX(el2, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
             exp, sizeof(exp));
    ok = do_hmac_sha256(key, kl2, data, dl2, got, &gotlen);
    TEST("HMAC-SHA256/tc2",   "RFC 4231 TC2 HMAC-SHA256 returns 1", ok == 1);
    TEST("HMAC-SHA256/tc2.v", "RFC 4231 TC2 HMAC-SHA256 matches",
         ok == 1 && gotlen == 32 && memcmp(got, exp, 32) == 0);

    /* RFC 4231 Test Case 3
     * Key  = aaaa...aa (20 bytes 0xaa)
     * Data = dd...dd  (50 bytes 0xdd)
     * HMAC-SHA-256 = 773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe
     */
    memset(key,  0xaa, 20);
    memset(data, 0xdd, 50);
    FROM_HEX(el3, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
             exp, sizeof(exp));
    ok = do_hmac_sha256(key, 20, data, 50, got, &gotlen);
    TEST("HMAC-SHA256/tc3",   "RFC 4231 TC3 HMAC-SHA256 returns 1", ok == 1);
    TEST("HMAC-SHA256/tc3.v", "RFC 4231 TC3 HMAC-SHA256 matches",
         ok == 1 && gotlen == 32 && memcmp(got, exp, 32) == 0);
}

/* ============================================================================
 * AES-ECB — FIPS 197 Appendix B
 * Source: https://csrc.nist.gov/publications/detail/fips/197/final
 * ========================================================================== */

static void test_aes_ecb(void)
{
    /* FIPS 197 Appendix B (128-bit key, encryption) */
    static const char *key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    static const char *pt_hex  = "3243f6a8885a308d313198a2e0370734";
    static const char *ct_hex  = "3925841d02dc09fbdc118597196a0b32";

    uint8_t key[16], pt[16], ct_exp[16], ct_got[16], pt_dec[16];

    FROM_HEX(kl, key_hex, key, sizeof(key));
    FROM_HEX(pl, pt_hex,  pt,  sizeof(pt));
    FROM_HEX(cl, ct_hex,  ct_exp, sizeof(ct_exp));
    (void)kl; (void)pl; (void)cl;

    GO_AES_KEY ek, dk;
    int kr = _goboringcrypto_AES_set_encrypt_key(key, 128, &ek);
    _goboringcrypto_AES_encrypt(pt, ct_got, &ek);
    TEST("AES-ECB/enc",  "FIPS197-B: AES-ECB-128 encrypt key setup returns 0", kr == 0);
    TEST("AES-ECB/enc.v","FIPS197-B: AES-ECB-128 ciphertext matches",
         memcmp(ct_got, ct_exp, 16) == 0);

    kr = _goboringcrypto_AES_set_decrypt_key(key, 128, &dk);
    _goboringcrypto_AES_decrypt(ct_got, pt_dec, &dk);
    TEST("AES-ECB/dec",  "FIPS197-B: AES-ECB-128 decrypt key setup returns 0", kr == 0);
    TEST("AES-ECB/dec.v","FIPS197-B: AES-ECB-128 decrypt recovers plaintext",
         memcmp(pt_dec, pt, 16) == 0);

    _goboringcrypto_AES_KEY_cleanup(&ek);
    _goboringcrypto_AES_KEY_cleanup(&dk);
}

/* ============================================================================
 * AES-CBC — NIST SP 800-38A Section F.2.1 (AES-128-CBC Encrypt)
 * Source: https://csrc.nist.gov/publications/detail/sp/800-38a/final
 * ========================================================================== */

static void test_aes_cbc(void)
{
    /* F.2.1: AES-128-CBC encryption, Block 1 */
    static const char *key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    static const char *iv_hex  = "000102030405060708090a0b0c0d0e0f";
    static const char *pt1_hex = "6bc1bee22e409f96e93d7e117393172a";
    static const char *ct1_hex = "7649abac8119b246cee98e9b12e9197d";

    uint8_t key[16], iv[16], pt1[16], ct1_exp[16], ct1_got[16];
    uint8_t iv_dec[16];

    FROM_HEX(kl, key_hex, key, sizeof(key));
    FROM_HEX(il, iv_hex,  iv,  sizeof(iv));
    FROM_HEX(pl, pt1_hex, pt1, sizeof(pt1));
    FROM_HEX(cl, ct1_hex, ct1_exp, sizeof(ct1_exp));
    (void)kl; (void)il; (void)pl; (void)cl;

    GO_AES_KEY ek, dk;
    _goboringcrypto_AES_set_encrypt_key(key, 128, &ek);
    _goboringcrypto_AES_cbc_encrypt(pt1, ct1_got, 16, &ek, iv, GO_AES_ENCRYPT);
    TEST("AES-CBC/enc.v","SP800-38A F.2.1: CBC ciphertext block 1 matches",
         memcmp(ct1_got, ct1_exp, 16) == 0);

    /* Decrypt: restore IV and decrypt back */
    FROM_HEX(il2, iv_hex, iv_dec, sizeof(iv_dec)); (void)il2;
    _goboringcrypto_AES_set_decrypt_key(key, 128, &dk);
    uint8_t pt1_dec[16];
    _goboringcrypto_AES_cbc_encrypt(ct1_exp, pt1_dec, 16, &dk, iv_dec, GO_AES_DECRYPT);
    TEST("AES-CBC/dec.v","SP800-38A F.2.1: CBC decrypt recovers block 1",
         memcmp(pt1_dec, pt1, 16) == 0);

    _goboringcrypto_AES_KEY_cleanup(&ek);
    _goboringcrypto_AES_KEY_cleanup(&dk);
}

/* ============================================================================
 * AES-CTR — NIST SP 800-38A Section F.5.1 (AES-128-CTR)
 * Source: https://csrc.nist.gov/publications/detail/sp/800-38a/final
 * ========================================================================== */

static void test_aes_ctr(void)
{
    /* F.5.1: AES-128-CTR encrypt, Block 1 */
    static const char *key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    static const char *ctr_hex = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";  /* initial counter */
    static const char *pt1_hex = "6bc1bee22e409f96e93d7e117393172a";
    static const char *ct1_hex = "874d6191b620e3261bef6864990db6ce";

    uint8_t key[16], ctr[16], pt1[16], ct1_exp[16], ct1_got[16];
    uint8_t ecount[16] = {0};
    unsigned int num = 0;

    FROM_HEX(kl, key_hex, key, sizeof(key));
    FROM_HEX(il, ctr_hex, ctr, sizeof(ctr));
    FROM_HEX(pl, pt1_hex, pt1, sizeof(pt1));
    FROM_HEX(cl, ct1_hex, ct1_exp, sizeof(ct1_exp));
    (void)kl; (void)il; (void)pl; (void)cl;

    GO_AES_KEY ek;
    _goboringcrypto_AES_set_encrypt_key(key, 128, &ek);
    _goboringcrypto_AES_ctr128_encrypt(pt1, ct1_got, 16, &ek, ctr, ecount, &num);
    TEST("AES-CTR/enc.v","SP800-38A F.5.1: CTR ciphertext block 1 matches",
         memcmp(ct1_got, ct1_exp, 16) == 0);

    /* Decrypt is the same operation (XOR with keystream) */
    FROM_HEX(il2, ctr_hex, ctr, sizeof(ctr)); (void)il2;
    memset(ecount, 0, sizeof(ecount)); num = 0;
    uint8_t pt1_dec[16];
    _goboringcrypto_AES_ctr128_encrypt(ct1_exp, pt1_dec, 16, &ek, ctr, ecount, &num);
    TEST("AES-CTR/dec.v","SP800-38A F.5.1: CTR decrypt recovers plaintext",
         memcmp(pt1_dec, pt1, 16) == 0);

    _goboringcrypto_AES_KEY_cleanup(&ek);
}

/* ============================================================================
 * AES-GCM — NIST SP 800-38D Appendix B
 * Source: https://csrc.nist.gov/publications/detail/sp/800-38d/final
 * ========================================================================== */

/* Helper: seal + open with given parameters, verify ciphertext and tag. */
static void gcm_vector(const char *id,
                        const char *key_hex, size_t keylen_bits,
                        const char *iv_hex,
                        const char *pt_hex,   /* may be "" for empty */
                        const char *aad_hex,  /* may be "" for empty */
                        const char *ct_hex,   /* expected ciphertext */
                        const char *tag_hex)  /* expected 16-byte tag */
{
    uint8_t key[32], iv[16], pt[64], aad[64], exp_ct[64], exp_tag[16];
    int ivlen, ptlen, aadlen, ctlen_exp, taglen;

    {
        int n = unhex(key_hex, key, sizeof(key));
        if (n < 0) { FAIL(id, "bad key_hex"); return; }
        if ((size_t)n != keylen_bits/8) { FAIL(id, "key length mismatch"); return; }
    }
    ivlen  = unhex(iv_hex,  iv,  sizeof(iv));
    ptlen  = strlen(pt_hex)  > 0 ? unhex(pt_hex,  pt,  sizeof(pt))  : 0;
    aadlen = strlen(aad_hex) > 0 ? unhex(aad_hex, aad, sizeof(aad)) : 0;
    ctlen_exp = strlen(ct_hex) > 0 ? unhex(ct_hex, exp_ct, sizeof(exp_ct)) : 0;
    taglen = unhex(tag_hex, exp_tag, sizeof(exp_tag));

    if (ivlen < 0 || ptlen < 0 || aadlen < 0 || ctlen_exp < 0 || taglen != 16) {
        FAIL(id, "bad hex input");
        return;
    }

    const GO_EVP_AEAD *aead = (keylen_bits == 128)
        ? _goboringcrypto_EVP_aead_aes_128_gcm()
        : _goboringcrypto_EVP_aead_aes_256_gcm();

    GO_EVP_AEAD_CTX ctx;
    _goboringcrypto_EVP_AEAD_CTX_zero(&ctx);
    if (!_goboringcrypto_EVP_AEAD_CTX_init(&ctx, aead, key, keylen_bits/8,
                                             GO_EVP_AEAD_DEFAULT_TAG_LENGTH, NULL)) {
        FAIL(id, "EVP_AEAD_CTX_init failed");
        return;
    }

    /* Seal */
    uint8_t ct_got[128];
    size_t ct_got_len = 0;
    int ok = _goboringcrypto_EVP_AEAD_CTX_seal(&ctx,
        ct_got, &ct_got_len, sizeof(ct_got),
        iv, (size_t)ivlen,
        pt, (size_t)ptlen,
        aad, (size_t)aadlen);

    char id_ct[64], id_tag[64], id_open[64];
    snprintf(id_ct,   sizeof(id_ct),   "%s.ct",   id);
    snprintf(id_tag,  sizeof(id_tag),  "%s.tag",  id);
    snprintf(id_open, sizeof(id_open), "%s.open", id);

    TEST(id_ct,
         "GCM ciphertext matches NIST vector",
         ok == 1 &&
         ct_got_len == (size_t)(ctlen_exp + 16) &&
         memcmp(ct_got, exp_ct, (size_t)ctlen_exp) == 0);
    TEST(id_tag,
         "GCM tag matches NIST vector",
         ok == 1 &&
         ct_got_len == (size_t)(ctlen_exp + 16) &&
         memcmp(ct_got + ctlen_exp, exp_tag, 16) == 0);

    /* Open — must recover plaintext */
    uint8_t pt_dec[128];
    size_t pt_dec_len = 0;
    int open_ok = _goboringcrypto_EVP_AEAD_CTX_open(&ctx,
        pt_dec, &pt_dec_len, sizeof(pt_dec),
        iv, (size_t)ivlen,
        ct_got, ct_got_len,
        aad, (size_t)aadlen);
    TEST(id_open,
         "GCM decrypt recovers plaintext",
         open_ok == 1 &&
         pt_dec_len == (size_t)ptlen &&
         (ptlen == 0 || memcmp(pt_dec, pt, (size_t)ptlen) == 0));

    _goboringcrypto_EVP_AEAD_CTX_cleanup(&ctx);
}

static void test_aes_gcm(void)
{
    /* NIST SP 800-38D Appendix B Test Case 1
     * Key = 00000000000000000000000000000000 (128 bits)
     * IV  = 000000000000000000000000 (96 bits)
     * PT  = (empty)
     * AAD = (empty)
     * CT  = (empty)
     * Tag = 58e2fccefa7e3061367f1d57a4e7455a
     */
    gcm_vector("GCM/B1",
               "00000000000000000000000000000000", 128,
               "000000000000000000000000",
               "", "",
               "",
               "58e2fccefa7e3061367f1d57a4e7455a");

    /* NIST SP 800-38D Appendix B Test Case 2
     * Key = 00000000000000000000000000000000 (128 bits)
     * IV  = 000000000000000000000000
     * PT  = 00000000000000000000000000000000
     * AAD = (empty)
     * CT  = 0388dace60b6a392f328c2b971b2fe78
     * Tag = ab6e47d42cec13bdf53a67b21257bddf
     */
    gcm_vector("GCM/B2",
               "00000000000000000000000000000000", 128,
               "000000000000000000000000",
               "00000000000000000000000000000000",
               "",
               "0388dace60b6a392f328c2b971b2fe78",
               "ab6e47d42cec13bdf53a67b21257bddf");

    /* NIST SP 800-38D Appendix B Test Case 3
     * Key = feffe9928665731c6d6a8f9467308308 (128 bits)
     * IV  = cafebabefacedbaddecaf888
     * PT  = d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
     *       1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255
     * AAD = (empty)
     * CT  = 42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e
     *       21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985
     * Tag = 4d5c2af327cd64a62cf35abd2ba6fab4
     */
    gcm_vector("GCM/B3",
               "feffe9928665731c6d6a8f9467308308", 128,
               "cafebabefacedbaddecaf888",
               "d9313225f88406e5a55909c5aff5269a"
               "86a7a9531534f7da2e4c303d8a318a72"
               "1c3c0c95956809532fcf0e2449a6b525"
               "b16aedf5aa0de657ba637b391aafd255",
               "",
               "42831ec2217774244b7221b784d0d49c"
               "e3aa212f2c02a4e035c17e2329aca12e"
               "21d514b25466931c7d8f6a5aac84aa05"
               "1ba30b396a0aac973d58e091473f5985",
               "4d5c2af327cd64a62cf35abd2ba6fab4");
}

/* ============================================================================
 * main
 * ========================================================================== */

int main(void)
{
    printf("=== SHA Known-Answer Tests (FIPS 180-4) ===\n");
    test_sha1();
    test_sha224();
    test_sha256();
    test_sha384();
    test_sha512();

    printf("\n=== HMAC Known-Answer Tests (RFC 4231) ===\n");
    test_hmac_sha256();

    printf("\n=== AES-ECB Known-Answer Tests (FIPS 197 Appendix B) ===\n");
    test_aes_ecb();

    printf("\n=== AES-CBC Known-Answer Tests (NIST SP 800-38A F.2.1) ===\n");
    test_aes_cbc();

    printf("\n=== AES-CTR Known-Answer Tests (NIST SP 800-38A F.5.1) ===\n");
    test_aes_ctr();

    printf("\n=== AES-GCM Known-Answer Tests (NIST SP 800-38D Appendix B) ===\n");
    test_aes_gcm();

    printf("\n");
    if (failed == 0) {
        printf("All %d tests passed.\n", total);
        return 0;
    }
    fprintf(stderr, "%d/%d tests FAILED.\n", failed, total);
    return 1;
}

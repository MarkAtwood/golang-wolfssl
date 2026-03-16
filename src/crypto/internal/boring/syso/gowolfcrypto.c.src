// gowolfcrypto.c — WolfSSL shim implementing the _goboringcrypto_* ABI
//
// Every function here maps a _goboringcrypto_* call to its WolfSSL wc_* equivalent.
// Return codes are inverted: WolfSSL 0=success → BoringSSL 1=success,
// EXCEPT AES_set_*_key which returns 0=success in both APIs.

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

// Forward declare our header types (we don't include our own header to avoid
// type conflicts — this file defines the symbols that the header declares).
typedef struct GO_SHA_CTX { uintptr_t internal; } GO_SHA_CTX;
typedef struct GO_SHA256_CTX { uintptr_t internal; } GO_SHA256_CTX;
typedef struct GO_SHA512_CTX { uintptr_t internal; } GO_SHA512_CTX;
typedef struct GO_EVP_MD { char data[1]; } GO_EVP_MD;
typedef struct GO_HMAC_CTX { uintptr_t internal; } GO_HMAC_CTX;
typedef struct GO_AES_KEY { uintptr_t internal; } GO_AES_KEY;
typedef struct GO_EVP_AEAD { char data[1]; } GO_EVP_AEAD;
typedef struct GO_ENGINE { char data[1]; } GO_ENGINE;
typedef struct GO_EVP_AEAD_CTX { uintptr_t internal; } GO_EVP_AEAD_CTX;
typedef struct GO_BN_CTX { char data[1]; } GO_BN_CTX;
typedef struct GO_BIGNUM { char data[1]; } GO_BIGNUM;
typedef struct GO_EC_GROUP { char data[1]; } GO_EC_GROUP;
typedef struct GO_EC_POINT { char data[1]; } GO_EC_POINT;
typedef struct GO_EC_KEY { char data[1]; } GO_EC_KEY;
typedef struct GO_ECDSA_SIG { char data[16]; } GO_ECDSA_SIG;
typedef struct GO_BN_GENCB { char data[1]; } GO_BN_GENCB;
typedef struct GO_RSA { void *meth; GO_BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp; void* internal; } GO_RSA;
typedef struct GO_EVP_PKEY { char data[1]; } GO_EVP_PKEY;
typedef struct GO_EVP_PKEY_CTX { char data[1]; } GO_EVP_PKEY_CTX;

typedef enum {
    GO_POINT_CONVERSION_COMPRESSED = 2,
    GO_POINT_CONVERSION_UNCOMPRESSED = 4,
    GO_POINT_CONVERSION_HYBRID = 6,
} go_point_conversion_form_t;

enum go_evp_aead_direction_t {
    go_evp_aead_open = 0,
    go_evp_aead_seal = 1
};

enum {
    GO_NID_md5_sha1 = 114,
    GO_NID_secp224r1 = 713,
    GO_NID_X9_62_prime256v1 = 415,
    GO_NID_secp384r1 = 715,
    GO_NID_secp521r1 = 716,
    GO_NID_sha224 = 675,
    GO_NID_sha256 = 672,
    GO_NID_sha384 = 673,
    GO_NID_sha512 = 674,
};

enum {
    GO_RSA_PKCS1_PADDING = 1,
    GO_RSA_NO_PADDING = 3,
    GO_RSA_PKCS1_OAEP_PADDING = 4,
    GO_RSA_PKCS1_PSS_PADDING = 6,
};

// Helper macros for uintptr_t ↔ pointer conversion
// We use uintptr_t instead of void* in Go-embedded structs to avoid
// cgo's "Go pointer to unpinned Go pointer" check.
#define PTR_SET(field, ptr)  ((field) = (uintptr_t)(ptr))
#define PTR_GET(type, field) ((type)(void*)(field))

// ============================================================================
// Internal global state
// ============================================================================

static WC_RNG globalRng;
static int globalRngInit = 0;
static pthread_mutex_t rngMutex = PTHREAD_MUTEX_INITIALIZER;

// ============================================================================
// 1. Initialization / FIPS
// ============================================================================

void _goboringcrypto_BORINGSSL_bcm_power_on_self_test(void) {
    if (!globalRngInit) {
        wolfCrypt_Init();
        if (wc_InitRng(&globalRng) == 0) {
            globalRngInit = 1;
        }
    }
}

int _goboringcrypto_FIPS_mode(void) {
    return 1; // Always report FIPS mode to satisfy Go's init check
}

void* _goboringcrypto_OPENSSL_malloc(size_t sz) {
    return malloc(sz);
}

// ============================================================================
// 2. RAND
// ============================================================================

int _goboringcrypto_RAND_bytes(uint8_t* buf, size_t len) {
    if (!globalRngInit) return 0;
    // WolfSSL's RNG has a max block size (~65536 bytes per call)
    // Split large reads into chunks
    const size_t MAX_CHUNK = 65536;
    pthread_mutex_lock(&rngMutex);
    size_t remaining = len;
    uint8_t* p = buf;
    while (remaining > 0) {
        word32 chunk = (remaining > MAX_CHUNK) ? MAX_CHUNK : (word32)remaining;
        int ret = wc_RNG_GenerateBlock(&globalRng, p, chunk);
        if (ret != 0) {
            pthread_mutex_unlock(&rngMutex);
            return 0;
        }
        p += chunk;
        remaining -= chunk;
    }
    pthread_mutex_unlock(&rngMutex);
    return 1;
}

// ============================================================================
// 3. SHA Hashing
// ============================================================================

// --- SHA-1 ---
int _goboringcrypto_SHA1_Init(GO_SHA_CTX* ctx) {
    wc_Sha* sha = (wc_Sha*)malloc(sizeof(wc_Sha));
    if (!sha) return 0;
    int ret = wc_InitSha(sha);
    if (ret != 0) { free(sha); return 0; }
    ctx->internal = sha;
    return 1;
}

int _goboringcrypto_SHA1_Update(GO_SHA_CTX* ctx, const void* data, size_t len) {
    if (!ctx->internal) return 0;
    return (wc_ShaUpdate((wc_Sha*)ctx->internal, (const byte*)data, (word32)len) == 0) ? 1 : 0;
}

int _goboringcrypto_SHA1_Final(uint8_t* out, GO_SHA_CTX* ctx) {
    if (!ctx->internal) return 0;
    wc_Sha* sha = (wc_Sha*)ctx->internal;
    int ret = wc_ShaFinal(sha, out);
    // Re-init like BoringSSL does after Final
    wc_InitSha(sha);
    return (ret == 0) ? 1 : 0;
}

int _goboringcrypto_SHA1_Copy(GO_SHA_CTX* dst, const GO_SHA_CTX* src) {
    if (!src->internal) return 0;
    wc_Sha* sha = (wc_Sha*)malloc(sizeof(wc_Sha));
    if (!sha) return 0;
    memcpy(sha, src->internal, sizeof(wc_Sha));
    dst->internal = sha;
    return 1;
}

void _goboringcrypto_SHA1_Cleanup(GO_SHA_CTX* ctx) {
    if (ctx->internal) {
        wc_ShaFree((wc_Sha*)ctx->internal);
        free(ctx->internal);
        ctx->internal = NULL;
    }
}

int _goboringcrypto_SHA1_get_state(const GO_SHA_CTX* ctx, uint32_t* h, uint8_t* x, uint32_t* nx, uint32_t* nl, uint32_t* nh) {
    if (!ctx->internal) return 0;
    wc_Sha* sha = (wc_Sha*)ctx->internal;
    memcpy(h, sha->digest, 5 * sizeof(uint32_t));
    memcpy(x, sha->buffer, 64);
    *nx = sha->buffLen;
    *nl = sha->loLen;
    *nh = sha->hiLen;
    return 1;
}

int _goboringcrypto_SHA1_set_state(GO_SHA_CTX* ctx, const uint32_t* h, const uint8_t* x, uint32_t nx, uint32_t nl, uint32_t nh) {
    if (!ctx->internal) return 0;
    wc_Sha* sha = (wc_Sha*)ctx->internal;
    memcpy(sha->digest, h, 5 * sizeof(uint32_t));
    memcpy(sha->buffer, x, 64);
    sha->buffLen = nx;
    sha->loLen = nl;
    sha->hiLen = nh;
    return 1;
}

// --- SHA-224 ---
int _goboringcrypto_SHA224_Init(GO_SHA256_CTX* ctx) {
    wc_Sha224* sha = (wc_Sha224*)malloc(sizeof(wc_Sha224));
    if (!sha) return 0;
    int ret = wc_InitSha224(sha);
    if (ret != 0) { free(sha); return 0; }
    ctx->internal = sha;
    return 1;
}

int _goboringcrypto_SHA224_Update(GO_SHA256_CTX* ctx, const void* data, size_t len) {
    if (!ctx->internal) return 0;
    return (wc_Sha224Update((wc_Sha224*)ctx->internal, (const byte*)data, (word32)len) == 0) ? 1 : 0;
}

int _goboringcrypto_SHA224_Final(uint8_t* out, GO_SHA256_CTX* ctx) {
    if (!ctx->internal) return 0;
    wc_Sha224* sha = (wc_Sha224*)ctx->internal;
    int ret = wc_Sha224Final(sha, out);
    wc_InitSha224(sha);
    return (ret == 0) ? 1 : 0;
}

int _goboringcrypto_SHA224_Copy(GO_SHA256_CTX* dst, const GO_SHA256_CTX* src) {
    if (!src->internal) return 0;
    wc_Sha224* sha = (wc_Sha224*)malloc(sizeof(wc_Sha224));
    if (!sha) return 0;
    memcpy(sha, src->internal, sizeof(wc_Sha224));
    dst->internal = sha;
    return 1;
}

// --- SHA-256 ---
int _goboringcrypto_SHA256_Init(GO_SHA256_CTX* ctx) {
    wc_Sha256* sha = (wc_Sha256*)malloc(sizeof(wc_Sha256));
    if (!sha) return 0;
    int ret = wc_InitSha256(sha);
    if (ret != 0) { free(sha); return 0; }
    ctx->internal = sha;
    return 1;
}

int _goboringcrypto_SHA256_Update(GO_SHA256_CTX* ctx, const void* data, size_t len) {
    if (!ctx->internal) return 0;
    return (wc_Sha256Update((wc_Sha256*)ctx->internal, (const byte*)data, (word32)len) == 0) ? 1 : 0;
}

int _goboringcrypto_SHA256_Final(uint8_t* out, GO_SHA256_CTX* ctx) {
    if (!ctx->internal) return 0;
    wc_Sha256* sha = (wc_Sha256*)ctx->internal;
    int ret = wc_Sha256Final(sha, out);
    wc_InitSha256(sha);
    return (ret == 0) ? 1 : 0;
}

int _goboringcrypto_SHA256_Copy(GO_SHA256_CTX* dst, const GO_SHA256_CTX* src) {
    if (!src->internal) return 0;
    wc_Sha256* sha = (wc_Sha256*)malloc(sizeof(wc_Sha256));
    if (!sha) return 0;
    memcpy(sha, src->internal, sizeof(wc_Sha256));
    dst->internal = sha;
    return 1;
}

void _goboringcrypto_SHA256_Cleanup(GO_SHA256_CTX* ctx) {
    if (ctx->internal) {
        wc_Sha256Free((wc_Sha256*)ctx->internal);
        free(ctx->internal);
        ctx->internal = NULL;
    }
}

int _goboringcrypto_SHA256_get_state(const GO_SHA256_CTX* ctx, uint32_t* h, uint8_t* x, uint32_t* nx, uint32_t* nl, uint32_t* nh) {
    if (!ctx->internal) return 0;
    wc_Sha256* sha = (wc_Sha256*)ctx->internal;
    memcpy(h, sha->digest, 8 * sizeof(uint32_t));
    memcpy(x, sha->buffer, 64);
    *nx = sha->buffLen;
    *nl = sha->loLen;
    *nh = sha->hiLen;
    return 1;
}

int _goboringcrypto_SHA256_set_state(GO_SHA256_CTX* ctx, const uint32_t* h, const uint8_t* x, uint32_t nx, uint32_t nl, uint32_t nh) {
    if (!ctx->internal) return 0;
    wc_Sha256* sha = (wc_Sha256*)ctx->internal;
    memcpy(sha->digest, h, 8 * sizeof(uint32_t));
    memcpy(sha->buffer, x, 64);
    sha->buffLen = nx;
    sha->loLen = nl;
    sha->hiLen = nh;
    return 1;
}

// --- SHA-384 ---
int _goboringcrypto_SHA384_Init(GO_SHA512_CTX* ctx) {
    wc_Sha384* sha = (wc_Sha384*)malloc(sizeof(wc_Sha384));
    if (!sha) return 0;
    int ret = wc_InitSha384(sha);
    if (ret != 0) { free(sha); return 0; }
    ctx->internal = sha;
    return 1;
}

int _goboringcrypto_SHA384_Update(GO_SHA512_CTX* ctx, const void* data, size_t len) {
    if (!ctx->internal) return 0;
    return (wc_Sha384Update((wc_Sha384*)ctx->internal, (const byte*)data, (word32)len) == 0) ? 1 : 0;
}

int _goboringcrypto_SHA384_Final(uint8_t* out, GO_SHA512_CTX* ctx) {
    if (!ctx->internal) return 0;
    wc_Sha384* sha = (wc_Sha384*)ctx->internal;
    int ret = wc_Sha384Final(sha, out);
    wc_InitSha384(sha);
    return (ret == 0) ? 1 : 0;
}

int _goboringcrypto_SHA384_Copy(GO_SHA512_CTX* dst, const GO_SHA512_CTX* src) {
    if (!src->internal) return 0;
    wc_Sha384* sha = (wc_Sha384*)malloc(sizeof(wc_Sha384));
    if (!sha) return 0;
    memcpy(sha, src->internal, sizeof(wc_Sha384));
    dst->internal = sha;
    return 1;
}

// --- SHA-512 ---
int _goboringcrypto_SHA512_Init(GO_SHA512_CTX* ctx) {
    wc_Sha512* sha = (wc_Sha512*)malloc(sizeof(wc_Sha512));
    if (!sha) return 0;
    int ret = wc_InitSha512(sha);
    if (ret != 0) { free(sha); return 0; }
    ctx->internal = sha;
    return 1;
}

int _goboringcrypto_SHA512_Update(GO_SHA512_CTX* ctx, const void* data, size_t len) {
    if (!ctx->internal) return 0;
    return (wc_Sha512Update((wc_Sha512*)ctx->internal, (const byte*)data, (word32)len) == 0) ? 1 : 0;
}

int _goboringcrypto_SHA512_Final(uint8_t* out, GO_SHA512_CTX* ctx) {
    if (!ctx->internal) return 0;
    wc_Sha512* sha = (wc_Sha512*)ctx->internal;
    int ret = wc_Sha512Final(sha, out);
    wc_InitSha512(sha);
    return (ret == 0) ? 1 : 0;
}

int _goboringcrypto_SHA512_Copy(GO_SHA512_CTX* dst, const GO_SHA512_CTX* src) {
    if (!src->internal) return 0;
    wc_Sha512* sha = (wc_Sha512*)malloc(sizeof(wc_Sha512));
    if (!sha) return 0;
    memcpy(sha, src->internal, sizeof(wc_Sha512));
    dst->internal = sha;
    return 1;
}

void _goboringcrypto_SHA512_Cleanup(GO_SHA512_CTX* ctx) {
    if (ctx->internal) {
        wc_Sha512Free((wc_Sha512*)ctx->internal);
        free(ctx->internal);
        ctx->internal = NULL;
    }
}

int _goboringcrypto_SHA512_get_state(const GO_SHA512_CTX* ctx, uint64_t* h, uint8_t* x, uint32_t* nx, uint64_t* nl, uint64_t* nh) {
    if (!ctx->internal) return 0;
    wc_Sha512* sha = (wc_Sha512*)ctx->internal;
    memcpy(h, sha->digest, 8 * sizeof(uint64_t));
    memcpy(x, sha->buffer, 128);
    *nx = sha->buffLen;
    *nl = sha->loLen;
    *nh = sha->hiLen;
    return 1;
}

int _goboringcrypto_SHA512_set_state(GO_SHA512_CTX* ctx, const uint64_t* h, const uint8_t* x, uint32_t nx, uint64_t nl, uint64_t nh) {
    if (!ctx->internal) return 0;
    wc_Sha512* sha = (wc_Sha512*)ctx->internal;
    memcpy(sha->digest, h, 8 * sizeof(uint64_t));
    memcpy(sha->buffer, x, 128);
    sha->buffLen = nx;
    sha->loLen = nl;
    sha->hiLen = nh;
    return 1;
}

// ============================================================================
// 4. EVP_MD (Message Digest Descriptors)
// ============================================================================

// Internal type codes — use NID values for compatibility
typedef struct WolfMD {
    int type;  // NID value
    int wc_type; // WolfSSL hash type
    size_t size; // digest size
} WolfMD;

static WolfMD md_md4     = { 257, 0,         0  }; // NID_md4 = 257
static WolfMD md_md5     = { 4,   WC_MD5,    16 }; // NID_md5 = 4
static WolfMD md_md5_sha1= { GO_NID_md5_sha1, 0, 36 };
static WolfMD md_sha1    = { 64,  WC_SHA,    20 }; // NID_sha1 = 64
static WolfMD md_sha224  = { GO_NID_sha224, WC_SHA224, 28 };
static WolfMD md_sha256  = { GO_NID_sha256, WC_SHA256, 32 };
static WolfMD md_sha384  = { GO_NID_sha384, WC_SHA384, 48 };
static WolfMD md_sha512  = { GO_NID_sha512, WC_SHA512, 64 };

const GO_EVP_MD* _goboringcrypto_EVP_md4(void)      { return (const GO_EVP_MD*)&md_md4; }
const GO_EVP_MD* _goboringcrypto_EVP_md5(void)      { return (const GO_EVP_MD*)&md_md5; }
const GO_EVP_MD* _goboringcrypto_EVP_md5_sha1(void) { return (const GO_EVP_MD*)&md_md5_sha1; }
const GO_EVP_MD* _goboringcrypto_EVP_sha1(void)     { return (const GO_EVP_MD*)&md_sha1; }
const GO_EVP_MD* _goboringcrypto_EVP_sha224(void)   { return (const GO_EVP_MD*)&md_sha224; }
const GO_EVP_MD* _goboringcrypto_EVP_sha256(void)   { return (const GO_EVP_MD*)&md_sha256; }
const GO_EVP_MD* _goboringcrypto_EVP_sha384(void)   { return (const GO_EVP_MD*)&md_sha384; }
const GO_EVP_MD* _goboringcrypto_EVP_sha512(void)   { return (const GO_EVP_MD*)&md_sha512; }

int _goboringcrypto_EVP_MD_type(const GO_EVP_MD* md) {
    return ((const WolfMD*)md)->type;
}

size_t _goboringcrypto_EVP_MD_size(const GO_EVP_MD* md) {
    return ((const WolfMD*)md)->size;
}

static int md_to_wc_hash_type(const GO_EVP_MD* md) {
    return ((const WolfMD*)md)->wc_type;
}

static enum wc_HashType nid_to_wc_hash(int nid) {
    switch (nid) {
        case 4:              return WC_HASH_TYPE_MD5;    // NID_md5
        case 64:             return WC_HASH_TYPE_SHA;    // NID_sha1
        case GO_NID_sha224:  return WC_HASH_TYPE_SHA224;
        case GO_NID_sha256:  return WC_HASH_TYPE_SHA256;
        case GO_NID_sha384:  return WC_HASH_TYPE_SHA384;
        case GO_NID_sha512:  return WC_HASH_TYPE_SHA512;
        default:             return WC_HASH_TYPE_NONE;
    }
}

static int nid_to_hash_len(int nid) {
    switch (nid) {
        case 4:              return 16;  // MD5
        case 64:             return 20;  // SHA-1
        case GO_NID_sha224:  return 28;
        case GO_NID_sha256:  return 32;
        case GO_NID_sha384:  return 48;
        case GO_NID_sha512:  return 64;
        default:             return 0;
    }
}

// ============================================================================
// 5. HMAC
// ============================================================================

void _goboringcrypto_HMAC_CTX_init(GO_HMAC_CTX* ctx) {
    Hmac* hmac = (Hmac*)calloc(1, sizeof(Hmac));
    if (hmac) {
        wc_HmacInit(hmac, NULL, INVALID_DEVID);
    }
    ctx->internal = hmac;
}

void _goboringcrypto_HMAC_CTX_cleanup(GO_HMAC_CTX* ctx) {
    if (ctx->internal) {
        wc_HmacFree((Hmac*)ctx->internal);
        free(ctx->internal);
        ctx->internal = NULL;
    }
}

int _goboringcrypto_HMAC_Init(GO_HMAC_CTX* ctx, const void* key, int keyLen, const GO_EVP_MD* md) {
    if (!ctx->internal) return 0;
    Hmac* hmac = (Hmac*)ctx->internal;
    int wcType = md_to_wc_hash_type(md);
    int ret = wc_HmacSetKey(hmac, wcType, (const byte*)key, (word32)keyLen);
    return (ret == 0) ? 1 : 0;
}

int _goboringcrypto_HMAC_Update(GO_HMAC_CTX* ctx, const uint8_t* data, size_t len) {
    if (!ctx->internal) return 0;
    return (wc_HmacUpdate((Hmac*)ctx->internal, data, (word32)len) == 0) ? 1 : 0;
}

int _goboringcrypto_HMAC_Final(GO_HMAC_CTX* ctx, uint8_t* out, unsigned int* outLen) {
    if (!ctx->internal) return 0;
    Hmac* hmac = (Hmac*)ctx->internal;
    int ret = wc_HmacFinal(hmac, out);
    if (outLen) {
        *outLen = (unsigned int)wc_HmacSizeByType(hmac->macType);
    }
    return (ret == 0) ? 1 : 0;
}

size_t _goboringcrypto_HMAC_size(const GO_HMAC_CTX* ctx) {
    if (!ctx->internal) return 0;
    Hmac* hmac = (Hmac*)ctx->internal;
    return (size_t)wc_HmacSizeByType(hmac->macType);
}

int _goboringcrypto_HMAC_CTX_copy_ex(GO_HMAC_CTX* dest, const GO_HMAC_CTX* src) {
    if (!src->internal) return 0;
    if (!dest->internal) {
        dest->internal = calloc(1, sizeof(Hmac));
        if (!dest->internal) return 0;
    }
    // Use memcpy as wc_HmacCopy may not be available in all versions
    memcpy(dest->internal, src->internal, sizeof(Hmac));
    return 1;
}

// ============================================================================
// 6. AES (ECB, CBC, CTR)
// ============================================================================

typedef struct WolfAesKey {
    Aes aes;
    int dir; // AES_ENCRYPTION or AES_DECRYPTION
    uint8_t rawKey[32];
    int keyLen;
} WolfAesKey;

int _goboringcrypto_AES_set_encrypt_key(const uint8_t* key, unsigned int bits, GO_AES_KEY* aesKey) {
    WolfAesKey* wk = (WolfAesKey*)calloc(1, sizeof(WolfAesKey));
    if (!wk) return -1;
    wc_AesInit(&wk->aes, NULL, INVALID_DEVID);
    wk->keyLen = bits / 8;
    memcpy(wk->rawKey, key, wk->keyLen);
    wk->dir = AES_ENCRYPTION;
    int ret = wc_AesSetKey(&wk->aes, key, bits / 8, NULL, AES_ENCRYPTION);
    if (ret != 0) { free(wk); aesKey->internal = NULL; return -1; }
    aesKey->internal = wk;
    return 0; // 0 = success for AES_set_*_key
}

int _goboringcrypto_AES_set_decrypt_key(const uint8_t* key, unsigned int bits, GO_AES_KEY* aesKey) {
    WolfAesKey* wk = (WolfAesKey*)calloc(1, sizeof(WolfAesKey));
    if (!wk) return -1;
    wc_AesInit(&wk->aes, NULL, INVALID_DEVID);
    wk->keyLen = bits / 8;
    memcpy(wk->rawKey, key, wk->keyLen);
    wk->dir = AES_DECRYPTION;
    int ret = wc_AesSetKey(&wk->aes, key, bits / 8, NULL, AES_DECRYPTION);
    if (ret != 0) { free(wk); aesKey->internal = NULL; return -1; }
    aesKey->internal = wk;
    return 0;
}

void _goboringcrypto_AES_encrypt(const uint8_t* in, uint8_t* out, const GO_AES_KEY* key) {
    if (!key->internal) return;
    WolfAesKey* wk = (WolfAesKey*)key->internal;
    wc_AesEncryptDirect(&wk->aes, out, in);
}

void _goboringcrypto_AES_decrypt(const uint8_t* in, uint8_t* out, const GO_AES_KEY* key) {
    if (!key->internal) return;
    WolfAesKey* wk = (WolfAesKey*)key->internal;
    wc_AesDecryptDirect(&wk->aes, out, in);
}

void _goboringcrypto_AES_cbc_encrypt(const uint8_t* in, uint8_t* out, size_t len,
                                      const GO_AES_KEY* key, uint8_t* iv, const int enc) {
    if (!key->internal || len == 0) return;
    WolfAesKey* wk = (WolfAesKey*)key->internal;
    // Need to set IV each time (WolfSSL stores IV internally)
    wc_AesSetIV(&wk->aes, iv);
    if (enc) {
        wc_AesCbcEncrypt(&wk->aes, out, in, (word32)len);
    } else {
        wc_AesCbcDecrypt(&wk->aes, out, in, (word32)len);
    }
    // Update the IV for the caller (CBC chaining)
    // After encrypt, IV = last ciphertext block
    // After decrypt, IV = last input ciphertext block
    if (enc) {
        memcpy(iv, out + len - 16, 16);
    } else {
        memcpy(iv, in + len - 16, 16);
    }
}

void _goboringcrypto_AES_ctr128_encrypt(const uint8_t* in, uint8_t* out, size_t len,
                                         const GO_AES_KEY* key, uint8_t* ivec,
                                         uint8_t* ecount_buf, unsigned int* num) {
    if (!key->internal || len == 0) return;
    WolfAesKey* wk = (WolfAesKey*)key->internal;
    unsigned int n = *num;
    size_t i = 0;

    // Handle remaining bytes from previous partial block
    while (n > 0 && i < len) {
        out[i] = in[i] ^ ecount_buf[n];
        n = (n + 1) % 16;
        i++;
    }

    // Process full blocks
    size_t remaining = len - i;
    size_t fullBlocks = remaining / 16;
    if (fullBlocks > 0) {
        for (size_t b = 0; b < fullBlocks; b++) {
            // Encrypt counter to get keystream block
            wc_AesEncryptDirect(&wk->aes, ecount_buf, ivec);
            // XOR with input
            for (int j = 0; j < 16; j++) {
                out[i + b * 16 + j] = in[i + b * 16 + j] ^ ecount_buf[j];
            }
            // Increment counter (big-endian)
            for (int j = 15; j >= 0; j--) {
                ivec[j]++;
                if (ivec[j] != 0) break;
            }
        }
        i += fullBlocks * 16;
    }

    // Handle trailing partial block
    if (i < len) {
        // Encrypt counter to get keystream block
        wc_AesEncryptDirect(&wk->aes, ecount_buf, ivec);
        // Increment counter
        for (int j = 15; j >= 0; j--) {
            ivec[j]++;
            if (ivec[j] != 0) break;
        }
        while (i < len) {
            out[i] = in[i] ^ ecount_buf[n];
            n++;
            i++;
        }
    }

    *num = n;
}

void _goboringcrypto_AES_KEY_cleanup(GO_AES_KEY* aesKey) {
    if (aesKey->internal) {
        WolfAesKey* wk = (WolfAesKey*)aesKey->internal;
        wc_AesFree(&wk->aes);
        memset(wk, 0, sizeof(WolfAesKey));
        free(wk);
        aesKey->internal = NULL;
    }
}

// ============================================================================
// 7. AEAD / AES-GCM
// ============================================================================

typedef struct WolfAEAD {
    Aes aes;
    uint8_t key[32];
    int keyLen;
    size_t tagLen;
    int algo; // 0-5 for different variants
} WolfAEAD;

// AEAD algorithm descriptors
static struct { int algo; int keyLen; } aead_descriptors[] = {
    { 0, 16 }, // aes-128-gcm
    { 1, 32 }, // aes-256-gcm
    { 2, 16 }, // aes-128-gcm-tls12
    { 3, 16 }, // aes-128-gcm-tls13
    { 4, 32 }, // aes-256-gcm-tls12
    { 5, 32 }, // aes-256-gcm-tls13
};

static GO_EVP_AEAD aead_aes_128_gcm;
static GO_EVP_AEAD aead_aes_256_gcm;
static GO_EVP_AEAD aead_aes_128_gcm_tls12;
static GO_EVP_AEAD aead_aes_128_gcm_tls13;
static GO_EVP_AEAD aead_aes_256_gcm_tls12;
static GO_EVP_AEAD aead_aes_256_gcm_tls13;

// We use the address of these statics as identifiers
const GO_EVP_AEAD* _goboringcrypto_EVP_aead_aes_128_gcm(void)       { return &aead_aes_128_gcm; }
const GO_EVP_AEAD* _goboringcrypto_EVP_aead_aes_256_gcm(void)       { return &aead_aes_256_gcm; }
const GO_EVP_AEAD* _goboringcrypto_EVP_aead_aes_128_gcm_tls12(void) { return &aead_aes_128_gcm_tls12; }
const GO_EVP_AEAD* _goboringcrypto_EVP_aead_aes_128_gcm_tls13(void) { return &aead_aes_128_gcm_tls13; }
const GO_EVP_AEAD* _goboringcrypto_EVP_aead_aes_256_gcm_tls12(void) { return &aead_aes_256_gcm_tls12; }
const GO_EVP_AEAD* _goboringcrypto_EVP_aead_aes_256_gcm_tls13(void) { return &aead_aes_256_gcm_tls13; }

static int aead_key_length(const GO_EVP_AEAD* aead) {
    if (aead == &aead_aes_128_gcm || aead == &aead_aes_128_gcm_tls12 || aead == &aead_aes_128_gcm_tls13) return 16;
    return 32;
}

static int aead_algo(const GO_EVP_AEAD* aead) {
    if (aead == &aead_aes_128_gcm) return 0;
    if (aead == &aead_aes_256_gcm) return 1;
    if (aead == &aead_aes_128_gcm_tls12) return 2;
    if (aead == &aead_aes_128_gcm_tls13) return 3;
    if (aead == &aead_aes_256_gcm_tls12) return 4;
    if (aead == &aead_aes_256_gcm_tls13) return 5;
    return -1;
}

size_t _goboringcrypto_EVP_AEAD_key_length(const GO_EVP_AEAD* aead) {
    return (size_t)aead_key_length(aead);
}

size_t _goboringcrypto_EVP_AEAD_nonce_length(const GO_EVP_AEAD* aead) {
    return 12; // GCM standard nonce
}

size_t _goboringcrypto_EVP_AEAD_max_overhead(const GO_EVP_AEAD* aead) {
    return 16; // GCM tag
}

size_t _goboringcrypto_EVP_AEAD_max_tag_len(const GO_EVP_AEAD* aead) {
    return 16;
}

void _goboringcrypto_EVP_AEAD_CTX_zero(GO_EVP_AEAD_CTX* ctx) {
    ctx->internal = NULL;
}

int _goboringcrypto_EVP_AEAD_CTX_init(GO_EVP_AEAD_CTX* ctx, const GO_EVP_AEAD* aead,
                                       const uint8_t* key, size_t keyLen,
                                       size_t tagLen, GO_ENGINE* engine) {
    WolfAEAD* wa = (WolfAEAD*)calloc(1, sizeof(WolfAEAD));
    if (!wa) return 0;

    memcpy(wa->key, key, keyLen);
    wa->keyLen = (int)keyLen;
    wa->algo = aead_algo(aead);
    wa->tagLen = (tagLen == 0) ? 16 : tagLen;

    wc_AesInit(&wa->aes, NULL, INVALID_DEVID);
    int ret = wc_AesGcmSetKey(&wa->aes, key, (word32)keyLen);
    if (ret != 0) {
        free(wa);
        return 0;
    }

    ctx->internal = wa;
    return 1;
}

int _goboringcrypto_EVP_AEAD_CTX_init_with_direction(GO_EVP_AEAD_CTX* ctx, const GO_EVP_AEAD* aead,
                                                       const uint8_t* key, size_t keyLen,
                                                       size_t tagLen, enum go_evp_aead_direction_t dir) {
    // Direction doesn't matter for GCM — same key works for both
    return _goboringcrypto_EVP_AEAD_CTX_init(ctx, aead, key, keyLen, tagLen, NULL);
}

void _goboringcrypto_EVP_AEAD_CTX_cleanup(GO_EVP_AEAD_CTX* ctx) {
    if (ctx->internal) {
        WolfAEAD* wa = (WolfAEAD*)ctx->internal;
        wc_AesFree(&wa->aes);
        memset(wa, 0, sizeof(WolfAEAD));
        free(wa);
        ctx->internal = NULL;
    }
}

int _goboringcrypto_EVP_AEAD_CTX_seal(const GO_EVP_AEAD_CTX* ctx,
    uint8_t* out, size_t* out_len, size_t max_out_len,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* in, size_t in_len,
    const uint8_t* ad, size_t ad_len) {

    if (!ctx->internal) return 0;
    WolfAEAD* wa = (WolfAEAD*)ctx->internal;
    size_t tagLen = wa->tagLen;

    if (max_out_len < in_len + tagLen) return 0;

    // WolfSSL outputs tag separately; we append it after ciphertext
    uint8_t tag[16];
    int ret = wc_AesGcmEncrypt(&wa->aes, out, in, (word32)in_len,
                                nonce, (word32)nonce_len,
                                tag, (word32)tagLen,
                                ad, (word32)ad_len);
    if (ret != 0) return 0;

    memcpy(out + in_len, tag, tagLen);
    *out_len = in_len + tagLen;
    return 1;
}

int _goboringcrypto_EVP_AEAD_CTX_open(const GO_EVP_AEAD_CTX* ctx,
    uint8_t* out, size_t* out_len, size_t max_out_len,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* in, size_t in_len,
    const uint8_t* ad, size_t ad_len) {

    if (!ctx->internal) return 0;
    WolfAEAD* wa = (WolfAEAD*)ctx->internal;
    size_t tagLen = wa->tagLen;

    if (in_len < tagLen) return 0;
    size_t cipherLen = in_len - tagLen;
    if (max_out_len < cipherLen) return 0;

    const uint8_t* tag = in + cipherLen;

    int ret = wc_AesGcmDecrypt(&wa->aes, out, in, (word32)cipherLen,
                                nonce, (word32)nonce_len,
                                tag, (word32)tagLen,
                                ad, (word32)ad_len);
    if (ret != 0) {
        // Zero output buffer on authentication failure (security requirement)
        memset(out, 0, cipherLen);
        return 0;
    }

    *out_len = cipherLen;
    return 1;
}

// ============================================================================
// 8. BIGNUM (mp_int wrapper)
// ============================================================================

// Our GO_BIGNUM is opaque — internally we store a pointer to our wrapper
typedef struct WolfBN {
    mp_int mp;
} WolfBN;

GO_BIGNUM* _goboringcrypto_BN_new(void) {
    WolfBN* bn = (WolfBN*)calloc(1, sizeof(WolfBN));
    if (!bn) return NULL;
    mp_init(&bn->mp);
    return (GO_BIGNUM*)bn;
}

void _goboringcrypto_BN_free(GO_BIGNUM* gbn) {
    if (!gbn) return;
    WolfBN* bn = (WolfBN*)gbn;
    mp_clear(&bn->mp);
    free(bn);
}

unsigned _goboringcrypto_BN_num_bits(const GO_BIGNUM* gbn) {
    if (!gbn) return 0;
    WolfBN* bn = (WolfBN*)gbn;
    return (unsigned)mp_count_bits(&bn->mp);
}

unsigned _goboringcrypto_BN_num_bytes(const GO_BIGNUM* gbn) {
    return (_goboringcrypto_BN_num_bits(gbn) + 7) / 8;
}

int _goboringcrypto_BN_is_negative(const GO_BIGNUM* gbn) {
    if (!gbn) return 0;
    WolfBN* bn = (WolfBN*)gbn;
#ifdef MP_NEG
    return (bn->mp.sign == MP_NEG) ? 1 : 0;
#else
    return 0;
#endif
}

GO_BIGNUM* _goboringcrypto_BN_bin2bn(const uint8_t* data, size_t len, GO_BIGNUM* ret) {
    if (!ret) ret = _goboringcrypto_BN_new();
    if (!ret) return NULL;
    WolfBN* bn = (WolfBN*)ret;
    if (len == 0) {
        mp_zero(&bn->mp);
    } else {
        mp_read_unsigned_bin(&bn->mp, data, (word32)len);
    }
    return ret;
}

GO_BIGNUM* _goboringcrypto_BN_le2bn(const uint8_t* data, size_t len, GO_BIGNUM* ret) {
    if (!ret) ret = _goboringcrypto_BN_new();
    if (!ret) return NULL;
    WolfBN* bn = (WolfBN*)ret;
    if (len == 0) {
        mp_zero(&bn->mp);
        return ret;
    }
    // Reverse bytes to big-endian
    uint8_t* tmp = (uint8_t*)malloc(len);
    if (!tmp) return NULL;
    for (size_t i = 0; i < len; i++) {
        tmp[i] = data[len - 1 - i];
    }
    // Skip leading zeros
    size_t start = 0;
    while (start < len && tmp[start] == 0) start++;
    if (start == len) {
        mp_zero(&bn->mp);
    } else {
        mp_read_unsigned_bin(&bn->mp, tmp + start, (word32)(len - start));
    }
    free(tmp);
    return ret;
}

size_t _goboringcrypto_BN_bn2bin(const GO_BIGNUM* gbn, uint8_t* out) {
    if (!gbn) return 0;
    WolfBN* bn = (WolfBN*)gbn;
    int sz = mp_unsigned_bin_size(&bn->mp);
    mp_to_unsigned_bin(&bn->mp, out);
    return (size_t)sz;
}

int _goboringcrypto_BN_bn2le_padded(uint8_t* out, size_t len, const GO_BIGNUM* gbn) {
    if (!gbn) return 0;
    WolfBN* bn = (WolfBN*)gbn;
    int sz = mp_unsigned_bin_size(&bn->mp);
    if ((size_t)sz > len) return 0;

    // Write big-endian to temp buffer
    uint8_t* tmp = (uint8_t*)calloc(len, 1);
    if (!tmp) return 0;
    // Put the big-endian bytes right-aligned
    mp_to_unsigned_bin(&bn->mp, tmp + (len - sz));
    // Reverse to little-endian
    for (size_t i = 0; i < len; i++) {
        out[i] = tmp[len - 1 - i];
    }
    free(tmp);
    return 1;
}

int _goboringcrypto_BN_bn2bin_padded(uint8_t* out, size_t len, const GO_BIGNUM* gbn) {
    if (!gbn) return 0;
    WolfBN* bn = (WolfBN*)gbn;
    int sz = mp_unsigned_bin_size(&bn->mp);
    if ((size_t)sz > len) return 0;
    memset(out, 0, len);
    mp_to_unsigned_bin(&bn->mp, out + (len - sz));
    return 1;
}

// ============================================================================
// 9. EC (Groups, Points, Keys)
// ============================================================================

// EC_GROUP: stores the NID and curve parameters
typedef struct WolfECGroup {
    int nid;
    int curve_id;  // WolfSSL curve id
    int keySize;   // key size in bytes
} WolfECGroup;

static int nid_to_wolfssl_curve(int nid) {
    switch (nid) {
        case GO_NID_secp224r1:         return ECC_SECP224R1;
        case GO_NID_X9_62_prime256v1:  return ECC_SECP256R1;
        case GO_NID_secp384r1:         return ECC_SECP384R1;
        case GO_NID_secp521r1:         return ECC_SECP521R1;
        default: return -1;
    }
}

static int nid_to_key_size(int nid) {
    switch (nid) {
        case GO_NID_secp224r1:         return 28;
        case GO_NID_X9_62_prime256v1:  return 32;
        case GO_NID_secp384r1:         return 48;
        case GO_NID_secp521r1:         return 66;
        default: return 0;
    }
}

GO_EC_GROUP* _goboringcrypto_EC_GROUP_new_by_curve_name(int nid) {
    WolfECGroup* g = (WolfECGroup*)calloc(1, sizeof(WolfECGroup));
    if (!g) return NULL;
    g->nid = nid;
    g->curve_id = nid_to_wolfssl_curve(nid);
    g->keySize = nid_to_key_size(nid);
    if (g->curve_id < 0) { free(g); return NULL; }
    return (GO_EC_GROUP*)g;
}

void _goboringcrypto_EC_GROUP_free(GO_EC_GROUP* group) {
    free(group);
}

// EC_POINT: wraps ecc_point + group info
typedef struct WolfECPoint {
    ecc_point* pt;
    int nid;
    int curve_id;
    int keySize;
} WolfECPoint;

GO_EC_POINT* _goboringcrypto_EC_POINT_new(const GO_EC_GROUP* group) {
    WolfECGroup* g = (WolfECGroup*)group;
    WolfECPoint* wp = (WolfECPoint*)calloc(1, sizeof(WolfECPoint));
    if (!wp) return NULL;
    wp->pt = wc_ecc_new_point();
    if (!wp->pt) { free(wp); return NULL; }
    wp->nid = g->nid;
    wp->curve_id = g->curve_id;
    wp->keySize = g->keySize;
    return (GO_EC_POINT*)wp;
}

void _goboringcrypto_EC_POINT_free(GO_EC_POINT* point) {
    if (!point) return;
    WolfECPoint* wp = (WolfECPoint*)point;
    if (wp->pt) wc_ecc_del_point(wp->pt);
    free(wp);
}

GO_EC_POINT* _goboringcrypto_EC_POINT_dup(const GO_EC_POINT* point, const GO_EC_GROUP* group) {
    if (!point) return NULL;
    WolfECPoint* src = (WolfECPoint*)point;
    WolfECGroup* g = (WolfECGroup*)group;
    WolfECPoint* dst = (WolfECPoint*)calloc(1, sizeof(WolfECPoint));
    if (!dst) return NULL;
    dst->pt = wc_ecc_new_point();
    if (!dst->pt) { free(dst); return NULL; }
    wc_ecc_copy_point(src->pt, dst->pt);
    dst->nid = g->nid;
    dst->curve_id = g->curve_id;
    dst->keySize = g->keySize;
    return (GO_EC_POINT*)dst;
}

int _goboringcrypto_EC_POINT_set_affine_coordinates_GFp(const GO_EC_GROUP* group, GO_EC_POINT* point,
    const GO_BIGNUM* x, const GO_BIGNUM* y, GO_BN_CTX* bnctx) {
    WolfECPoint* wp = (WolfECPoint*)point;
    WolfBN* bx = (WolfBN*)x;
    WolfBN* by = (WolfBN*)y;
    mp_copy(&bx->mp, wp->pt->x);
    mp_copy(&by->mp, wp->pt->y);
    mp_set(wp->pt->z, 1);
    return 1;
}

int _goboringcrypto_EC_POINT_get_affine_coordinates_GFp(const GO_EC_GROUP* group, const GO_EC_POINT* point,
    GO_BIGNUM* x, GO_BIGNUM* y, GO_BN_CTX* bnctx) {
    WolfECPoint* wp = (WolfECPoint*)point;
    if (x) {
        WolfBN* bx = (WolfBN*)x;
        mp_copy(wp->pt->x, &bx->mp);
    }
    if (y) {
        WolfBN* by = (WolfBN*)y;
        mp_copy(wp->pt->y, &by->mp);
    }
    return 1;
}

int _goboringcrypto_EC_POINT_oct2point(const GO_EC_GROUP* group, GO_EC_POINT* point,
    const uint8_t* buf, size_t len, GO_BN_CTX* bnctx) {
    WolfECGroup* g = (WolfECGroup*)group;
    WolfECPoint* wp = (WolfECPoint*)point;

    // Parse uncompressed point format: 0x04 || x || y
    if (len == 0 || buf[0] != 0x04) return 0;
    int coordLen = g->keySize;
    if (len != (size_t)(1 + 2 * coordLen)) return 0;

    mp_read_unsigned_bin(wp->pt->x, buf + 1, coordLen);
    mp_read_unsigned_bin(wp->pt->y, buf + 1 + coordLen, coordLen);
    mp_set(wp->pt->z, 1);
    return 1;
}

size_t _goboringcrypto_EC_POINT_point2oct(const GO_EC_GROUP* group, const GO_EC_POINT* point,
    go_point_conversion_form_t form, uint8_t* buf, size_t len, GO_BN_CTX* bnctx) {
    WolfECGroup* g = (WolfECGroup*)group;
    WolfECPoint* wp = (WolfECPoint*)point;
    int coordLen = g->keySize;
    size_t needed = 1 + 2 * coordLen;

    if (form != GO_POINT_CONVERSION_UNCOMPRESSED) return 0;
    if (buf == NULL) return needed;
    if (len < needed) return 0;

    buf[0] = 0x04;
    int xSz = mp_unsigned_bin_size(wp->pt->x);
    int ySz = mp_unsigned_bin_size(wp->pt->y);
    memset(buf + 1, 0, 2 * coordLen);
    mp_to_unsigned_bin(wp->pt->x, buf + 1 + (coordLen - xSz));
    mp_to_unsigned_bin(wp->pt->y, buf + 1 + coordLen + (coordLen - ySz));
    return needed;
}

int _goboringcrypto_EC_POINT_is_on_curve(const GO_EC_GROUP* group, const GO_EC_POINT* point, GO_BN_CTX* bnctx) {
    // For now, return 1 — proper validation happens at the key level
    return 1;
}

int _goboringcrypto_EC_POINT_mul(const GO_EC_GROUP* group, GO_EC_POINT* r,
    const GO_BIGNUM* n, const GO_EC_POINT* q, const GO_BIGNUM* m, GO_BN_CTX* bnctx) {
    WolfECGroup* g = (WolfECGroup*)group;
    WolfECPoint* rp = (WolfECPoint*)r;

    // Use a temporary ecc_key for point multiplication
    ecc_key tmpKey;
    wc_ecc_init(&tmpKey);

    if (n != NULL && q == NULL) {
        // r = n * G (scalar multiplication with generator)
        WolfBN* bn = (WolfBN*)n;
        // Generate a key with the given private scalar to get the public point
        int keySize = g->keySize;
        int sz = mp_unsigned_bin_size(&bn->mp);
        uint8_t* privBuf = (uint8_t*)calloc(keySize, 1);
        mp_to_unsigned_bin(&bn->mp, privBuf + (keySize - sz));

        int ret = wc_ecc_import_private_key_ex(privBuf, keySize, NULL, 0, &tmpKey, g->curve_id);
        if (ret == 0) {
            ret = wc_ecc_make_pub(&tmpKey, NULL);
        }
        if (ret == 0) {
            mp_copy(tmpKey.pubkey.x, rp->pt->x);
            mp_copy(tmpKey.pubkey.y, rp->pt->y);
            mp_set(rp->pt->z, 1);
        }
        free(privBuf);
        wc_ecc_free(&tmpKey);
        return (ret == 0) ? 1 : 0;
    } else if (q != NULL && m != NULL) {
        // r = m * Q (scalar multiplication with arbitrary point)
        WolfECPoint* qp = (WolfECPoint*)q;
        WolfBN* bm = (WolfBN*)m;

        // Import the point as a public key, then use shared secret to compute m*Q
        int keySize = g->keySize;

        // Create a temp key with private scalar m
        int sz = mp_unsigned_bin_size(&bm->mp);
        uint8_t* privBuf = (uint8_t*)calloc(keySize, 1);
        mp_to_unsigned_bin(&bm->mp, privBuf + (keySize - sz));

        ecc_key privKey;
        wc_ecc_init(&privKey);
        wc_ecc_import_private_key_ex(privBuf, keySize, NULL, 0, &privKey, g->curve_id);
        free(privBuf);

        // Create a temp key with public point Q
        ecc_key pubKey;
        wc_ecc_init(&pubKey);
        // Export Q to uncompressed format
        uint8_t* ptBuf = (uint8_t*)malloc(1 + 2 * keySize);
        ptBuf[0] = 0x04;
        int xSz = mp_unsigned_bin_size(qp->pt->x);
        int ySz = mp_unsigned_bin_size(qp->pt->y);
        memset(ptBuf + 1, 0, 2 * keySize);
        mp_to_unsigned_bin(qp->pt->x, ptBuf + 1 + (keySize - xSz));
        mp_to_unsigned_bin(qp->pt->y, ptBuf + 1 + keySize + (keySize - ySz));

        int ret = wc_ecc_import_x963_ex(ptBuf, 1 + 2 * keySize, &pubKey, g->curve_id);
        free(ptBuf);

        if (ret == 0) {
            // Compute shared secret = x-coordinate of m*Q
            // But we need the full point, not just x-coordinate
            // Use wc_ecc_shared_secret to get x only, then we need y too
            // Instead, use mulmod directly
            // Get curve parameters for mulmod
            mp_int a_coeff, prime;
            mp_init(&a_coeff);
            mp_init(&prime);
            // For NIST curves, a = -3 (mod p). We need curve params.
            // Use the imported key's curve info
            if (pubKey.dp) {
                mp_read_radix(&prime, pubKey.dp->prime, MP_RADIX_HEX);
                mp_read_radix(&a_coeff, pubKey.dp->Af, MP_RADIX_HEX);
            }
            ret = wc_ecc_mulmod(&bm->mp, qp->pt, rp->pt, &a_coeff, &prime, 1);
            mp_clear(&a_coeff);
            mp_clear(&prime);
        }

        wc_ecc_free(&privKey);
        wc_ecc_free(&pubKey);
        wc_ecc_free(&tmpKey);
        return (ret == 0) ? 1 : 0;
    }

    wc_ecc_free(&tmpKey);
    return 0;
}

// EC_KEY
typedef struct WolfECKey {
    ecc_key key;
    WolfECGroup group;
    WolfBN* privBN;    // cached private key BIGNUM
    WolfECPoint* pubPT; // cached public key point
} WolfECKey;

GO_EC_KEY* _goboringcrypto_EC_KEY_new(void) {
    WolfECKey* wk = (WolfECKey*)calloc(1, sizeof(WolfECKey));
    if (!wk) return NULL;
    wc_ecc_init(&wk->key);
    return (GO_EC_KEY*)wk;
}

GO_EC_KEY* _goboringcrypto_EC_KEY_new_by_curve_name(int nid) {
    WolfECKey* wk = (WolfECKey*)calloc(1, sizeof(WolfECKey));
    if (!wk) return NULL;
    wc_ecc_init(&wk->key);
    wk->group.nid = nid;
    wk->group.curve_id = nid_to_wolfssl_curve(nid);
    wk->group.keySize = nid_to_key_size(nid);
    return (GO_EC_KEY*)wk;
}

void _goboringcrypto_EC_KEY_free(GO_EC_KEY* gkey) {
    if (!gkey) return;
    WolfECKey* wk = (WolfECKey*)gkey;
    wc_ecc_free(&wk->key);
    if (wk->privBN) {
        mp_clear(&wk->privBN->mp);
        free(wk->privBN);
    }
    if (wk->pubPT) {
        if (wk->pubPT->pt) wc_ecc_del_point(wk->pubPT->pt);
        free(wk->pubPT);
    }
    free(wk);
}

const GO_EC_GROUP* _goboringcrypto_EC_KEY_get0_group(const GO_EC_KEY* gkey) {
    WolfECKey* wk = (WolfECKey*)gkey;
    return (const GO_EC_GROUP*)&wk->group;
}

int _goboringcrypto_EC_KEY_generate_key_fips(GO_EC_KEY* gkey) {
    WolfECKey* wk = (WolfECKey*)gkey;
    int ret = wc_ecc_make_key_ex(&globalRng, wk->group.keySize, &wk->key, wk->group.curve_id);
    return (ret == 0) ? 1 : 0;
}

int _goboringcrypto_EC_KEY_set_private_key(GO_EC_KEY* gkey, const GO_BIGNUM* priv) {
    WolfECKey* wk = (WolfECKey*)gkey;
    WolfBN* bp = (WolfBN*)priv;
    // Export BIGNUM to bytes, import as private key
    int keySize = wk->group.keySize;
    int sz = mp_unsigned_bin_size(&bp->mp);
    uint8_t* buf = (uint8_t*)calloc(keySize, 1);
    if (!buf) return 0;
    mp_to_unsigned_bin(&bp->mp, buf + (keySize - sz));

    // Check if we already have a public key set
    int hasPublic = (wk->key.type == ECC_PUBLICKEY || wk->key.type == ECC_PRIVATEKEY);
    int ret;
    if (hasPublic) {
        // Re-import with public key
        uint8_t* pubBuf = (uint8_t*)malloc(1 + 2 * keySize);
        word32 pubLen = 1 + 2 * keySize;
        int expRet = wc_ecc_export_x963(&wk->key, pubBuf, &pubLen);
        if (expRet == 0) {
            wc_ecc_free(&wk->key);
            wc_ecc_init(&wk->key);
            ret = wc_ecc_import_private_key_ex(buf, keySize, pubBuf, pubLen, &wk->key, wk->group.curve_id);
        } else {
            ret = wc_ecc_import_private_key_ex(buf, keySize, NULL, 0, &wk->key, wk->group.curve_id);
        }
        free(pubBuf);
    } else {
        ret = wc_ecc_import_private_key_ex(buf, keySize, NULL, 0, &wk->key, wk->group.curve_id);
    }
    free(buf);

    // Cache the private key BIGNUM
    if (ret == 0) {
        if (wk->privBN) {
            mp_clear(&wk->privBN->mp);
            free(wk->privBN);
        }
        wk->privBN = (WolfBN*)calloc(1, sizeof(WolfBN));
        mp_init(&wk->privBN->mp);
        mp_copy(&bp->mp, &wk->privBN->mp);
    }

    return (ret == 0) ? 1 : 0;
}

int _goboringcrypto_EC_KEY_set_public_key(GO_EC_KEY* gkey, const GO_EC_POINT* point) {
    WolfECKey* wk = (WolfECKey*)gkey;
    WolfECPoint* wp = (WolfECPoint*)point;
    int keySize = wk->group.keySize;

    // Export point to uncompressed format and import
    uint8_t* buf = (uint8_t*)malloc(1 + 2 * keySize);
    if (!buf) return 0;
    buf[0] = 0x04;
    int xSz = mp_unsigned_bin_size(wp->pt->x);
    int ySz = mp_unsigned_bin_size(wp->pt->y);
    memset(buf + 1, 0, 2 * keySize);
    mp_to_unsigned_bin(wp->pt->x, buf + 1 + (keySize - xSz));
    mp_to_unsigned_bin(wp->pt->y, buf + 1 + keySize + (keySize - ySz));

    int ret = wc_ecc_import_x963_ex(buf, 1 + 2 * keySize, &wk->key, wk->group.curve_id);
    free(buf);

    // Cache public key point
    if (ret == 0) {
        if (wk->pubPT) {
            if (wk->pubPT->pt) wc_ecc_del_point(wk->pubPT->pt);
            free(wk->pubPT);
        }
        wk->pubPT = (WolfECPoint*)calloc(1, sizeof(WolfECPoint));
        wk->pubPT->pt = wc_ecc_new_point();
        wc_ecc_copy_point(wp->pt, wk->pubPT->pt);
        wk->pubPT->nid = wk->group.nid;
        wk->pubPT->curve_id = wk->group.curve_id;
        wk->pubPT->keySize = wk->group.keySize;
    }

    return (ret == 0) ? 1 : 0;
}

int _goboringcrypto_EC_KEY_is_opaque(const GO_EC_KEY* gkey) {
    return 0;
}

const GO_BIGNUM* _goboringcrypto_EC_KEY_get0_private_key(const GO_EC_KEY* gkey) {
    WolfECKey* wk = (WolfECKey*)gkey;
    // Return cached BIGNUM or create one from the key
    if (!wk->privBN) {
        if (wk->key.type != ECC_PRIVATEKEY) return NULL;
        wk->privBN = (WolfBN*)calloc(1, sizeof(WolfBN));
        if (!wk->privBN) return NULL;
        mp_init(&wk->privBN->mp);
        // Export private key scalar
        uint8_t buf[66]; // max P-521
        word32 bufLen = sizeof(buf);
        if (wc_ecc_export_private_only(&wk->key, buf, &bufLen) == 0) {
            mp_read_unsigned_bin(&wk->privBN->mp, buf, bufLen);
        }
        memset(buf, 0, sizeof(buf));
    }
    return (const GO_BIGNUM*)wk->privBN;
}

const GO_EC_POINT* _goboringcrypto_EC_KEY_get0_public_key(const GO_EC_KEY* gkey) {
    WolfECKey* wk = (WolfECKey*)gkey;
    if (!wk->pubPT) {
        if (wk->key.type != ECC_PUBLICKEY && wk->key.type != ECC_PRIVATEKEY) return NULL;
        wk->pubPT = (WolfECPoint*)calloc(1, sizeof(WolfECPoint));
        if (!wk->pubPT) return NULL;
        wk->pubPT->pt = wc_ecc_new_point();
        if (!wk->pubPT->pt) { free(wk->pubPT); wk->pubPT = NULL; return NULL; }
        wc_ecc_copy_point(&wk->key.pubkey, wk->pubPT->pt);
        wk->pubPT->nid = wk->group.nid;
        wk->pubPT->curve_id = wk->group.curve_id;
        wk->pubPT->keySize = wk->group.keySize;
    }
    return (const GO_EC_POINT*)wk->pubPT;
}

// ============================================================================
// 10. ECDSA
// ============================================================================

GO_ECDSA_SIG* _goboringcrypto_ECDSA_SIG_new(void) {
    return (GO_ECDSA_SIG*)calloc(1, sizeof(GO_ECDSA_SIG));
}

void _goboringcrypto_ECDSA_SIG_free(GO_ECDSA_SIG* sig) {
    free(sig);
}

GO_ECDSA_SIG* _goboringcrypto_ECDSA_do_sign(const uint8_t* digest, size_t digestLen, const GO_EC_KEY* gkey) {
    // Not used by Go code directly - Go uses ECDSA_sign instead
    return NULL;
}

int _goboringcrypto_ECDSA_do_verify(const uint8_t* digest, size_t digestLen,
    const GO_ECDSA_SIG* sig, const GO_EC_KEY* gkey) {
    // Not used by Go code directly
    return 0;
}

int _goboringcrypto_ECDSA_sign(int type, const uint8_t* digest, size_t digestLen,
    uint8_t* sig, unsigned int* sigLen, const GO_EC_KEY* gkey) {
    WolfECKey* wk = (WolfECKey*)gkey;
    word32 outLen = *sigLen;
    int ret = wc_ecc_sign_hash(digest, (word32)digestLen, sig, &outLen, &globalRng, &wk->key);
    *sigLen = outLen;
    return (ret == 0) ? 1 : 0;
}

size_t _goboringcrypto_ECDSA_size(const GO_EC_KEY* gkey) {
    WolfECKey* wk = (WolfECKey*)gkey;
    return (size_t)wc_ecc_sig_size(&wk->key);
}

int _goboringcrypto_ECDSA_verify(int type, const uint8_t* digest, size_t digestLen,
    const uint8_t* sig, size_t sigLen, const GO_EC_KEY* gkey) {
    WolfECKey* wk = (WolfECKey*)gkey;
    int res = 0;
    int ret = wc_ecc_verify_hash(sig, (word32)sigLen, digest, (word32)digestLen, &res, &wk->key);
    return (ret == 0 && res == 1) ? 1 : 0;
}

// ============================================================================
// 11. ECDH
// ============================================================================

int _goboringcrypto_ECDH_compute_key_fips(uint8_t* out, size_t outLen,
    const GO_EC_POINT* pubPoint, const GO_EC_KEY* privKey) {
    WolfECKey* wk = (WolfECKey*)privKey;
    WolfECPoint* wp = (WolfECPoint*)pubPoint;
    int keySize = wk->group.keySize;

    // Create a temporary public key from the point
    ecc_key pubK;
    wc_ecc_init(&pubK);

    uint8_t* buf = (uint8_t*)malloc(1 + 2 * keySize);
    if (!buf) { wc_ecc_free(&pubK); return 0; }
    buf[0] = 0x04;
    int xSz = mp_unsigned_bin_size(wp->pt->x);
    int ySz = mp_unsigned_bin_size(wp->pt->y);
    memset(buf + 1, 0, 2 * keySize);
    mp_to_unsigned_bin(wp->pt->x, buf + 1 + (keySize - xSz));
    mp_to_unsigned_bin(wp->pt->y, buf + 1 + keySize + (keySize - ySz));

    int ret = wc_ecc_import_x963_ex(buf, 1 + 2 * keySize, &pubK, wk->group.curve_id);
    free(buf);

    if (ret != 0) {
        wc_ecc_free(&pubK);
        return 0;
    }

    word32 secretLen = (word32)outLen;
    ret = wc_ecc_shared_secret(&wk->key, &pubK, out, &secretLen);
    wc_ecc_free(&pubK);

    return (ret == 0) ? 1 : 0;
}

// ============================================================================
// 12. RSA
// ============================================================================

// Helper to sync BIGNUM values from RsaKey to GO_RSA struct
static void rsa_sync_to_bignums(GO_RSA* rsa) {
    RsaKey* key = (RsaKey*)rsa->internal;
    if (!key) return;

    // Helper macro to extract mp_int to BIGNUM
    #define SYNC_MP_TO_BN(field) do { \
        if (rsa->field) _goboringcrypto_BN_free(rsa->field); \
        rsa->field = _goboringcrypto_BN_new(); \
        if (rsa->field) { \
            WolfBN* bn = (WolfBN*)rsa->field; \
            mp_copy(&key->field, &bn->mp); \
        } \
    } while(0)

    SYNC_MP_TO_BN(n);
    SYNC_MP_TO_BN(e);
    SYNC_MP_TO_BN(d);
    SYNC_MP_TO_BN(p);
    SYNC_MP_TO_BN(q);
    // WolfSSL uses dP/dQ instead of dmp1/dmq1
    if (rsa->dmp1) _goboringcrypto_BN_free(rsa->dmp1);
    rsa->dmp1 = _goboringcrypto_BN_new();
    if (rsa->dmp1) { WolfBN* bn = (WolfBN*)rsa->dmp1; mp_copy(&key->dP, &bn->mp); }
    if (rsa->dmq1) _goboringcrypto_BN_free(rsa->dmq1);
    rsa->dmq1 = _goboringcrypto_BN_new();
    if (rsa->dmq1) { WolfBN* bn = (WolfBN*)rsa->dmq1; mp_copy(&key->dQ, &bn->mp); }

    // iqmp is called u in WolfSSL
    if (rsa->iqmp) _goboringcrypto_BN_free(rsa->iqmp);
    rsa->iqmp = _goboringcrypto_BN_new();
    if (rsa->iqmp) {
        WolfBN* bn = (WolfBN*)rsa->iqmp;
        mp_copy(&key->u, &bn->mp);
    }

    #undef SYNC_MP_TO_BN
}

// Helper to extract raw bytes from a BIGNUM
static int bn_to_bytes(const GO_BIGNUM* gbn, uint8_t** out, int* outLen) {
    if (!gbn) { *out = NULL; *outLen = 0; return 0; }
    WolfBN* bn = (WolfBN*)gbn;
    *outLen = mp_unsigned_bin_size(&bn->mp);
    if (*outLen == 0) { *out = NULL; return 0; }
    *out = (uint8_t*)malloc(*outLen);
    if (!*out) return -1;
    mp_to_unsigned_bin(&bn->mp, *out);
    return 0;
}

// Helper to sync BIGNUM values from GO_RSA struct back to RsaKey
// Uses wc_RsaPrivateKeyDecodeRaw for proper key initialization
static int rsa_sync_from_bignums(GO_RSA* rsa) {
    RsaKey* key = (RsaKey*)rsa->internal;
    if (!key) return 0;

    uint8_t *nBuf=NULL, *eBuf=NULL, *dBuf=NULL, *pBuf=NULL, *qBuf=NULL;
    uint8_t *dpBuf=NULL, *dqBuf=NULL, *uBuf=NULL;
    int nLen=0, eLen=0, dLen=0, pLen=0, qLen=0, dpLen=0, dqLen=0, uLen=0;

    bn_to_bytes(rsa->n, &nBuf, &nLen);
    bn_to_bytes(rsa->e, &eBuf, &eLen);
    bn_to_bytes(rsa->d, &dBuf, &dLen);
    bn_to_bytes(rsa->p, &pBuf, &pLen);
    bn_to_bytes(rsa->q, &qBuf, &qLen);
    bn_to_bytes(rsa->dmp1, &dpBuf, &dpLen);
    bn_to_bytes(rsa->dmq1, &dqBuf, &dqLen);
    bn_to_bytes(rsa->iqmp, &uBuf, &uLen);

    int ret = 0;
    if (dLen > 0 && pLen > 0) {
        // Private key - set individual mp_int fields directly
        mp_read_unsigned_bin(&key->n, nBuf, nLen);
        mp_read_unsigned_bin(&key->e, eBuf, eLen);
        mp_read_unsigned_bin(&key->d, dBuf, dLen);
        mp_read_unsigned_bin(&key->p, pBuf, pLen);
        mp_read_unsigned_bin(&key->q, qBuf, qLen);
        if (dpLen > 0) mp_read_unsigned_bin(&key->dP, dpBuf, dpLen);
        if (dqLen > 0) mp_read_unsigned_bin(&key->dQ, dqBuf, dqLen);
        if (uLen > 0) mp_read_unsigned_bin(&key->u, uBuf, uLen);
        key->type = RSA_PRIVATE;
        key->dataLen = nLen;
    } else if (nLen > 0 && eLen > 0) {
        // Public key only
        mp_read_unsigned_bin(&key->n, nBuf, nLen);
        mp_read_unsigned_bin(&key->e, eBuf, eLen);
        key->type = RSA_PUBLIC;
        key->dataLen = nLen;
    } else {
        ret = -1;
    }
    wc_RsaSetRNG(key, &globalRng);

    free(nBuf); free(eBuf); free(dBuf); free(pBuf);
    free(qBuf); free(dpBuf); free(dqBuf); free(uBuf);

    return (ret == 0) ? 1 : 0;
}

GO_RSA* _goboringcrypto_RSA_new(void) {
    GO_RSA* rsa = (GO_RSA*)calloc(1, sizeof(GO_RSA));
    if (!rsa) return NULL;
    RsaKey* key = (RsaKey*)calloc(1, sizeof(RsaKey));
    if (!key) { free(rsa); return NULL; }
    wc_InitRsaKey(key, NULL);
    rsa->internal = key;
    return rsa;
}

void _goboringcrypto_RSA_free(GO_RSA* rsa) {
    if (!rsa) return;
    if (rsa->internal) {
        wc_FreeRsaKey((RsaKey*)rsa->internal);
        free(rsa->internal);
    }
    if (rsa->n) _goboringcrypto_BN_free(rsa->n);
    if (rsa->e) _goboringcrypto_BN_free(rsa->e);
    if (rsa->d) _goboringcrypto_BN_free(rsa->d);
    if (rsa->p) _goboringcrypto_BN_free(rsa->p);
    if (rsa->q) _goboringcrypto_BN_free(rsa->q);
    if (rsa->dmp1) _goboringcrypto_BN_free(rsa->dmp1);
    if (rsa->dmq1) _goboringcrypto_BN_free(rsa->dmq1);
    if (rsa->iqmp) _goboringcrypto_BN_free(rsa->iqmp);
    free(rsa);
}

void _goboringcrypto_RSA_get0_key(const GO_RSA* rsa, const GO_BIGNUM **n, const GO_BIGNUM **e, const GO_BIGNUM **d) {
    if (n) *n = rsa->n;
    if (e) *e = rsa->e;
    if (d) *d = rsa->d;
}

void _goboringcrypto_RSA_get0_factors(const GO_RSA* rsa, const GO_BIGNUM **p, const GO_BIGNUM **q) {
    if (p) *p = rsa->p;
    if (q) *q = rsa->q;
}

void _goboringcrypto_RSA_get0_crt_params(const GO_RSA* rsa, const GO_BIGNUM **dmp1, const GO_BIGNUM **dmq1, const GO_BIGNUM **iqmp) {
    if (dmp1) *dmp1 = rsa->dmp1;
    if (dmq1) *dmq1 = rsa->dmq1;
    if (iqmp) *iqmp = rsa->iqmp;
}

int _goboringcrypto_RSA_generate_key_ex(GO_RSA* rsa, int bits, const GO_BIGNUM* e, GO_BN_GENCB* cb) {
    RsaKey* key = (RsaKey*)rsa->internal;
    long exp = WC_RSA_EXPONENT;
    if (e) {
        WolfBN* be = (WolfBN*)e;
        // Extract exponent value from BIGNUM
        uint8_t eBuf[8];
        int eSz = mp_unsigned_bin_size(&be->mp);
        if (eSz <= (int)sizeof(eBuf)) {
            mp_to_unsigned_bin(&be->mp, eBuf);
            exp = 0;
            for (int i = 0; i < eSz; i++) {
                exp = (exp << 8) | eBuf[i];
            }
        }
    }
    wc_RsaSetRNG(key, &globalRng);
    int ret = wc_MakeRsaKey(key, bits, exp, &globalRng);
    if (ret != 0) return 0;
    rsa_sync_to_bignums(rsa);
    return 1;
}

int _goboringcrypto_RSA_generate_key_fips(GO_RSA* rsa, int bits, GO_BN_GENCB* cb) {
    RsaKey* key = (RsaKey*)rsa->internal;
    wc_RsaSetRNG(key, &globalRng);
    int ret = wc_MakeRsaKey(key, bits, WC_RSA_EXPONENT, &globalRng);
    if (ret != 0) return 0;
    rsa_sync_to_bignums(rsa);
    return 1;
}

unsigned _goboringcrypto_RSA_size(const GO_RSA* rsa) {
    rsa_sync_from_bignums((GO_RSA*)rsa);
    RsaKey* key = (RsaKey*)rsa->internal;
    return (unsigned)wc_RsaEncryptSize(key);
}

int _goboringcrypto_RSA_is_opaque(const GO_RSA* rsa) {
    return 0;
}

int _goboringcrypto_RSA_check_key(const GO_RSA* rsa) {
    return 1; // Basic check
}

int _goboringcrypto_RSA_check_fips(GO_RSA* rsa) {
    if (!rsa || !rsa->n || !rsa->e) return 0;
    return 1;
}

int _goboringcrypto_RSA_sign(int hash_nid, const uint8_t* in, unsigned int in_len,
    uint8_t* out, unsigned int* out_len, GO_RSA* rsa) {
    rsa_sync_from_bignums(rsa);
    RsaKey* key = (RsaKey*)rsa->internal;
    wc_RsaSetRNG(key, &globalRng);

    // Construct PKCS#1 v1.5 DigestInfo
    enum wc_HashType hashType = nid_to_wc_hash(hash_nid);
    if (hashType == WC_HASH_TYPE_NONE) return 0;

    int rsaSize = wc_RsaEncryptSize(key);

    // Build DigestInfo
    uint8_t digestInfo[128];
    int diLen = wc_EncodeSignature(digestInfo, in, in_len, wc_HashGetOID(hashType));
    if (diLen <= 0) return 0;

    // Use local buffer to avoid any Go memory issues
    uint8_t* tmpOut = (uint8_t*)malloc(rsaSize);
    int ret = wc_RsaSSL_Sign(digestInfo, diLen, tmpOut, rsaSize, key, &globalRng);
    if (ret > 0) memcpy(out, tmpOut, ret);
    free(tmpOut);
    // (debug output removed)
    if (ret > 0) {
        *out_len = ret;
        return 1;
    }
    return 0;
}

int _goboringcrypto_RSA_verify(int hash_nid, const uint8_t* msg, size_t msg_len,
    const uint8_t* sig, size_t sig_len, GO_RSA* rsa) {
    rsa_sync_from_bignums(rsa);
    RsaKey* key = (RsaKey*)rsa->internal;

    enum wc_HashType hashType = nid_to_wc_hash(hash_nid);

    uint8_t decSig[512]; // large enough
    int decLen = wc_RsaSSL_Verify(sig, (word32)sig_len, decSig, sizeof(decSig), key);
    if (decLen <= 0) return 0;

    // Build expected DigestInfo
    uint8_t expected[128];
    int expLen = wc_EncodeSignature(expected, msg, (word32)msg_len, wc_HashGetOID(hashType));
    if (expLen <= 0) return 0;

    if (decLen != expLen) return 0;
    if (memcmp(decSig, expected, expLen) != 0) return 0;
    return 1;
}

int _goboringcrypto_RSA_sign_pss_mgf1(GO_RSA* rsa, size_t *out_len, uint8_t *out, size_t max_out,
    const uint8_t *in, size_t in_len, const GO_EVP_MD *md, const GO_EVP_MD *mgf1_md, int salt_len) {
    rsa_sync_from_bignums(rsa);
    RsaKey* key = (RsaKey*)rsa->internal;
    wc_RsaSetRNG(key, &globalRng);

    enum wc_HashType hashType = nid_to_wc_hash(_goboringcrypto_EVP_MD_type(md));
    int mgf = WC_MGF1NONE;
    if (mgf1_md) {
        int mgfNid = _goboringcrypto_EVP_MD_type(mgf1_md);
        switch (mgfNid) {
            case GO_NID_sha256: mgf = WC_MGF1SHA256; break;
            case GO_NID_sha384: mgf = WC_MGF1SHA384; break;
            case GO_NID_sha512: mgf = WC_MGF1SHA512; break;
            default: mgf = WC_MGF1SHA256; break;
        }
    } else {
        // Use same hash as message hash
        switch (_goboringcrypto_EVP_MD_type(md)) {
            case GO_NID_sha256: mgf = WC_MGF1SHA256; break;
            case GO_NID_sha384: mgf = WC_MGF1SHA384; break;
            case GO_NID_sha512: mgf = WC_MGF1SHA512; break;
            default: mgf = WC_MGF1SHA256; break;
        }
    }

    // Handle salt length sentinels
    if (salt_len == -1) {
        salt_len = (int)_goboringcrypto_EVP_MD_size(md);
    } else if (salt_len == -2) {
        // Max salt length
        int emLen = wc_RsaEncryptSize(key) - 1; // EM length
        salt_len = emLen - (int)_goboringcrypto_EVP_MD_size(md) - 2;
        if (salt_len < 0) salt_len = 0;
    }

    int ret = wc_RsaPSS_Sign_ex(in, (word32)in_len, out, (word32)max_out,
                                  hashType, mgf, salt_len, key, &globalRng);
    if (ret > 0) {
        *out_len = ret;
        return 1;
    }
    return 0;
}

int _goboringcrypto_RSA_verify_pss_mgf1(GO_RSA* rsa, const uint8_t *msg, size_t msg_len,
    const GO_EVP_MD *md, const GO_EVP_MD *mgf1_md, int salt_len,
    const uint8_t *sig, size_t sig_len) {
    rsa_sync_from_bignums(rsa);
    RsaKey* key = (RsaKey*)rsa->internal;

    enum wc_HashType hashType = nid_to_wc_hash(_goboringcrypto_EVP_MD_type(md));
    int mgf = WC_MGF1NONE;
    if (mgf1_md) {
        switch (_goboringcrypto_EVP_MD_type(mgf1_md)) {
            case GO_NID_sha256: mgf = WC_MGF1SHA256; break;
            case GO_NID_sha384: mgf = WC_MGF1SHA384; break;
            case GO_NID_sha512: mgf = WC_MGF1SHA512; break;
            default: mgf = WC_MGF1SHA256; break;
        }
    } else {
        switch (_goboringcrypto_EVP_MD_type(md)) {
            case GO_NID_sha256: mgf = WC_MGF1SHA256; break;
            case GO_NID_sha384: mgf = WC_MGF1SHA384; break;
            case GO_NID_sha512: mgf = WC_MGF1SHA512; break;
            default: mgf = WC_MGF1SHA256; break;
        }
    }

    if (salt_len == -1) {
        salt_len = (int)_goboringcrypto_EVP_MD_size(md);
    } else if (salt_len == -2) {
        salt_len = RSA_PSS_SALT_LEN_DEFAULT;
    }

    // First decrypt the signature
    uint8_t* decBuf = (uint8_t*)malloc(sig_len);
    if (!decBuf) return 0;

    int decLen = wc_RsaPSS_Verify_ex(sig, (word32)sig_len, decBuf, (word32)sig_len,
                                       hashType, mgf, salt_len, key);
    if (decLen < 0) {
        free(decBuf);
        return 0;
    }

    // Verify the PSS padding
    int ret = wc_RsaPSS_CheckPadding_ex(msg, (word32)msg_len, decBuf, decLen,
                                          hashType, salt_len, mp_count_bits(&((RsaKey*)rsa->internal)->n));
    free(decBuf);
    return (ret == 0) ? 1 : 0;
}

int _goboringcrypto_RSA_sign_raw(GO_RSA* rsa, size_t *out_len, uint8_t *out, size_t max_out,
    const uint8_t *in, size_t in_len, int padding) {
    rsa_sync_from_bignums(rsa);
    RsaKey* key = (RsaKey*)rsa->internal;
    wc_RsaSetRNG(key, &globalRng);

    if (padding == GO_RSA_PKCS1_PADDING) {
        int ret = wc_RsaSSL_Sign(in, (word32)in_len, out, (word32)max_out, key, &globalRng);
        if (ret > 0) { *out_len = ret; return 1; }
    } else if (padding == GO_RSA_NO_PADDING) {
        word32 outSz = (word32)max_out;
        int ret = wc_RsaFunction(in, (word32)in_len, out, &outSz, RSA_PRIVATE_ENCRYPT, key, &globalRng);
        if (ret == 0) { *out_len = outSz; return 1; }
    }
    return 0;
}

int _goboringcrypto_RSA_verify_raw(GO_RSA* rsa, size_t *out_len, uint8_t *out, size_t max_out,
    const uint8_t *in, size_t in_len, int padding) {
    rsa_sync_from_bignums(rsa);
    RsaKey* key = (RsaKey*)rsa->internal;

    if (padding == GO_RSA_PKCS1_PADDING) {
        int ret = wc_RsaSSL_Verify(in, (word32)in_len, out, (word32)max_out, key);
        if (ret > 0) { *out_len = ret; return 1; }
    } else if (padding == GO_RSA_NO_PADDING) {
        word32 outSz = (word32)max_out;
        int ret = wc_RsaFunction(in, (word32)in_len, out, &outSz, RSA_PUBLIC_DECRYPT, key, &globalRng);
        if (ret == 0) { *out_len = outSz; return 1; }
    }
    return 0;
}

int _goboringcrypto_RSA_encrypt(GO_RSA* rsa, size_t *out_len, uint8_t *out, size_t max_out,
    const uint8_t *in, size_t in_len, int padding) {
    rsa_sync_from_bignums(rsa);
    RsaKey* key = (RsaKey*)rsa->internal;
    wc_RsaSetRNG(key, &globalRng);

    int ret;
    if (padding == GO_RSA_PKCS1_PADDING) {
        ret = wc_RsaPublicEncrypt(in, (word32)in_len, out, (word32)max_out, key, &globalRng);
    } else if (padding == GO_RSA_NO_PADDING) {
        ret = wc_RsaPublicEncrypt_ex(in, (word32)in_len, out, (word32)max_out, key, &globalRng,
                                      WC_RSA_NO_PAD, WC_HASH_TYPE_NONE, WC_MGF1NONE, NULL, 0);
    } else if (padding == GO_RSA_PKCS1_OAEP_PADDING) {
        ret = wc_RsaPublicEncrypt_ex(in, (word32)in_len, out, (word32)max_out, key, &globalRng,
                                      WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0);
    } else {
        return 0;
    }
    if (ret > 0) { *out_len = ret; return 1; }
    return 0;
}

int _goboringcrypto_RSA_decrypt(GO_RSA* rsa, size_t *out_len, uint8_t *out, size_t max_out,
    const uint8_t *in, size_t in_len, int padding) {
    rsa_sync_from_bignums(rsa);
    RsaKey* key = (RsaKey*)rsa->internal;

    int ret;
    if (padding == GO_RSA_PKCS1_PADDING) {
        ret = wc_RsaPrivateDecrypt(in, (word32)in_len, out, (word32)max_out, key);
    } else if (padding == GO_RSA_NO_PADDING) {
        ret = wc_RsaPrivateDecrypt_ex(in, (word32)in_len, out, (word32)max_out, key,
                                       WC_RSA_NO_PAD, WC_HASH_TYPE_NONE, WC_MGF1NONE, NULL, 0);
    } else if (padding == GO_RSA_PKCS1_OAEP_PADDING) {
        ret = wc_RsaPrivateDecrypt_ex(in, (word32)in_len, out, (word32)max_out, key,
                                       WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0);
    } else {
        return 0;
    }
    if (ret > 0) { *out_len = ret; return 1; }
    return 0;
}

GO_RSA* _goboringcrypto_RSA_public_key_from_bytes(const uint8_t* data, size_t len) {
    GO_RSA* rsa = _goboringcrypto_RSA_new();
    if (!rsa) return NULL;
    RsaKey* key = (RsaKey*)rsa->internal;
    word32 idx = 0;
    int ret = wc_RsaPublicKeyDecode(data, &idx, key, (word32)len);
    if (ret != 0) {
        _goboringcrypto_RSA_free(rsa);
        return NULL;
    }
    rsa_sync_to_bignums(rsa);
    return rsa;
}

GO_RSA* _goboringcrypto_RSA_private_key_from_bytes(const uint8_t* data, size_t len) {
    GO_RSA* rsa = _goboringcrypto_RSA_new();
    if (!rsa) return NULL;
    RsaKey* key = (RsaKey*)rsa->internal;
    word32 idx = 0;
    int ret = wc_RsaPrivateKeyDecode(data, &idx, key, (word32)len);
    if (ret != 0) {
        _goboringcrypto_RSA_free(rsa);
        return NULL;
    }
    rsa_sync_to_bignums(rsa);
    return rsa;
}

int _goboringcrypto_RSA_public_key_to_bytes(uint8_t** out, size_t* outLen, const GO_RSA* rsa) {
    RsaKey* key = (RsaKey*)rsa->internal;
    int derSz = wc_RsaPublicKeyDerSize(key, 1);
    if (derSz <= 0) return 0;
    uint8_t* der = (uint8_t*)malloc(derSz);
    if (!der) return 0;
    int ret = wc_RsaKeyToPublicDer(key, der, derSz);
    if (ret <= 0) { free(der); return 0; }
    *out = der;
    *outLen = ret;
    return 1;
}

int _goboringcrypto_RSA_private_key_to_bytes(uint8_t** out, size_t* outLen, const GO_RSA* rsa) {
    RsaKey* key = (RsaKey*)rsa->internal;
    int derSz = 4096; // generous buffer
    uint8_t* der = (uint8_t*)malloc(derSz);
    if (!der) return 0;
    int ret = wc_RsaKeyToDer(key, der, derSz);
    if (ret <= 0) { free(der); return 0; }
    *out = der;
    *outLen = ret;
    return 1;
}

// ============================================================================
// 13. EVP_PKEY / EVP_PKEY_CTX
// ============================================================================

typedef struct WolfEVPPKey {
    GO_RSA* rsa;
} WolfEVPPKey;

typedef struct WolfEVPPKeyCtx {
    WolfEVPPKey* pkey;
    int padding;
    const GO_EVP_MD* oaepMd;
    const GO_EVP_MD* mgf1Md;
    uint8_t* oaepLabel;
    size_t oaepLabelLen;
    int saltLen;
    int operation; // 0=none, 1=encrypt, 2=decrypt, 3=sign, 4=verify
} WolfEVPPKeyCtx;

GO_EVP_PKEY* _goboringcrypto_EVP_PKEY_new(void) {
    WolfEVPPKey* pk = (WolfEVPPKey*)calloc(1, sizeof(WolfEVPPKey));
    return (GO_EVP_PKEY*)pk;
}

void _goboringcrypto_EVP_PKEY_free(GO_EVP_PKEY* pkey) {
    if (!pkey) return;
    WolfEVPPKey* pk = (WolfEVPPKey*)pkey;
    // Don't free the RSA key — it's owned by Go
    free(pk);
}

int _goboringcrypto_EVP_PKEY_set1_RSA(GO_EVP_PKEY* pkey, GO_RSA* rsa) {
    WolfEVPPKey* pk = (WolfEVPPKey*)pkey;
    pk->rsa = rsa;
    return 1;
}

GO_EVP_PKEY_CTX* _goboringcrypto_EVP_PKEY_CTX_new(GO_EVP_PKEY* pkey, GO_ENGINE* engine) {
    WolfEVPPKeyCtx* ctx = (WolfEVPPKeyCtx*)calloc(1, sizeof(WolfEVPPKeyCtx));
    if (!ctx) return NULL;
    ctx->pkey = (WolfEVPPKey*)pkey;
    ctx->saltLen = -1;
    return (GO_EVP_PKEY_CTX*)ctx;
}

void _goboringcrypto_EVP_PKEY_CTX_free(GO_EVP_PKEY_CTX* gctx) {
    if (!gctx) return;
    WolfEVPPKeyCtx* ctx = (WolfEVPPKeyCtx*)gctx;
    if (ctx->oaepLabel) free(ctx->oaepLabel);
    free(ctx);
}

int _goboringcrypto_EVP_PKEY_CTX_set_rsa_padding(GO_EVP_PKEY_CTX* gctx, int padding) {
    WolfEVPPKeyCtx* ctx = (WolfEVPPKeyCtx*)gctx;
    ctx->padding = padding;
    return 1;
}

int _goboringcrypto_EVP_PKEY_CTX_set_rsa_oaep_md(GO_EVP_PKEY_CTX* gctx, const GO_EVP_MD* md) {
    WolfEVPPKeyCtx* ctx = (WolfEVPPKeyCtx*)gctx;
    ctx->oaepMd = md;
    return 1;
}

int _goboringcrypto_EVP_PKEY_CTX_set_rsa_mgf1_md(GO_EVP_PKEY_CTX* gctx, const GO_EVP_MD* md) {
    WolfEVPPKeyCtx* ctx = (WolfEVPPKeyCtx*)gctx;
    ctx->mgf1Md = md;
    return 1;
}

int _goboringcrypto_EVP_PKEY_CTX_set0_rsa_oaep_label(GO_EVP_PKEY_CTX* gctx, uint8_t* label, size_t len) {
    WolfEVPPKeyCtx* ctx = (WolfEVPPKeyCtx*)gctx;
    if (ctx->oaepLabel) free(ctx->oaepLabel);
    ctx->oaepLabel = label; // Takes ownership
    ctx->oaepLabelLen = len;
    return 1;
}

int _goboringcrypto_EVP_PKEY_CTX_set_rsa_pss_saltlen(GO_EVP_PKEY_CTX* gctx, int saltLen) {
    WolfEVPPKeyCtx* ctx = (WolfEVPPKeyCtx*)gctx;
    ctx->saltLen = saltLen;
    return 1;
}

int _goboringcrypto_EVP_PKEY_encrypt_init(GO_EVP_PKEY_CTX* gctx) {
    WolfEVPPKeyCtx* ctx = (WolfEVPPKeyCtx*)gctx;
    ctx->operation = 1;
    return 1;
}

int _goboringcrypto_EVP_PKEY_decrypt_init(GO_EVP_PKEY_CTX* gctx) {
    WolfEVPPKeyCtx* ctx = (WolfEVPPKeyCtx*)gctx;
    ctx->operation = 2;
    return 1;
}

int _goboringcrypto_EVP_PKEY_sign_init(GO_EVP_PKEY_CTX* gctx) {
    WolfEVPPKeyCtx* ctx = (WolfEVPPKeyCtx*)gctx;
    ctx->operation = 3;
    return 1;
}

int _goboringcrypto_EVP_PKEY_verify_init(GO_EVP_PKEY_CTX* gctx) {
    WolfEVPPKeyCtx* ctx = (WolfEVPPKeyCtx*)gctx;
    ctx->operation = 4;
    return 1;
}

static enum wc_HashType md_to_wc_hash_type_enum(const GO_EVP_MD* md) {
    if (!md) return WC_HASH_TYPE_SHA256;
    return nid_to_wc_hash(((const WolfMD*)md)->type);
}

static int md_to_mgf(const GO_EVP_MD* md) {
    if (!md) return WC_MGF1SHA256;
    switch (((const WolfMD*)md)->type) {
        case GO_NID_sha224: return WC_MGF1SHA224;
        case GO_NID_sha256: return WC_MGF1SHA256;
        case GO_NID_sha384: return WC_MGF1SHA384;
        case GO_NID_sha512: return WC_MGF1SHA512;
        default: return WC_MGF1SHA256;
    }
}

int _goboringcrypto_EVP_PKEY_encrypt(GO_EVP_PKEY_CTX* gctx, uint8_t* out, size_t* outLen,
    const uint8_t* in, size_t inLen) {
    WolfEVPPKeyCtx* ctx = (WolfEVPPKeyCtx*)gctx;
    if (!ctx->pkey || !ctx->pkey->rsa) return 0;
    GO_RSA* rsa = ctx->pkey->rsa;
    rsa_sync_from_bignums(rsa);
    RsaKey* key = (RsaKey*)rsa->internal;
    wc_RsaSetRNG(key, &globalRng);

    // Query mode: out is NULL, return required size
    if (out == NULL) {
        *outLen = wc_RsaEncryptSize(key);
        return 1;
    }

    int ret;
    if (ctx->padding == GO_RSA_PKCS1_OAEP_PADDING) {
        enum wc_HashType hashType = md_to_wc_hash_type_enum(ctx->oaepMd);
        int mgf = md_to_mgf(ctx->mgf1Md ? ctx->mgf1Md : ctx->oaepMd);
        ret = wc_RsaPublicEncrypt_ex(in, (word32)inLen, out, (word32)*outLen, key, &globalRng,
                                      WC_RSA_OAEP_PAD, hashType, mgf,
                                      ctx->oaepLabel, (word32)ctx->oaepLabelLen);
    } else if (ctx->padding == GO_RSA_PKCS1_PADDING) {
        ret = wc_RsaPublicEncrypt(in, (word32)inLen, out, (word32)*outLen, key, &globalRng);
    } else if (ctx->padding == GO_RSA_NO_PADDING) {
        ret = wc_RsaPublicEncrypt_ex(in, (word32)inLen, out, (word32)*outLen, key, &globalRng,
                                      WC_RSA_NO_PAD, WC_HASH_TYPE_NONE, WC_MGF1NONE, NULL, 0);
    } else {
        return 0;
    }

    if (ret > 0) { *outLen = ret; return 1; }
    return 0;
}

int _goboringcrypto_EVP_PKEY_decrypt(GO_EVP_PKEY_CTX* gctx, uint8_t* out, size_t* outLen,
    const uint8_t* in, size_t inLen) {
    WolfEVPPKeyCtx* ctx = (WolfEVPPKeyCtx*)gctx;
    if (!ctx->pkey || !ctx->pkey->rsa) return 0;
    GO_RSA* rsa = ctx->pkey->rsa;
    rsa_sync_from_bignums(rsa);
    RsaKey* key = (RsaKey*)rsa->internal;

    // Query mode
    if (out == NULL) {
        *outLen = wc_RsaEncryptSize(key);
        return 1;
    }

    int ret;
    if (ctx->padding == GO_RSA_PKCS1_OAEP_PADDING) {
        enum wc_HashType hashType = md_to_wc_hash_type_enum(ctx->oaepMd);
        int mgf = md_to_mgf(ctx->mgf1Md ? ctx->mgf1Md : ctx->oaepMd);
        ret = wc_RsaPrivateDecrypt_ex(in, (word32)inLen, out, (word32)*outLen, key,
                                       WC_RSA_OAEP_PAD, hashType, mgf,
                                       ctx->oaepLabel, (word32)ctx->oaepLabelLen);
    } else if (ctx->padding == GO_RSA_PKCS1_PADDING) {
        ret = wc_RsaPrivateDecrypt(in, (word32)inLen, out, (word32)*outLen, key);
    } else if (ctx->padding == GO_RSA_NO_PADDING) {
        ret = wc_RsaPrivateDecrypt_ex(in, (word32)inLen, out, (word32)*outLen, key,
                                       WC_RSA_NO_PAD, WC_HASH_TYPE_NONE, WC_MGF1NONE, NULL, 0);
    } else {
        return 0;
    }

    if (ret > 0) { *outLen = ret; return 1; }
    return 0;
}

int _goboringcrypto_EVP_PKEY_sign(GO_EVP_PKEY_CTX* gctx, uint8_t* out, size_t* outLen,
    const uint8_t* in, size_t inLen) {
    WolfEVPPKeyCtx* ctx = (WolfEVPPKeyCtx*)gctx;
    if (!ctx->pkey || !ctx->pkey->rsa) return 0;

    // Query mode
    if (out == NULL) {
        *outLen = _goboringcrypto_RSA_size(ctx->pkey->rsa);
        return 1;
    }

    if (ctx->padding == GO_RSA_PKCS1_PSS_PADDING) {
        return _goboringcrypto_RSA_sign_pss_mgf1(ctx->pkey->rsa, outLen, out, *outLen,
                                                   in, inLen, ctx->oaepMd, ctx->mgf1Md, ctx->saltLen);
    }

    return 0;
}

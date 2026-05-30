# Thinking: Swapping BoringSSL for WolfSSL in Go's Crypto Backend

## 1. Architecture Overview of Go's BoringCrypto Integration

### 1.1 Three-Layer Design

The Go BoringCrypto integration uses a three-layer architecture:

**Layer 1 — Pre-built `.syso` object files:**
- Located at `src/crypto/internal/boring/syso/goboringcrypto_linux_{amd64,arm64}.syso`
- Built from BoringSSL's `libcrypto.a` with all symbols prefixed `_goboringcrypto_` via `objcopy --redefine-syms`
- Linked directly into the Go binary at build time
- Only supported on `linux/{amd64,arm64}`

**Layer 2 — `goboringcrypto.h` header:**
- A standalone C header (258 lines) at `src/crypto/internal/boring/goboringcrypto.h`
- Declares `_goboringcrypto_`-prefixed function prototypes
- Defines opaque struct typedefs with fixed-size `char data[N]` bodies (sizes must match BoringSSL exactly)
- **No BoringSSL headers are needed at Go build time** — this is the entire C interface

**Layer 3 — Go files with cgo:**
- Each `.go` file does `#include "goboringcrypto.h"` in a cgo preamble
- Calls C functions via cgo's `C.` namespace
- Build constraint: `//go:build boringcrypto && linux && (amd64 || arm64) && !android && !msan`

### 1.2 Build Process (build-goboring.sh)

1. An AWK script parses `goboringcrypto.h` and generates a C++ verification program
2. The verification program checks that:
   - Struct sizes match actual BoringSSL structs
   - Function prototypes match actual BoringSSL functions
3. `ld -r` links `libcrypto.a` into a single object file
4. `objcopy` renames symbols with `_goboringcrypto_` prefix and hides non-exported symbols
5. Result: `goboringcrypto_linux_{amd64,arm64}.syso`

### 1.3 FIPS Enforcement

On init:
```go
func init() {
    C._goboringcrypto_BORINGSSL_bcm_power_on_self_test()
    if C._goboringcrypto_FIPS_mode() != 1 {
        panic("boringcrypto: not in FIPS mode")
    }
}
```

---

## 2. Complete API Surface in goboringcrypto.h

### 2.1 Initialization / FIPS
```c
void _goboringcrypto_BORINGSSL_bcm_power_on_self_test(void);
int _goboringcrypto_FIPS_mode(void);
void* _goboringcrypto_OPENSSL_malloc(size_t);
```

### 2.2 Random Number Generation
```c
int _goboringcrypto_RAND_bytes(uint8_t*, size_t);
```

### 2.3 SHA Hashing

**Struct sizes (BoringSSL-specific):**
- `GO_SHA_CTX`: 96 bytes
- `GO_SHA256_CTX`: 112 bytes (48+64)
- `GO_SHA512_CTX`: 216 bytes (88+128)

**Functions:**
```c
// SHA-1
int _goboringcrypto_SHA1_Init(GO_SHA_CTX*);
int _goboringcrypto_SHA1_Update(GO_SHA_CTX*, const void*, size_t);
int _goboringcrypto_SHA1_Final(uint8_t*, GO_SHA_CTX*);

// SHA-224 (uses GO_SHA256_CTX)
int _goboringcrypto_SHA224_Init(GO_SHA256_CTX*);
int _goboringcrypto_SHA224_Update(GO_SHA256_CTX*, const void*, size_t);
int _goboringcrypto_SHA224_Final(uint8_t*, GO_SHA256_CTX*);

// SHA-256
int _goboringcrypto_SHA256_Init(GO_SHA256_CTX*);
int _goboringcrypto_SHA256_Update(GO_SHA256_CTX*, const void*, size_t);
int _goboringcrypto_SHA256_Final(uint8_t*, GO_SHA256_CTX*);

// SHA-384 (uses GO_SHA512_CTX)
int _goboringcrypto_SHA384_Init(GO_SHA512_CTX*);
int _goboringcrypto_SHA384_Update(GO_SHA512_CTX*, const void*, size_t);
int _goboringcrypto_SHA384_Final(uint8_t*, GO_SHA512_CTX*);

// SHA-512
int _goboringcrypto_SHA512_Init(GO_SHA512_CTX*);
int _goboringcrypto_SHA512_Update(GO_SHA512_CTX*, const void*, size_t);
int _goboringcrypto_SHA512_Final(uint8_t*, GO_SHA512_CTX*);
```

**Return convention:** All return `int`, where 1 = success, 0 = failure.

**Critical detail for MarshalBinary/UnmarshalBinary:** The Go code casts the opaque `GO_SHA*_CTX` to Go struct types and directly reads/writes internal hash state fields (h[0..4], nl, nh, x[0..63], nx). The struct layouts MUST match exactly:
- `sha1Ctx`: `h [5]uint32; nl, nh uint32; x [64]byte; nx uint32` — total 96 bytes ✓
- `sha256Ctx`: `h [8]uint32; nl, nh uint32; x [64]byte; nx uint32` — total 112 bytes ✓
- `sha512Ctx`: `h [8]uint64; nl, nh uint64; x [128]byte; nx uint32` — total 216 bytes ✓

### 2.4 EVP_MD (Message Digest Descriptors)
```c
typedef struct GO_EVP_MD { char data[1]; } GO_EVP_MD;  // opaque
const GO_EVP_MD* _goboringcrypto_EVP_md4(void);
const GO_EVP_MD* _goboringcrypto_EVP_md5(void);
const GO_EVP_MD* _goboringcrypto_EVP_md5_sha1(void);
const GO_EVP_MD* _goboringcrypto_EVP_sha1(void);
const GO_EVP_MD* _goboringcrypto_EVP_sha224(void);
const GO_EVP_MD* _goboringcrypto_EVP_sha256(void);
const GO_EVP_MD* _goboringcrypto_EVP_sha384(void);
const GO_EVP_MD* _goboringcrypto_EVP_sha512(void);
int _goboringcrypto_EVP_MD_type(const GO_EVP_MD*);
size_t _goboringcrypto_EVP_MD_size(const GO_EVP_MD*);
```

### 2.5 HMAC

**Struct size:** `GO_HMAC_CTX`: 104 bytes

```c
void _goboringcrypto_HMAC_CTX_init(GO_HMAC_CTX*);
void _goboringcrypto_HMAC_CTX_cleanup(GO_HMAC_CTX*);
int _goboringcrypto_HMAC_Init(GO_HMAC_CTX*, const void*, int, const GO_EVP_MD*);
int _goboringcrypto_HMAC_Update(GO_HMAC_CTX*, const uint8_t*, size_t);
int _goboringcrypto_HMAC_Final(GO_HMAC_CTX*, uint8_t*, unsigned int*);
size_t _goboringcrypto_HMAC_size(const GO_HMAC_CTX*);
int _goboringcrypto_HMAC_CTX_copy_ex(GO_HMAC_CTX *dest, const GO_HMAC_CTX *src);
```

### 2.6 AES

**Struct size:** `GO_AES_KEY`: 244 bytes

```c
int _goboringcrypto_AES_set_encrypt_key(const uint8_t*, unsigned int, GO_AES_KEY*);
int _goboringcrypto_AES_set_decrypt_key(const uint8_t*, unsigned int, GO_AES_KEY*);
void _goboringcrypto_AES_encrypt(const uint8_t*, uint8_t*, const GO_AES_KEY*);
void _goboringcrypto_AES_decrypt(const uint8_t*, uint8_t*, const GO_AES_KEY*);
void _goboringcrypto_AES_ctr128_encrypt(const uint8_t*, uint8_t*, size_t, const GO_AES_KEY*, uint8_t*, uint8_t*, unsigned int*);
void _goboringcrypto_AES_cbc_encrypt(const uint8_t*, uint8_t*, size_t, const GO_AES_KEY*, uint8_t*, const int);
```

**Note:** `AES_set_encrypt_key`/`AES_set_decrypt_key` return 0 on success (opposite of most BoringSSL conventions).

### 2.7 AEAD (AES-GCM)

**Struct sizes:**
- `GO_EVP_AEAD`: opaque (1 byte placeholder)
- `GO_ENGINE`: opaque (1 byte placeholder)
- `GO_EVP_AEAD_CTX`: 600 bytes

```c
const GO_EVP_AEAD* _goboringcrypto_EVP_aead_aes_128_gcm(void);
const GO_EVP_AEAD* _goboringcrypto_EVP_aead_aes_256_gcm(void);
const GO_EVP_AEAD* _goboringcrypto_EVP_aead_aes_128_gcm_tls12(void);
const GO_EVP_AEAD* _goboringcrypto_EVP_aead_aes_128_gcm_tls13(void);
const GO_EVP_AEAD* _goboringcrypto_EVP_aead_aes_256_gcm_tls12(void);
const GO_EVP_AEAD* _goboringcrypto_EVP_aead_aes_256_gcm_tls13(void);

size_t _goboringcrypto_EVP_AEAD_key_length(const GO_EVP_AEAD*);
size_t _goboringcrypto_EVP_AEAD_nonce_length(const GO_EVP_AEAD*);
size_t _goboringcrypto_EVP_AEAD_max_overhead(const GO_EVP_AEAD*);
size_t _goboringcrypto_EVP_AEAD_max_tag_len(const GO_EVP_AEAD*);

void _goboringcrypto_EVP_AEAD_CTX_zero(GO_EVP_AEAD_CTX*);
int _goboringcrypto_EVP_AEAD_CTX_init(GO_EVP_AEAD_CTX*, const GO_EVP_AEAD*, const uint8_t*, size_t, size_t, GO_ENGINE*);
void _goboringcrypto_EVP_AEAD_CTX_cleanup(GO_EVP_AEAD_CTX*);
int _goboringcrypto_EVP_AEAD_CTX_seal(const GO_EVP_AEAD_CTX*, uint8_t*, size_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t);
int _goboringcrypto_EVP_AEAD_CTX_open(const GO_EVP_AEAD_CTX*, uint8_t*, size_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t);
int _goboringcrypto_EVP_AEAD_CTX_init_with_direction(GO_EVP_AEAD_CTX*, const GO_EVP_AEAD*, const uint8_t*, size_t, size_t, enum go_evp_aead_direction_t);
```

**This is a MAJOR challenge:** BoringSSL's AEAD API (`EVP_AEAD_*`) is **BoringSSL-specific** and does NOT exist in standard OpenSSL or WolfSSL. WolfSSL provides AES-GCM through its native `wc_AesGcm*` API instead.

### 2.8 BIGNUM
```c
typedef struct GO_BIGNUM { char data[24]; } GO_BIGNUM;
GO_BIGNUM* _goboringcrypto_BN_new(void);
void _goboringcrypto_BN_free(GO_BIGNUM*);
unsigned _goboringcrypto_BN_num_bits(const GO_BIGNUM*);
unsigned _goboringcrypto_BN_num_bytes(const GO_BIGNUM*);
int _goboringcrypto_BN_is_negative(const GO_BIGNUM*);
GO_BIGNUM* _goboringcrypto_BN_bin2bn(const uint8_t*, size_t, GO_BIGNUM*);
GO_BIGNUM* _goboringcrypto_BN_le2bn(const uint8_t*, size_t, GO_BIGNUM*);
size_t _goboringcrypto_BN_bn2bin(const GO_BIGNUM*, uint8_t*);
int _goboringcrypto_BN_bn2le_padded(uint8_t*, size_t, const GO_BIGNUM*);
int _goboringcrypto_BN_bn2bin_padded(uint8_t*, size_t, const GO_BIGNUM*);
```

### 2.9 EC (Elliptic Curves)
```c
// Groups
GO_EC_GROUP* _goboringcrypto_EC_GROUP_new_by_curve_name(int);
void _goboringcrypto_EC_GROUP_free(GO_EC_GROUP*);

// Points
GO_EC_POINT* _goboringcrypto_EC_POINT_new(const GO_EC_GROUP*);
void _goboringcrypto_EC_POINT_free(GO_EC_POINT*);
GO_EC_POINT* _goboringcrypto_EC_POINT_dup(const GO_EC_POINT*, const GO_EC_GROUP*);
int _goboringcrypto_EC_POINT_mul(const GO_EC_GROUP*, GO_EC_POINT*, const GO_BIGNUM*, const GO_EC_POINT*, const GO_BIGNUM*, GO_BN_CTX*);
int _goboringcrypto_EC_POINT_get_affine_coordinates_GFp(const GO_EC_GROUP*, const GO_EC_POINT*, GO_BIGNUM*, GO_BIGNUM*, GO_BN_CTX*);
int _goboringcrypto_EC_POINT_set_affine_coordinates_GFp(const GO_EC_GROUP*, GO_EC_POINT*, const GO_BIGNUM*, const GO_BIGNUM*, GO_BN_CTX*);
int _goboringcrypto_EC_POINT_oct2point(const GO_EC_GROUP*, GO_EC_POINT*, const uint8_t*, size_t, GO_BN_CTX*);
int _goboringcrypto_EC_POINT_is_on_curve(const GO_EC_GROUP*, const GO_EC_POINT*, GO_BN_CTX*);
size_t _goboringcrypto_EC_POINT_point2oct(const GO_EC_GROUP*, const GO_EC_POINT*, go_point_conversion_form_t, uint8_t*, size_t, GO_BN_CTX*);

// Keys
GO_EC_KEY* _goboringcrypto_EC_KEY_new(void);
GO_EC_KEY* _goboringcrypto_EC_KEY_new_by_curve_name(int);
void _goboringcrypto_EC_KEY_free(GO_EC_KEY*);
const GO_EC_GROUP* _goboringcrypto_EC_KEY_get0_group(const GO_EC_KEY*);
int _goboringcrypto_EC_KEY_generate_key_fips(GO_EC_KEY*);
int _goboringcrypto_EC_KEY_set_private_key(GO_EC_KEY*, const GO_BIGNUM*);
int _goboringcrypto_EC_KEY_set_public_key(GO_EC_KEY*, const GO_EC_POINT*);
const GO_BIGNUM* _goboringcrypto_EC_KEY_get0_private_key(const GO_EC_KEY*);
const GO_EC_POINT* _goboringcrypto_EC_KEY_get0_public_key(const GO_EC_KEY*);
```

### 2.10 ECDH
```c
int _goboringcrypto_ECDH_compute_key_fips(uint8_t*, size_t, const GO_EC_POINT*, const GO_EC_KEY*);
```
**Note:** This is a BoringSSL-specific FIPS variant. Standard OpenSSL uses `ECDH_compute_key()`.

### 2.11 ECDSA
```c
typedef struct GO_ECDSA_SIG { char data[16]; } GO_ECDSA_SIG;
GO_ECDSA_SIG* _goboringcrypto_ECDSA_SIG_new(void);
void _goboringcrypto_ECDSA_SIG_free(GO_ECDSA_SIG*);
GO_ECDSA_SIG* _goboringcrypto_ECDSA_do_sign(const uint8_t*, size_t, const GO_EC_KEY*);
int _goboringcrypto_ECDSA_do_verify(const uint8_t*, size_t, const GO_ECDSA_SIG*, const GO_EC_KEY*);
int _goboringcrypto_ECDSA_sign(int, const uint8_t*, size_t, uint8_t*, unsigned int*, const GO_EC_KEY*);
size_t _goboringcrypto_ECDSA_size(const GO_EC_KEY*);
int _goboringcrypto_ECDSA_verify(int, const uint8_t*, size_t, const uint8_t*, size_t, const GO_EC_KEY*);
```

### 2.12 RSA
```c
typedef struct GO_RSA { void *meth; GO_BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp; char data[168]; } GO_RSA;

GO_RSA* _goboringcrypto_RSA_new(void);
void _goboringcrypto_RSA_free(GO_RSA*);
void _goboringcrypto_RSA_get0_key(const GO_RSA*, const GO_BIGNUM **n, const GO_BIGNUM **e, const GO_BIGNUM **d);
void _goboringcrypto_RSA_get0_factors(const GO_RSA*, const GO_BIGNUM **p, const GO_BIGNUM **q);
void _goboringcrypto_RSA_get0_crt_params(const GO_RSA*, const GO_BIGNUM **dmp1, const GO_BIGNUM **dmp2, const GO_BIGNUM **iqmp);
int _goboringcrypto_RSA_generate_key_ex(GO_RSA*, int, const GO_BIGNUM*, GO_BN_GENCB*);
int _goboringcrypto_RSA_generate_key_fips(GO_RSA*, int, GO_BN_GENCB*);
int _goboringcrypto_RSA_encrypt(GO_RSA*, size_t*, uint8_t*, size_t, const uint8_t*, size_t, int);
int _goboringcrypto_RSA_decrypt(GO_RSA*, size_t*, uint8_t*, size_t, const uint8_t*, size_t, int);
int _goboringcrypto_RSA_sign(int, const uint8_t*, unsigned int, uint8_t*, unsigned int*, GO_RSA*);
int _goboringcrypto_RSA_verify(int, const uint8_t*, size_t, const uint8_t*, size_t, GO_RSA*);
int _goboringcrypto_RSA_sign_pss_mgf1(GO_RSA*, size_t*, uint8_t*, size_t, const uint8_t*, size_t, const GO_EVP_MD*, const GO_EVP_MD*, int);
int _goboringcrypto_RSA_verify_pss_mgf1(GO_RSA*, const uint8_t*, size_t, const GO_EVP_MD*, const GO_EVP_MD*, int, const uint8_t*, size_t);
int _goboringcrypto_RSA_sign_raw(GO_RSA*, size_t*, uint8_t*, size_t, const uint8_t*, size_t, int);
int _goboringcrypto_RSA_verify_raw(GO_RSA*, size_t*, uint8_t*, size_t, const uint8_t*, size_t, int);
unsigned _goboringcrypto_RSA_size(const GO_RSA*);
int _goboringcrypto_RSA_check_fips(GO_RSA*);
GO_RSA* _goboringcrypto_RSA_public_key_from_bytes(const uint8_t*, size_t);
GO_RSA* _goboringcrypto_RSA_private_key_from_bytes(const uint8_t*, size_t);
int _goboringcrypto_RSA_public_key_to_bytes(uint8_t**, size_t*, const GO_RSA*);
int _goboringcrypto_RSA_private_key_to_bytes(uint8_t**, size_t*, const GO_RSA*);
```

**Critical: GO_RSA struct layout.** The Go code directly accesses `key.n`, `key.e`, `key.d`, `key.p`, `key.q`, `key.dmp1`, `key.dmq1`, `key.iqmp` fields by name! The struct is NOT fully opaque — its field layout (pointer positions) must be compatible.

### 2.13 EVP_PKEY (RSA key wrapper)
```c
GO_EVP_PKEY* _goboringcrypto_EVP_PKEY_new(void);
void _goboringcrypto_EVP_PKEY_free(GO_EVP_PKEY*);
int _goboringcrypto_EVP_PKEY_set1_RSA(GO_EVP_PKEY*, GO_RSA*);

GO_EVP_PKEY_CTX* _goboringcrypto_EVP_PKEY_CTX_new(GO_EVP_PKEY*, GO_ENGINE*);
void _goboringcrypto_EVP_PKEY_CTX_free(GO_EVP_PKEY_CTX*);
int _goboringcrypto_EVP_PKEY_CTX_set0_rsa_oaep_label(GO_EVP_PKEY_CTX*, uint8_t*, size_t);
int _goboringcrypto_EVP_PKEY_CTX_set_rsa_oaep_md(GO_EVP_PKEY_CTX*, const GO_EVP_MD*);
int _goboringcrypto_EVP_PKEY_CTX_set_rsa_padding(GO_EVP_PKEY_CTX*, int);
int _goboringcrypto_EVP_PKEY_decrypt(GO_EVP_PKEY_CTX*, uint8_t*, size_t*, const uint8_t*, size_t);
int _goboringcrypto_EVP_PKEY_encrypt(GO_EVP_PKEY_CTX*, uint8_t*, size_t*, const uint8_t*, size_t);
int _goboringcrypto_EVP_PKEY_decrypt_init(GO_EVP_PKEY_CTX*);
int _goboringcrypto_EVP_PKEY_encrypt_init(GO_EVP_PKEY_CTX*);
int _goboringcrypto_EVP_PKEY_CTX_set_rsa_mgf1_md(GO_EVP_PKEY_CTX*, const GO_EVP_MD*);
int _goboringcrypto_EVP_PKEY_CTX_set_rsa_pss_saltlen(GO_EVP_PKEY_CTX*, int);
int _goboringcrypto_EVP_PKEY_sign_init(GO_EVP_PKEY_CTX*);
int _goboringcrypto_EVP_PKEY_verify_init(GO_EVP_PKEY_CTX*);
int _goboringcrypto_EVP_PKEY_sign(GO_EVP_PKEY_CTX*, uint8_t*, size_t*, const uint8_t*, size_t);
```

### 2.14 NIDs (Algorithm Identifiers)
```c
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
```

---

## 3. WolfSSL API Analysis — Mapping Candidates

### 3.1 SHA Hashing

WolfSSL uses a completely different API pattern: `wc_InitSha*` / `wc_Sha*Update` / `wc_Sha*Final` / `wc_Sha*Free`.

**Key differences from BoringSSL:**
- Return convention: WolfSSL returns 0 on success (negative on error), BoringSSL returns 1 on success
- WolfSSL structs are much larger and contain platform-specific fields
- WolfSSL requires calling `wc_ShaFree()` for cleanup; BoringSSL SHA contexts are self-contained
- WolfSSL struct layouts differ from BoringSSL — the Go code's `MarshalBinary`/`UnmarshalBinary` cast the context to read internal fields

**WolfSSL SHA API:**
```c
int wc_InitSha(wc_Sha* sha);
int wc_ShaUpdate(wc_Sha* sha, const byte* data, word32 len);
int wc_ShaFinal(wc_Sha* sha, byte* hash);
void wc_ShaFree(wc_Sha* sha);

int wc_InitSha256(wc_Sha256* sha);
int wc_Sha256Update(wc_Sha256* sha, const byte* data, word32 len);
int wc_Sha256Final(wc_Sha256* sha256, byte* hash);
void wc_Sha256Free(wc_Sha256* sha256);

int wc_InitSha384(wc_Sha384* sha);
int wc_Sha384Update(wc_Sha384* sha, const byte* data, word32 len);
int wc_Sha384Final(wc_Sha384* sha384, byte* hash);
void wc_Sha384Free(wc_Sha384* sha);

int wc_InitSha512(wc_Sha512* sha);
int wc_Sha512Update(wc_Sha512* sha, const byte* data, word32 len);
int wc_Sha512Final(wc_Sha512* sha512, byte* hash);
void wc_Sha512Free(wc_Sha512* sha);

int wc_InitSha224(wc_Sha224* sha224);
int wc_Sha224Update(wc_Sha224* sha224, const byte* data, word32 len);
int wc_Sha224Final(wc_Sha224* sha224, byte* hash);
void wc_Sha224Free(wc_Sha224* sha224);
```

**Struct size issue:** wc_Sha (SHA-1) on default Linux is much larger than 96 bytes due to heap pointer and other fields. We'll need wrapper structs or heap-allocated contexts.

### 3.2 HMAC

**WolfSSL HMAC API:**
```c
int wc_HmacInit(Hmac* hmac, void* heap, int devId);
int wc_HmacSetKey(Hmac* hmac, int type, const byte* key, word32 length);
int wc_HmacUpdate(Hmac* hmac, const byte* msg, word32 length);
int wc_HmacFinal(Hmac* hmac, byte* hash);
int wc_HmacCopy(Hmac* src, Hmac* dst);
void wc_HmacFree(Hmac* hmac);
```

**Key differences:**
- WolfSSL uses hash type constants (WC_SHA, WC_SHA256, etc.) instead of `EVP_MD*` pointers
- No separate Init/SetKey — `wc_HmacSetKey` initializes and sets the key
- WolfSSL Hmac struct is much larger due to containing the full hash union

### 3.3 AES

**WolfSSL AES API:**
```c
int wc_AesSetKey(Aes* aes, const byte* key, word32 len, const byte* iv, int dir);
int wc_AesEcbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz);
int wc_AesEcbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz);
int wc_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz);
int wc_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz);
int wc_AesCtrEncrypt(Aes* aes, byte* out, const byte* in, word32 sz);
```

**Key differences:**
- WolfSSL uses a single `Aes` struct (not separate enc/dec key structs)
- `wc_AesSetKey` takes direction (AES_ENCRYPTION / AES_DECRYPTION)
- No separate single-block encrypt/decrypt — WolfSSL's ECB operates on arbitrary lengths
- AES-GCM is separate: `wc_AesGcmSetKey`, `wc_AesGcmEncrypt`, `wc_AesGcmDecrypt`

**AES-GCM (the AEAD replacement):**
```c
int wc_AesGcmSetKey(Aes* aes, const byte* key, word32 len);
int wc_AesGcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
                      const byte* iv, word32 ivSz,
                      byte* authTag, word32 authTagSz,
                      const byte* authIn, word32 authInSz);
int wc_AesGcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
                      const byte* iv, word32 ivSz,
                      const byte* authTag, word32 authTagSz,
                      const byte* authIn, word32 authInSz);
```

**Critical:** WolfSSL's AES-GCM API is fundamentally different from BoringSSL's EVP_AEAD:
- BoringSSL appends the tag to ciphertext in `seal`, expects tag at end in `open`
- WolfSSL has separate tag parameter
- BoringSSL has TLS12/TLS13 specific AEAD variants; WolfSSL does not
- Need to write C shim functions that translate between the two conventions

### 3.4 RSA

**WolfSSL RSA API:**
```c
int wc_InitRsaKey(RsaKey* key, void* heap);
int wc_FreeRsaKey(RsaKey* key);
int wc_MakeRsaKey(RsaKey* key, int size, long e, WC_RNG* rng);
int wc_RsaPublicEncrypt(const byte* in, word32 inLen, byte* out, word32 outLen, RsaKey* key, WC_RNG* rng);
int wc_RsaPrivateDecrypt(const byte* in, word32 inLen, byte* out, word32 outLen, RsaKey* key);
int wc_RsaSSL_Sign(const byte* in, word32 inLen, byte* out, word32 outLen, RsaKey* key, WC_RNG* rng);
int wc_RsaSSL_Verify(const byte* in, word32 inLen, byte* out, word32 outLen, RsaKey* key);
int wc_RsaPSS_Sign(const byte* in, word32 inLen, byte* out, word32 outLen, enum wc_HashType hash, int mgf, RsaKey* key, WC_RNG* rng);
int wc_RsaPSS_Verify(const byte* in, word32 inLen, byte* out, word32 outLen, enum wc_HashType hash, int mgf, RsaKey* key);
int wc_RsaPublicEncrypt_ex(const byte* in, word32 inLen, byte* out, word32 outLen, RsaKey* key, WC_RNG* rng, int type, enum wc_HashType hash, int mgf, byte* label, word32 labelSz);
int wc_RsaPrivateDecrypt_ex(const byte* in, word32 inLen, byte* out, word32 outLen, RsaKey* key, int type, enum wc_HashType hash, int mgf, byte* label, word32 labelSz);
int wc_RsaEncryptSize(const RsaKey* key);
int wc_RsaExportKey(const RsaKey* key, byte* e, word32* eSz, byte* n, word32* nSz, byte* d, word32* dSz, byte* p, word32* pSz, byte* q, word32* qSz);
int wc_RsaPrivateKeyDecodeRaw(...);
```

**Key differences:**
- WolfSSL's `RsaKey` struct is very different from BoringSSL's `RSA` — uses `mp_int` for components, not `BIGNUM*`
- No `RSA_get0_key`/`RSA_get0_factors` — WolfSSL uses `wc_RsaExportKey` or direct field access
- No separate `RSA_encrypt`/`RSA_decrypt` with padding param — WolfSSL has `_ex` variants
- WolfSSL PSS sign/verify has different signature (hash type enum vs EVP_MD pointer, mgf param)
- WolfSSL returns size of output (positive) on success for encrypt/decrypt, negative on error
- No `RSA_public_key_from_bytes`/`RSA_private_key_from_bytes` — WolfSSL uses ASN.1 DER decode

### 3.5 ECC / ECDSA / ECDH

**WolfSSL ECC API:**
```c
int wc_ecc_init(ecc_key* key);
int wc_ecc_free(ecc_key* key);
int wc_ecc_make_key(WC_RNG* rng, int keysize, ecc_key* key);
int wc_ecc_make_key_ex(WC_RNG* rng, int keysize, ecc_key* key, int curve_id);
int wc_ecc_sign_hash(const byte* in, word32 inlen, byte* out, word32* outlen, WC_RNG* rng, ecc_key* key);
int wc_ecc_verify_hash(const byte* sig, word32 siglen, const byte* hash, word32 hashlen, int* res, ecc_key* key);
int wc_ecc_shared_secret(ecc_key* private_key, ecc_key* public_key, byte* out, word32* outlen);
int wc_ecc_import_x963(const byte* in, word32 inLen, ecc_key* key);
int wc_ecc_export_x963(ecc_key* key, byte* out, word32* outLen);
int wc_ecc_import_unsigned(ecc_key* key, const byte* qx, const byte* qy, const byte* d, int curve_id);
int wc_ecc_export_public_raw(ecc_key* key, byte* qx, word32* qxLen, byte* qy, word32* qyLen);
int wc_ecc_export_private_raw(ecc_key* key, byte* qx, word32* qxLen, byte* qy, word32* qyLen, byte* d, word32* dLen);
int wc_ecc_import_private_key(const byte* priv, word32 privSz, const byte* pub, word32 pubSz, ecc_key* key);
int wc_ecc_check_key(ecc_key* key);
int wc_ecc_size(ecc_key* key);
int wc_ecc_sig_size(const ecc_key* key);
```

**Key differences:**
- WolfSSL uses a unified `ecc_key` struct (not separate EC_GROUP, EC_POINT, EC_KEY)
- Curve identification: WolfSSL uses `ecc_curve_id` enum (ECC_SECP256R1=7, ECC_SECP384R1=15, ECC_SECP521R1=16) vs BoringSSL NIDs
- No separate EC_POINT operations — WolfSSL works with key-level import/export
- WolfSSL ECDSA output is DER-encoded (same as BoringSSL's `ECDSA_sign`)
- WolfSSL ECDH via `wc_ecc_shared_secret` operates on ecc_key, not separate EC_POINT
- WolfSSL verify returns result via `int* res` out-parameter, not as return value

### 3.6 Random Number Generation

**WolfSSL RNG API:**
```c
int wc_InitRng(WC_RNG* rng);
int wc_RNG_GenerateBlock(WC_RNG* rng, byte* output, word32 sz);
int wc_FreeRng(WC_RNG* rng);
```

**Key difference:** WolfSSL requires an initialized `WC_RNG` object, while BoringSSL's `RAND_bytes` is stateless (uses a global RNG).

### 3.7 FIPS

WolfSSL has a FIPS-validated version (wolfCrypt FIPS 140-2 and 140-3). Key considerations:
- Requires separate commercial license from wolfSSL Inc.
- Provides `wolfCrypt_SetCb_fips` callback, self-test via `wolfCrypt_FIPS_test()`
- Different build configuration (`--enable-fips`)
- FIPS boundary includes power-on self-tests

---

## 4. Critical Design Decisions

### 4.1 Strategy: Write a C Shim Layer (Recommended)

**Option A: Write a `gowolfcrypto.h` + C shim that implements the `_goboringcrypto_*` API on top of WolfSSL.**
- Pros: Minimal changes to Go code — same function signatures
- Cons: Complex shim code, must handle all semantic differences
- This means the Go `.go` files remain almost unchanged

**Option B: Rewrite all Go files to call WolfSSL directly.**
- Pros: Cleaner, no shim overhead
- Cons: Massive amount of Go code changes, higher risk of bugs

**Decision: Option A (C shim) is strongly recommended.**

The Go code is well-tested and the cgo interface is delicate (noescape annotations, finalizers, KeepAlive patterns). Rewriting all Go files introduces too much risk. A C shim that maps the `_goboringcrypto_*` ABI to WolfSSL calls is safer.

### 4.2 Struct Size Problem

BoringSSL structs embedded in `goboringcrypto.h` have fixed sizes that must match exactly. WolfSSL structs are different sizes. Two approaches:

**Option A: Heap-allocate WolfSSL structs, store pointers in fixed-size containers.**
- The `char data[N]` arrays become large enough to hold a pointer
- Shim functions allocate/free WolfSSL structs on the heap

**Option B: Make the containers large enough for WolfSSL structs.**
- Change `char data[N]` sizes to match WolfSSL struct sizes
- Simpler but means the Go MarshalBinary/UnmarshalBinary code needs changes

**Decision: Use heap allocation (Option A) for complex types (RSA, EC, HMAC, AEAD). For SHA contexts, use Option B (resize containers) since the Go code directly accesses internal fields for Marshal/Unmarshal.**

### 4.3 SHA MarshalBinary Compatibility

The Go code reaches into SHA context internals for serialization. WolfSSL's `wc_Sha256` has this layout (on standard Linux x86_64):
```c
struct wc_Sha256 {
    word32 digest[8];     // offset 0, 32 bytes
    word32 buffer[16];    // offset 32, 64 bytes
    word32 buffLen;       // offset 96, 4 bytes
    word32 loLen;         // offset 100, 4 bytes
    word32 hiLen;         // offset 104, 4 bytes
    void*  heap;          // offset 108 (or 112 with alignment), 8 bytes
    ...
};
```

BoringSSL's SHA256 context (as interpreted by Go):
```go
type sha256Ctx struct {
    h      [8]uint32   // 32 bytes
    nl, nh uint32      // 8 bytes
    x      [64]byte    // 64 bytes
    nx     uint32      // 4 bytes
}
// Total: 108 bytes (packed), but container is 112 bytes
```

WolfSSL puts `digest` first and `buffer` second (like the hash block), while BoringSSL puts hash state (`h`) first, then byte count (`nl`, `nh`), then buffer (`x`), then used count (`nx`). **The field order is different!**

**Decision: Write custom MarshalBinary/UnmarshalBinary that understand WolfSSL's layout, OR write shim functions that translate. We must modify the Go sha.go to use WolfSSL field ordering.**

### 4.4 EVP_AEAD → WolfSSL AES-GCM Translation

This is the hardest part. BoringSSL's AEAD API:
- Combines ciphertext+tag in seal output
- Has TLS12/TLS13 specific variants (which handle nonce construction differently)
- Uses an EVP_AEAD_CTX that holds the key and can be reused

WolfSSL's AES-GCM:
- Separate tag parameter
- No TLS-specific variants
- Key is in the Aes struct

**Decision: Write C shim functions that:**
1. Store the Aes key + algorithm info in a struct that fits in `GO_EVP_AEAD_CTX`
2. Implement `seal` by calling `wc_AesGcmEncrypt` and appending the tag
3. Implement `open` by splitting off the tag and calling `wc_AesGcmDecrypt`
4. For TLS12/TLS13 variants, implement the specific nonce/counter logic in the shim

### 4.5 BIGNUM → mp_int Translation

BoringSSL uses `BIGNUM` (OpenSSL-style); WolfSSL uses `mp_int` (multiple precision integer). The Go code uses BIGNUMs for:
- EC point coordinates (x, y)
- EC private key (d)
- RSA key components (n, e, d, p, q, dp, dq, qinv)
- Conversion to/from Go's `BigInt` ([]uint, little-endian words)

**Decision: Write shim BIGNUM functions that wrap `mp_int`. The heap-allocated approach works here since BIGNUMs are always heap-allocated in BoringSSL too.**

### 4.6 RSA Struct Direct Field Access

The Go code does `key.n`, `key.e`, etc. directly on the `GO_RSA` struct:
```go
if !bigToBn(&key.n, N) || !bigToBn(&key.e, E) { ... }
```

This means the RSA struct must have BIGNUM pointers at the exact same offsets as BoringSSL. Since we're wrapping WolfSSL's `RsaKey` (which has `mp_int` fields), we need our `GO_RSA` to be a custom struct with `GO_BIGNUM*` pointers that we maintain alongside the internal `RsaKey`.

**Decision: Our `GO_RSA` will be a heap-allocated wrapper struct containing:
- BIGNUM pointer fields at the correct offsets (for Go's direct access)
- A WolfSSL `RsaKey*` internally
- Synchronization functions to copy between BIGNUM pointers and RsaKey mp_int fields

---

## 5. Missing APIs in WolfSSL

### 5.1 BoringSSL-Specific APIs (No WolfSSL Equivalent)

| BoringSSL API | Status | Workaround |
|---|---|---|
| `EVP_aead_aes_*_gcm_tls12()` | Missing | Implement TLS nonce logic in shim |
| `EVP_aead_aes_*_gcm_tls13()` | Missing | Implement TLS nonce logic in shim |
| `EVP_AEAD_CTX_*` | Missing | Write complete shim over wc_AesGcm* |
| `EC_KEY_generate_key_fips()` | Missing | Use `wc_ecc_make_key_ex()` + FIPS config |
| `ECDH_compute_key_fips()` | Missing | Use `wc_ecc_shared_secret()` + FIPS config |
| `RSA_generate_key_fips()` | Missing | Use `wc_MakeRsaKey()` + FIPS config |
| `RSA_check_fips()` | Missing | Use `wc_CheckRsaKey()` |
| `RSA_encrypt()` / `RSA_decrypt()` with padding enum | Different API | Map to `wc_RsaPublicEncrypt_ex`/`wc_RsaPrivateDecrypt_ex` |
| `RSA_sign_pss_mgf1()` / `RSA_verify_pss_mgf1()` | Different API | Map to `wc_RsaPSS_Sign_ex`/`wc_RsaPSS_Verify_ex` |
| `RSA_sign_raw()` / `RSA_verify_raw()` | Different API | Use `wc_RsaDirect` or no-padding variant |
| `RSA_public_key_from_bytes()` | Missing | Use `wc_RsaPublicKeyDecode` |
| `RSA_private_key_from_bytes()` | Missing | Use `wc_RsaPrivateKeyDecode` |
| `RSA_public_key_to_bytes()` | Missing | Use `wc_RsaKeyToDer` |
| `BN_le2bn()` / `BN_bn2le_padded()` | Missing | Implement byte-swap + `mp_read_unsigned_bin` |
| `BORINGSSL_bcm_power_on_self_test()` | Missing | Map to `wolfCrypt_FIPS_test()` or custom init |
| `FIPS_mode()` | Different | Check WolfSSL FIPS build flag |
| `OPENSSL_malloc()` | Missing | Use standard `malloc` |
| `EVP_md4()` / `EVP_md5()` / `EVP_md5_sha1()` | Partial | WolfSSL may not have MD4/MD5_SHA1 |

### 5.2 APIs Available in WolfSSL

| Capability | WolfSSL API | Notes |
|---|---|---|
| SHA-1 | `wc_InitSha`, `wc_ShaUpdate`, `wc_ShaFinal` | ✓ Full support |
| SHA-224 | `wc_InitSha224`, etc. | ✓ With `WOLFSSL_SHA224` |
| SHA-256 | `wc_InitSha256`, etc. | ✓ Default enabled |
| SHA-384 | `wc_InitSha384`, etc. | ✓ With `WOLFSSL_SHA384` |
| SHA-512 | `wc_InitSha512`, etc. | ✓ With `WOLFSSL_SHA512` |
| HMAC | `wc_HmacSetKey`, `wc_HmacUpdate`, `wc_HmacFinal` | ✓ Full support |
| AES-ECB | `wc_AesEcbEncrypt/Decrypt` | ✓ |
| AES-CBC | `wc_AesCbcEncrypt/Decrypt` | ✓ |
| AES-CTR | `wc_AesCtrEncrypt` | ✓ |
| AES-GCM | `wc_AesGcmEncrypt/Decrypt` | ✓ Different API shape |
| RSA keygen | `wc_MakeRsaKey` | ✓ With `WOLFSSL_KEY_GEN` |
| RSA PKCS1v15 | `wc_RsaSSL_Sign/Verify` | ✓ |
| RSA OAEP | `wc_RsaPublicEncrypt_ex` | ✓ With OAEP pad type |
| RSA PSS | `wc_RsaPSS_Sign/Verify` | ✓ With `WC_RSA_PSS` |
| ECDSA sign | `wc_ecc_sign_hash` | ✓ DER output |
| ECDSA verify | `wc_ecc_verify_hash` | ✓ |
| ECDH | `wc_ecc_shared_secret` | ✓ |
| ECC keygen | `wc_ecc_make_key_ex` | ✓ |
| RNG | `wc_RNG_GenerateBlock` | ✓ |
| HKDF | `wc_HKDF` | ✓ With `HAVE_HKDF` |

---

## 6. Build System Considerations

### 6.1 WolfSSL Configure Options Needed

```bash
./configure \
    --enable-aescbc \
    --enable-aesctr \
    --enable-aesgcm \
    --enable-sha \
    --enable-sha224 \
    --enable-sha384 \
    --enable-sha512 \
    --enable-rsa \
    --enable-rsapss \
    --enable-ecc \
    --enable-eccshamir \
    --enable-hkdf \
    --enable-keygen \
    --enable-certgen \
    --enable-singlethreaded=no \
    --enable-static \
    --disable-shared \
    --with-pic \
    CFLAGS="-fPIC -DWOLFSSL_KEY_GEN -DHAVE_ECC_SIGN -DHAVE_ECC_VERIFY -DHAVE_ECC_DHE -DHAVE_ECC_KEY_IMPORT -DHAVE_ECC_KEY_EXPORT -DWC_RSA_PSS -DWOLFSSL_SHA224 -DWOLFSSL_SHA384 -DWOLFSSL_SHA512 -DHAVE_HKDF -DWOLFSSL_AES_COUNTER -DHAVE_AES_ECB"
```

For FIPS: `--enable-fips` (requires commercial license and specific source bundle from wolfSSL Inc.)

### 6.2 Symbol Prefixing

Same approach as BoringSSL: use `objcopy --redefine-syms` to prefix all WolfSSL symbols with `_goboringcrypto_` (or better: `_gowolfcrypto_`). This avoids conflicts with any WolfSSL or OpenSSL already linked into the process.

### 6.3 Adapting build-goboring.sh → build-gowolf.sh

The script would:
1. Build WolfSSL as a static library (`libwolfssl.a`)
2. Build the C shim layer that translates `_gowolfcrypto_*` calls to WolfSSL
3. Link everything into a single `.o` file
4. Rename symbols
5. Output `gowolfcrypto_linux_{amd64,arm64}.syso`

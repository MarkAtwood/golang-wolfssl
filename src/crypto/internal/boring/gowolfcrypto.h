// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This header file describes the WolfSSL-backed crypto ABI as built for use in Go.
// It is a drop-in replacement for goboringcrypto.h, providing the same
// _goboringcrypto_* function prototypes with WolfSSL as the backend.

#include <stdlib.h> // size_t
#include <stdint.h> // uint8_t

// === Initialization / FIPS ===
/*unchecked*/ void _goboringcrypto_BORINGSSL_bcm_power_on_self_test(void);
int _goboringcrypto_FIPS_mode(void);
void* _goboringcrypto_OPENSSL_malloc(size_t);

// === RAND ===
int _goboringcrypto_RAND_bytes(uint8_t*, size_t);

// === NIDs ===
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

// === SHA ===
// Sizes must be >= WolfSSL's wc_Sha*/wc_Sha256/wc_Sha512 struct sizes.
// wc_Sha=104, wc_Sha256=128, wc_Sha512=224 on Linux x86_64.
// We use uintptr_t internal (heap-allocated) to avoid struct layout coupling
// and to prevent cgo "Go pointer to unpinned Go pointer" panics.
typedef struct GO_SHA_CTX { uintptr_t internal; } GO_SHA_CTX;
int _goboringcrypto_SHA1_Init(GO_SHA_CTX*);
int _goboringcrypto_SHA1_Update(GO_SHA_CTX*, const void*, size_t);
int _goboringcrypto_SHA1_Final(uint8_t*, GO_SHA_CTX*);

typedef struct GO_SHA256_CTX { uintptr_t internal; } GO_SHA256_CTX;
int _goboringcrypto_SHA224_Init(GO_SHA256_CTX*);
int _goboringcrypto_SHA224_Update(GO_SHA256_CTX*, const void*, size_t);
int _goboringcrypto_SHA224_Final(uint8_t*, GO_SHA256_CTX*);
int _goboringcrypto_SHA256_Init(GO_SHA256_CTX*);
int _goboringcrypto_SHA256_Update(GO_SHA256_CTX*, const void*, size_t);
int _goboringcrypto_SHA256_Final(uint8_t*, GO_SHA256_CTX*);

typedef struct GO_SHA512_CTX { uintptr_t internal; } GO_SHA512_CTX;
int _goboringcrypto_SHA384_Init(GO_SHA512_CTX*);
int _goboringcrypto_SHA384_Update(GO_SHA512_CTX*, const void*, size_t);
int _goboringcrypto_SHA384_Final(uint8_t*, GO_SHA512_CTX*);
int _goboringcrypto_SHA512_Init(GO_SHA512_CTX*);
int _goboringcrypto_SHA512_Update(GO_SHA512_CTX*, const void*, size_t);
int _goboringcrypto_SHA512_Final(uint8_t*, GO_SHA512_CTX*);

// SHA context copy (for Go's sum() method)
int _goboringcrypto_SHA1_Copy(GO_SHA_CTX* dst, const GO_SHA_CTX* src);
int _goboringcrypto_SHA256_Copy(GO_SHA256_CTX* dst, const GO_SHA256_CTX* src);
int _goboringcrypto_SHA224_Copy(GO_SHA256_CTX* dst, const GO_SHA256_CTX* src);
int _goboringcrypto_SHA384_Copy(GO_SHA512_CTX* dst, const GO_SHA512_CTX* src);
int _goboringcrypto_SHA512_Copy(GO_SHA512_CTX* dst, const GO_SHA512_CTX* src);

// SHA context cleanup
void _goboringcrypto_SHA1_Cleanup(GO_SHA_CTX*);
void _goboringcrypto_SHA256_Cleanup(GO_SHA256_CTX*);
void _goboringcrypto_SHA512_Cleanup(GO_SHA512_CTX*);

// SHA state access for Marshal/Unmarshal
// SHA-1: 5 uint32 digest, 64 byte buffer, uint32 buffLen, uint32 loLen, uint32 hiLen
int _goboringcrypto_SHA1_get_state(const GO_SHA_CTX*, uint32_t* h, uint8_t* x, uint32_t* nx, uint32_t* nl, uint32_t* nh);
int _goboringcrypto_SHA1_set_state(GO_SHA_CTX*, const uint32_t* h, const uint8_t* x, uint32_t nx, uint32_t nl, uint32_t nh);
// SHA-256/224: 8 uint32 digest, 64 byte buffer, uint32 buffLen, uint32 loLen, uint32 hiLen
int _goboringcrypto_SHA256_get_state(const GO_SHA256_CTX*, uint32_t* h, uint8_t* x, uint32_t* nx, uint32_t* nl, uint32_t* nh);
int _goboringcrypto_SHA256_set_state(GO_SHA256_CTX*, const uint32_t* h, const uint8_t* x, uint32_t nx, uint32_t nl, uint32_t nh);
// SHA-512/384: 8 uint64 digest, 128 byte buffer, uint32 buffLen, uint64 loLen, uint64 hiLen
int _goboringcrypto_SHA512_get_state(const GO_SHA512_CTX*, uint64_t* h, uint8_t* x, uint32_t* nx, uint64_t* nl, uint64_t* nh);
int _goboringcrypto_SHA512_set_state(GO_SHA512_CTX*, const uint64_t* h, const uint8_t* x, uint32_t nx, uint64_t nl, uint64_t nh);

// === EVP_MD ===
/*unchecked (opaque)*/ typedef struct GO_EVP_MD { char data[1]; } GO_EVP_MD;
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

// === HMAC ===
typedef struct GO_HMAC_CTX { uintptr_t internal; } GO_HMAC_CTX;
void _goboringcrypto_HMAC_CTX_init(GO_HMAC_CTX*);
void _goboringcrypto_HMAC_CTX_cleanup(GO_HMAC_CTX*);
int _goboringcrypto_HMAC_Init(GO_HMAC_CTX*, const void*, int, const GO_EVP_MD*);
int _goboringcrypto_HMAC_Update(GO_HMAC_CTX*, const uint8_t*, size_t);
int _goboringcrypto_HMAC_Final(GO_HMAC_CTX*, uint8_t*, unsigned int*);
size_t _goboringcrypto_HMAC_size(const GO_HMAC_CTX*);
int _goboringcrypto_HMAC_CTX_copy_ex(GO_HMAC_CTX *dest, const GO_HMAC_CTX *src);

// === AES ===
typedef struct GO_AES_KEY { uintptr_t internal; } GO_AES_KEY;
int _goboringcrypto_AES_set_encrypt_key(const uint8_t*, unsigned int, GO_AES_KEY*);
int _goboringcrypto_AES_set_decrypt_key(const uint8_t*, unsigned int, GO_AES_KEY*);
void _goboringcrypto_AES_encrypt(const uint8_t*, uint8_t*, const GO_AES_KEY*);
void _goboringcrypto_AES_decrypt(const uint8_t*, uint8_t*, const GO_AES_KEY*);
void _goboringcrypto_AES_ctr128_encrypt(const uint8_t*, uint8_t*, size_t, const GO_AES_KEY*, uint8_t*, uint8_t*, unsigned int*);
enum {
	GO_AES_ENCRYPT = 1,
	GO_AES_DECRYPT = 0
};
void _goboringcrypto_AES_cbc_encrypt(const uint8_t*, uint8_t*, size_t, const GO_AES_KEY*, uint8_t*, const int);

// AES key cleanup
void _goboringcrypto_AES_KEY_cleanup(GO_AES_KEY*);

// === AEAD (AES-GCM) ===
/*unchecked (opaque)*/ typedef struct GO_EVP_AEAD { char data[1]; } GO_EVP_AEAD;
/*unchecked (opaque)*/ typedef struct GO_ENGINE { char data[1]; } GO_ENGINE;
const GO_EVP_AEAD* _goboringcrypto_EVP_aead_aes_128_gcm(void);
const GO_EVP_AEAD* _goboringcrypto_EVP_aead_aes_256_gcm(void);
enum {
	GO_EVP_AEAD_DEFAULT_TAG_LENGTH = 0
};
size_t _goboringcrypto_EVP_AEAD_key_length(const GO_EVP_AEAD*);
size_t _goboringcrypto_EVP_AEAD_nonce_length(const GO_EVP_AEAD*);
size_t _goboringcrypto_EVP_AEAD_max_overhead(const GO_EVP_AEAD*);
size_t _goboringcrypto_EVP_AEAD_max_tag_len(const GO_EVP_AEAD*);
typedef struct GO_EVP_AEAD_CTX { uintptr_t internal; } GO_EVP_AEAD_CTX;
void _goboringcrypto_EVP_AEAD_CTX_zero(GO_EVP_AEAD_CTX*);
int _goboringcrypto_EVP_AEAD_CTX_init(GO_EVP_AEAD_CTX*, const GO_EVP_AEAD*, const uint8_t*, size_t, size_t, GO_ENGINE*);
void _goboringcrypto_EVP_AEAD_CTX_cleanup(GO_EVP_AEAD_CTX*);
int _goboringcrypto_EVP_AEAD_CTX_seal(const GO_EVP_AEAD_CTX*, uint8_t*, size_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t);
int _goboringcrypto_EVP_AEAD_CTX_open(const GO_EVP_AEAD_CTX*, uint8_t*, size_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t);
const GO_EVP_AEAD* _goboringcrypto_EVP_aead_aes_128_gcm_tls12(void);
const GO_EVP_AEAD* _goboringcrypto_EVP_aead_aes_128_gcm_tls13(void);
const GO_EVP_AEAD* _goboringcrypto_EVP_aead_aes_256_gcm_tls12(void);
const GO_EVP_AEAD* _goboringcrypto_EVP_aead_aes_256_gcm_tls13(void);
enum go_evp_aead_direction_t {
	go_evp_aead_open = 0,
	go_evp_aead_seal = 1
};
int _goboringcrypto_EVP_AEAD_CTX_init_with_direction(GO_EVP_AEAD_CTX*, const GO_EVP_AEAD*, const uint8_t*, size_t, size_t, enum go_evp_aead_direction_t);

// === BIGNUM ===
/*unchecked (opaque)*/ typedef struct GO_BN_CTX { char data[1]; } GO_BN_CTX;
/*unchecked (opaque)*/ typedef struct GO_BIGNUM { char data[1]; } GO_BIGNUM;
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

// === EC ===
/*unchecked (opaque)*/ typedef struct GO_EC_GROUP { char data[1]; } GO_EC_GROUP;
GO_EC_GROUP* _goboringcrypto_EC_GROUP_new_by_curve_name(int);
void _goboringcrypto_EC_GROUP_free(GO_EC_GROUP*);

/*unchecked (opaque)*/ typedef struct GO_EC_POINT { char data[1]; } GO_EC_POINT;
GO_EC_POINT* _goboringcrypto_EC_POINT_new(const GO_EC_GROUP*);
int _goboringcrypto_EC_POINT_mul(const GO_EC_GROUP*, GO_EC_POINT*, const GO_BIGNUM*, const GO_EC_POINT*, const GO_BIGNUM*, GO_BN_CTX*);
void _goboringcrypto_EC_POINT_free(GO_EC_POINT*);
int _goboringcrypto_EC_POINT_get_affine_coordinates_GFp(const GO_EC_GROUP*, const GO_EC_POINT*, GO_BIGNUM*, GO_BIGNUM*, GO_BN_CTX*);
int _goboringcrypto_EC_POINT_set_affine_coordinates_GFp(const GO_EC_GROUP*, GO_EC_POINT*, const GO_BIGNUM*, const GO_BIGNUM*, GO_BN_CTX*);
int _goboringcrypto_EC_POINT_oct2point(const GO_EC_GROUP*, GO_EC_POINT*, const uint8_t*, size_t, GO_BN_CTX*);
GO_EC_POINT* _goboringcrypto_EC_POINT_dup(const GO_EC_POINT*, const GO_EC_GROUP*);
int _goboringcrypto_EC_POINT_is_on_curve(const GO_EC_GROUP*, const GO_EC_POINT*, GO_BN_CTX*);
#ifndef OPENSSL_HEADER_EC_H
typedef enum {
	GO_POINT_CONVERSION_COMPRESSED = 2,
	GO_POINT_CONVERSION_UNCOMPRESSED = 4,
	GO_POINT_CONVERSION_HYBRID = 6,
} go_point_conversion_form_t;
#endif
size_t _goboringcrypto_EC_POINT_point2oct(const GO_EC_GROUP*, const GO_EC_POINT*, go_point_conversion_form_t, uint8_t*, size_t, GO_BN_CTX*);

// === EC KEY ===
/*unchecked (opaque)*/ typedef struct GO_EC_KEY { char data[1]; } GO_EC_KEY;
GO_EC_KEY* _goboringcrypto_EC_KEY_new(void);
GO_EC_KEY* _goboringcrypto_EC_KEY_new_by_curve_name(int);
void _goboringcrypto_EC_KEY_free(GO_EC_KEY*);
const GO_EC_GROUP* _goboringcrypto_EC_KEY_get0_group(const GO_EC_KEY*);
int _goboringcrypto_EC_KEY_generate_key_fips(GO_EC_KEY*);
int _goboringcrypto_EC_KEY_set_private_key(GO_EC_KEY*, const GO_BIGNUM*);
int _goboringcrypto_EC_KEY_set_public_key(GO_EC_KEY*, const GO_EC_POINT*);
int _goboringcrypto_EC_KEY_is_opaque(const GO_EC_KEY*);
const GO_BIGNUM* _goboringcrypto_EC_KEY_get0_private_key(const GO_EC_KEY*);
const GO_EC_POINT* _goboringcrypto_EC_KEY_get0_public_key(const GO_EC_KEY*);

// === ECDH ===
int _goboringcrypto_ECDH_compute_key_fips(uint8_t*, size_t, const GO_EC_POINT*, const GO_EC_KEY*);

// === ECDSA ===
typedef struct GO_ECDSA_SIG { char data[16]; } GO_ECDSA_SIG;
GO_ECDSA_SIG* _goboringcrypto_ECDSA_SIG_new(void);
void _goboringcrypto_ECDSA_SIG_free(GO_ECDSA_SIG*);
GO_ECDSA_SIG* _goboringcrypto_ECDSA_do_sign(const uint8_t*, size_t, const GO_EC_KEY*);
int _goboringcrypto_ECDSA_do_verify(const uint8_t*, size_t, const GO_ECDSA_SIG*, const GO_EC_KEY*);
int _goboringcrypto_ECDSA_sign(int, const uint8_t*, size_t, uint8_t*, unsigned int*, const GO_EC_KEY*);
size_t _goboringcrypto_ECDSA_size(const GO_EC_KEY*);
int _goboringcrypto_ECDSA_verify(int, const uint8_t*, size_t, const uint8_t*, size_t, const GO_EC_KEY*);

// === RSA ===
// CRITICAL: Go code directly accesses n, e, d, p, q, dmp1, dmq1, iqmp fields!
typedef struct GO_RSA { void *meth; GO_BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp; void* internal; } GO_RSA;
/*unchecked (opaque)*/ typedef struct GO_BN_GENCB { char data[1]; } GO_BN_GENCB;
GO_RSA* _goboringcrypto_RSA_new(void);
void _goboringcrypto_RSA_free(GO_RSA*);
void _goboringcrypto_RSA_get0_key(const GO_RSA*, const GO_BIGNUM **n, const GO_BIGNUM **e, const GO_BIGNUM **d);
void _goboringcrypto_RSA_get0_factors(const GO_RSA*, const GO_BIGNUM **p, const GO_BIGNUM **q);
void _goboringcrypto_RSA_get0_crt_params(const GO_RSA*, const GO_BIGNUM **dmp1, const GO_BIGNUM **dmp2, const GO_BIGNUM **iqmp);
int _goboringcrypto_RSA_generate_key_ex(GO_RSA*, int, const GO_BIGNUM*, GO_BN_GENCB*);
int _goboringcrypto_RSA_generate_key_fips(GO_RSA*, int, GO_BN_GENCB*);
enum {
	GO_RSA_PKCS1_PADDING = 1,
	GO_RSA_NO_PADDING = 3,
	GO_RSA_PKCS1_OAEP_PADDING = 4,
	GO_RSA_PKCS1_PSS_PADDING = 6,
};
int _goboringcrypto_RSA_encrypt(GO_RSA*, size_t *out_len, uint8_t *out, size_t max_out, const uint8_t *in, size_t in_len, int padding);
int _goboringcrypto_RSA_decrypt(GO_RSA*, size_t *out_len, uint8_t *out, size_t max_out, const uint8_t *in, size_t in_len, int padding);
int _goboringcrypto_RSA_sign(int hash_nid, const uint8_t* in, unsigned int in_len, uint8_t *out, unsigned int *out_len, GO_RSA*);
int _goboringcrypto_RSA_sign_pss_mgf1(GO_RSA*, size_t *out_len, uint8_t *out, size_t max_out, const uint8_t *in, size_t in_len, const GO_EVP_MD *md, const GO_EVP_MD *mgf1_md, int salt_len);
int _goboringcrypto_RSA_sign_raw(GO_RSA*, size_t *out_len, uint8_t *out, size_t max_out, const uint8_t *in, size_t in_len, int padding);
int _goboringcrypto_RSA_verify(int hash_nid, const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len, GO_RSA*);
int _goboringcrypto_RSA_verify_pss_mgf1(GO_RSA*, const uint8_t *msg, size_t msg_len, const GO_EVP_MD *md, const GO_EVP_MD *mgf1_md, int salt_len, const uint8_t *sig, size_t sig_len);
int _goboringcrypto_RSA_verify_raw(GO_RSA*, size_t *out_len, uint8_t *out, size_t max_out, const uint8_t *in, size_t in_len, int padding);
unsigned _goboringcrypto_RSA_size(const GO_RSA*);
int _goboringcrypto_RSA_is_opaque(const GO_RSA*);
int _goboringcrypto_RSA_check_key(const GO_RSA*);
int _goboringcrypto_RSA_check_fips(GO_RSA*);
GO_RSA* _goboringcrypto_RSA_public_key_from_bytes(const uint8_t*, size_t);
GO_RSA* _goboringcrypto_RSA_private_key_from_bytes(const uint8_t*, size_t);
int _goboringcrypto_RSA_public_key_to_bytes(uint8_t**, size_t*, const GO_RSA*);
int _goboringcrypto_RSA_private_key_to_bytes(uint8_t**, size_t*, const GO_RSA*);

// === EVP_PKEY ===
/*unchecked (opaque)*/ typedef struct GO_EVP_PKEY { char data[1]; } GO_EVP_PKEY;
GO_EVP_PKEY* _goboringcrypto_EVP_PKEY_new(void);
void _goboringcrypto_EVP_PKEY_free(GO_EVP_PKEY*);
int _goboringcrypto_EVP_PKEY_set1_RSA(GO_EVP_PKEY*, GO_RSA*);

/*unchecked (opaque)*/ typedef struct GO_EVP_PKEY_CTX { char data[1]; } GO_EVP_PKEY_CTX;

GO_EVP_PKEY_CTX* _goboringcrypto_EVP_PKEY_CTX_new(GO_EVP_PKEY*, GO_ENGINE*);
void _goboringcrypto_EVP_PKEY_CTX_free(GO_EVP_PKEY_CTX*);
int _goboringcrypto_EVP_PKEY_CTX_set0_rsa_oaep_label(GO_EVP_PKEY_CTX*, uint8_t*, size_t);
int _goboringcrypto_EVP_PKEY_CTX_set_rsa_oaep_md(GO_EVP_PKEY_CTX*, const GO_EVP_MD*);
int _goboringcrypto_EVP_PKEY_CTX_set_rsa_padding(GO_EVP_PKEY_CTX*, int padding);
int _goboringcrypto_EVP_PKEY_decrypt(GO_EVP_PKEY_CTX*, uint8_t*, size_t*, const uint8_t*, size_t);
int _goboringcrypto_EVP_PKEY_encrypt(GO_EVP_PKEY_CTX*, uint8_t*, size_t*, const uint8_t*, size_t);
int _goboringcrypto_EVP_PKEY_decrypt_init(GO_EVP_PKEY_CTX*);
int _goboringcrypto_EVP_PKEY_encrypt_init(GO_EVP_PKEY_CTX*);
int _goboringcrypto_EVP_PKEY_CTX_set_rsa_mgf1_md(GO_EVP_PKEY_CTX*, const GO_EVP_MD*);
int _goboringcrypto_EVP_PKEY_CTX_set_rsa_pss_saltlen(GO_EVP_PKEY_CTX*, int);
int _goboringcrypto_EVP_PKEY_sign_init(GO_EVP_PKEY_CTX*);
int _goboringcrypto_EVP_PKEY_verify_init(GO_EVP_PKEY_CTX*);
int _goboringcrypto_EVP_PKEY_sign(GO_EVP_PKEY_CTX*, uint8_t*, size_t*, const uint8_t*, size_t);

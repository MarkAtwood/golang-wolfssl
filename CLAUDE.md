# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

## What This Is

A Go source fork that replaces BoringSSL with WolfSSL as Go's crypto backend. A C shim implements all `_goboringcrypto_*` functions (Go's internal crypto ABI) on top of WolfSSL's native `wc_*` wolfcrypt API. The result is a `.syso` file that Go's build system picks up automatically when `GOEXPERIMENT=boringcrypto` is set.

## Repository Layout

```
src/crypto/internal/boring/         Modified Go boring layer
  goboringcrypto.h                  Original BoringSSL ABI header
  gowolfcrypto.h                    WolfSSL ABI header (replaces above)
  syso/gowolfcrypto.c.src           C shim source (canonical copy)
  syso/goboringcrypto_linux_amd64.syso  Built .syso artifact
wolfssl/                            Build tooling and tests
  bootstrap.sh                      Clone wolfSSL, apply patches, build
  build-gowolf.sh                   Compile shim + wolfSSL into .syso
  patches/                          WolfSSL bug fix patches (upstream PRs pending)
  verify_shim.c                     C-level smoke test
  test_vectors.c                    Correctness tests (NIST/RFC vectors)
  leak_check.c                      Memory leak detection
  testdata/                         Test fixtures
  wolfssl-shim-reference.md         API analysis: struct layouts, semantic diffs
```

Key file: `src/crypto/internal/boring/goboringcrypto.h` — defines the ~100-function C ABI the shim must implement.

## Build & Test

### Quick start

```bash
cd wolfssl
./bootstrap.sh        # clone wolfSSL @ v5.9.1, apply patches, configure, build
./build-gowolf.sh     # compile shim + libwolfssl.a into .syso, install it
```

### Build Go

```bash
GOEXPERIMENT=boringcrypto ./src/make.bash
```

### Run crypto tests

```bash
GOEXPERIMENT=boringcrypto ./bin/go test -v -count=1 \
    crypto/internal/boring \
    crypto/boring \
    crypto/aes \
    crypto/cipher \
    crypto/hmac \
    crypto/sha1 \
    crypto/sha256 \
    crypto/sha512 \
    crypto/rsa \
    crypto/ecdsa \
    crypto/ecdh \
    crypto/hkdf \
    crypto/rand \
    crypto/elliptic
```

### Run TLS tests

```bash
GOEXPERIMENT=boringcrypto ./bin/go test -v -count=1 crypto/tls
```

### C-level smoke test

```bash
cd wolfssl
clang -I ../src/crypto/internal/boring \
    verify_shim.c ../wolfssl/wolfssl-src/src/.libs/libwolfssl.a \
    -lpthread -lm -o verify_shim
./verify_shim
```

## Architecture

```
Go crypto package (src/crypto/*)
    |
    | cgo
    v
gowolfcrypto.h   declares _goboringcrypto_* (same ABI as goboringcrypto.h)
gowolfcrypto.c   implements _goboringcrypto_* using wc_* wolfcrypt API
    |
    v
libwolfssl.a     (wolfssl/wolfssl-src/src/.libs/libwolfssl.a)
```

The shim + `libwolfssl.a` are linked into a `.syso` via `wolfssl/build-gowolf.sh`; Go's build system picks up the `.syso` automatically when `GOEXPERIMENT=boringcrypto` is set.

## Critical Implementation Rules

### Return code convention
WolfSSL returns 0 for success; BoringSSL returns 1 for success. **Every wrapper must invert:**
- wolfSSL `0` → return `1` (success to caller)
- wolfSSL non-zero → return `0` (failure to caller)

**Exception**: `AES_set_encrypt_key` and `AES_set_decrypt_key` return 0 for success in both APIs — do not invert these.

### Context heap allocation
WolfSSL context structs (`wc_Sha`, `Aes`, `Hmac`, `RsaKey`, `ecc_key`, etc.) must be heap-allocated. Do not embed them inline in `GO_*` wrapper structs — store them via a `void* internal` pointer. Every `malloc` must have a corresponding `free` in the cleanup function.

### Memory zeroization
`memset(ptr, 0, sizeof(*ptr))` before freeing any key material.

### Use wolfcrypt direct API only
Use `wc_*` API. Do **not** use the wolfSSL OpenSSL compatibility layer (`SSL_*`, `EVP_*`, etc.).

### The `GO_RSA` struct exception
`GO_RSA` must preserve the exact BoringSSL field layout (`void *meth; GO_BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;`) because Go code writes to those fields directly via cgo. Add a `void* internal` field for the `RsaKey*`. Sync BIGNUMs → `RsaKey` `mp_int` fields before every RSA operation.

## C Coding Conventions

- 4 spaces per indent, no hard tabs
- 80 characters max line length
- No trailing whitespace

## Test Design Constraint

Tests must use an independent oracle. Never write a test that encrypts with a function and decrypts with the same function — that proves nothing.

Acceptable oracles for this project:
- NIST SP 800-38A/38D vectors (AES-CBC, AES-CTR, AES-GCM)
- FIPS 180-4 vectors (SHA)
- RFC 4231 vectors (HMAC)
- Go's own test vectors in `src/crypto/cipher/gcm_test.go`

## Common Failure Modes

When a test fails, check in this order:
1. **Return code inversion** — the most common bug; forgot to flip 0↔1
2. NULL pointer from a failed allocation
3. Wrong struct size causing memory corruption
4. SHA MarshalBinary/UnmarshalBinary field layout mismatch
5. AES-GCM tag append/split off-by-one
6. BIGNUM little-endian conversion error
7. RSA BIGNUM→`mp_int` sync not called before operation
8. ECDSA verify result not extracted from out-parameter

## WolfSSL Patches

The `wolfssl/patches/` directory contains fixes for wolfSSL bugs discovered during this project. Each has an upstream PR pending:

- `wolfssl-rsa-pss-fixes.patch` — two fixes in `wolfcrypt/src/rsa.c`:
  - PR [#10256](https://github.com/wolfSSL/wolfssl/pull/10256): Guard `RsaUnPad_PSS` masking when bits==0
  - PR [#10255](https://github.com/wolfSSL/wolfssl/pull/10255): Skip `RSA_MIN_PAD_SZ` check for PSS padding

These patches can be dropped once the upstream PRs merge and a new wolfSSL release includes them.

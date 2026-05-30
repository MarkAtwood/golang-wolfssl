# golang-wolfssl

A fork of the [Go programming language](https://go.dev/) that replaces
BoringSSL with [wolfSSL](https://www.wolfssl.com/) as the cryptographic
backend for `GOEXPERIMENT=boringcrypto` builds.

## Why

Go's `GOEXPERIMENT=boringcrypto` mode exists for organizations that
need a FIPS-validated crypto provider. Upstream Go hardcodes BoringSSL
for this role. wolfSSL's wolfCrypt library holds
[FIPS 140-2 and FIPS 140-3](https://www.wolfssl.com/license/fips/)
validations and is available as a lightweight, portable, commercially
supported alternative. This fork lets Go programs use wolfCrypt FIPS
instead of BoringCrypto.

## How It Works

Go's boring-crypto machinery delegates core cryptographic operations
(AES, SHA, HMAC, RSA, ECDSA, ECDH, HKDF, GCM, RAND) to a pre-built C
library linked via a `.syso` object file. Upstream Go ships a
BoringSSL-based `.syso`. This fork replaces it with one built from
wolfSSL.

A **C shim layer** (`gowolfcrypto.c`, ~2200 lines) implements every
`_goboringcrypto_*` function in Go's internal crypto ABI on top of
wolfSSL's native `wc_*` wolfCrypt API. The shim and a static
`libwolfssl.a` are merged into a single relocatable object with all
internal symbols hidden, producing a drop-in `.syso` replacement.

```
Go crypto packages (crypto/aes, crypto/rsa, ...)
    |
    | cgo — calls _goboringcrypto_* ABI
    v
gowolfcrypto.c — translates to wc_* wolfCrypt calls
    |
    v
libwolfssl.a — wolfSSL static library
```

A small number of Go files in `src/crypto/internal/boring/` are also
modified to accommodate differences in wolfSSL's context struct layouts
(SHA state serialization, heap-allocated AES/HMAC contexts).

## Building

### Prerequisites

- Linux (amd64 or arm64)
- clang, ld (binutils), nm, objcopy
- autoconf, automake, libtool (for wolfSSL)
- Git

### Quick Start

```bash
# 1. Clone wolfSSL, apply patches, and build libwolfssl.a
cd wolfssl
./bootstrap.sh

# 2. Compile the shim + wolfSSL into a .syso and install it
./build-gowolf.sh

# 3. Build the Go toolchain
cd ..
GOEXPERIMENT=boringcrypto ./src/make.bash

# 4. Run crypto tests
GOEXPERIMENT=boringcrypto ./bin/go test -count=1 \
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

# 5. Run TLS tests
GOEXPERIMENT=boringcrypto ./bin/go test -count=1 crypto/tls
```

### Using FIPS-Validated wolfCrypt

The default `bootstrap.sh` clones the open-source wolfSSL release. For
a FIPS-validated build, you must obtain the wolfCrypt FIPS source bundle
and certificate from wolfSSL under a commercial license. Replace the
wolfSSL source in `wolfssl/wolfssl-src/` with the FIPS bundle and
configure with the FIPS-specific flags documented in wolfSSL's FIPS
guide.

## Supported Algorithms

| Category | Algorithms |
|----------|------------|
| Hash     | SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 |
| MAC      | HMAC-SHA-1/224/256/384/512 |
| Cipher   | AES-128/192/256-CBC, AES-CTR, AES-GCM |
| RSA      | PKCS#1 v1.5 sign/verify/encrypt/decrypt, PSS sign/verify, OAEP encrypt/decrypt, key generation |
| ECDSA    | P-256, P-384, P-521 sign/verify/keygen |
| ECDH     | P-256, P-384, P-521 |
| KDF      | HKDF (RFC 5869) |
| RNG      | OS-seeded via wolfCrypt |

### Limitations

- Multi-prime RSA (3+ primes) is not supported by wolfSSL
- Only `linux/amd64` and `linux/arm64` are targeted
- FIPS mode requires a commercial wolfSSL FIPS license

## License

The Go source code is distributed under a BSD-style license (see
[LICENSE](LICENSE)).

**wolfSSL / wolfCrypt is licensed under
[GPLv3](https://www.wolfssl.com/license/) (open source) or a
commercial license.** Because the `.syso` statically links
`libwolfssl.a`, any binary built with `GOEXPERIMENT=boringcrypto` using
this fork incorporates wolfCrypt and is subject to GPLv3 terms.
This means **your resulting Go binaries must comply with GPLv3** — which
includes providing (or offering to provide) the corresponding source
code.

If GPL obligations are not suitable for your deployment, wolfSSL offers
commercial licenses that remove the GPL requirement. Contact wolfSSL
for commercial licensing:

- **Licensing inquiries:** licensing@wolfssl.com
- **General questions:** facts@wolfssl.com
- **Technical support:** support@wolfssl.com
- **Phone:** +1 (425) 245-8247
- **Web:** [wolfssl.com](https://www.wolfssl.com/)

wolfSSL Inc.
10016 Edmonds Way, Suite C-300
Edmonds, WA 98020, USA

## See Also

- [README-golang.md](README-golang.md) — upstream Go project README
- [wolfssl/wolfssl-shim-reference.md](wolfssl/wolfssl-shim-reference.md) — API analysis and struct layout documentation
- [wolfSSL FIPS information](https://www.wolfssl.com/license/fips/)

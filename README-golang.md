# The Go Programming Language — WolfSSL FIPS-Ready Variant

This is a fork of Go that replaces BoringSSL with [WolfSSL](https://www.wolfssl.com/)
as the cryptographic backend for `GOEXPERIMENT=boringcrypto` builds. WolfSSL
(wolfCrypt) is a lightweight, portable C crypto library with a
[FIPS 140-2 and 140-3 validated](https://www.wolfssl.com/license/fips/)
variant, making this fork suitable for environments that require a
FIPS-certified crypto provider different from BoringSSL.

## How it works

Go's `GOEXPERIMENT=boringcrypto` mode delegates core crypto operations
(AES, SHA, HMAC, RSA, ECDSA, ECDH, GCM, HKDF, RAND) to a pre-built C
library via a `.syso` object file. Upstream Go uses BoringSSL for this.
This fork replaces it with WolfSSL through a **C shim layer**
(`gowolfcrypto.c`) that implements the same `_goboringcrypto_*` ABI on
top of WolfSSL's native `wc_*` API.

### Build and test

```bash
# Build the Go toolchain
GOEXPERIMENT=boringcrypto ./src/make.bash

# Run crypto tests
GOEXPERIMENT=boringcrypto ./bin/go test crypto/...
```

### Current status

| Package | Status |
|---------|--------|
| crypto/sha1, sha256, sha512 | PASS |
| crypto/hmac | PASS |
| crypto/rand | PASS |
| crypto/aes, crypto/cipher | PASS |
| crypto/ecdsa | PASS |
| crypto/ecdh | PASS |
| crypto/elliptic | PASS |
| crypto/rsa | Partial (PKCS1v15 sign/verify, keygen, PSS golden vectors pass; OAEP decrypt and some edge cases in progress) |
| crypto/tls | Not yet tested |

### Key files

- `src/crypto/internal/boring/goboringcrypto.h` — WolfSSL-compatible header (replaces BoringSSL header)
- `src/crypto/internal/boring/syso/gowolfcrypto.c.src` — C shim source (~2100 lines)
- `src/crypto/internal/boring/syso/goboringcrypto_linux_amd64.syso` — Pre-built object (shim + libwolfssl.a)
- `src/crypto/internal/boring/sha.go` — Modified for WolfSSL SHA context layout
- `src/crypto/internal/boring/aes.go` — Modified for heap-allocated AES keys

### Limitations

- Multi-prime RSA (3+ primes) is not supported by WolfSSL
- FIPS mode requires a commercial WolfSSL FIPS license and source bundle
- Only linux/amd64 is currently built; linux/arm64 .syso not yet produced

---

Go is an open source programming language that makes it easy to build simple,
reliable, and efficient software.

![Gopher image](https://golang.org/doc/gopher/fiveyears.jpg)
*Gopher image by [Renee French][rf], licensed under [Creative Commons 4.0 Attribution license][cc4-by].*

Our canonical Git repository is located at https://go.googlesource.com/go.
There is a mirror of the repository at https://github.com/golang/go.

Unless otherwise noted, the Go source files are distributed under the
BSD-style license found in the LICENSE file.

### Download and Install

#### Binary Distributions

Official binary distributions are available at https://go.dev/dl/.

After downloading a binary release, visit https://go.dev/doc/install
for installation instructions.

#### Install From Source

If a binary distribution is not available for your combination of
operating system and architecture, visit
https://go.dev/doc/install/source
for source installation instructions.

### Contributing

Go is the work of thousands of contributors. We appreciate your help!

To contribute, please read the contribution guidelines at https://go.dev/doc/contribute.

Note that the Go project uses the issue tracker for bug reports and
proposals only. See https://go.dev/wiki/Questions for a list of
places to ask questions about the Go language.

[rf]: https://reneefrench.blogspot.com/
[cc4-by]: https://creativecommons.org/licenses/by/4.0/

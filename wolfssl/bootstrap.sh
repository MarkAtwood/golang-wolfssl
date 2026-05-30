#!/bin/bash
# bootstrap.sh — clone wolfSSL, apply patches, configure, and build libwolfssl.a
#
# Usage: ./bootstrap.sh [--clean]
#
# Creates wolfssl-src/ alongside this script directory, builds a static
# libwolfssl.a suitable for linking into the Go boring .syso.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WOLFSSL_TAG="v5.9.1-stable"
WOLFSSL_DIR="${SCRIPT_DIR}/wolfssl-src"
PATCHES_DIR="${SCRIPT_DIR}/patches"

# ---- Options ----------------------------------------------------------------

for arg in "$@"; do
    case "${arg}" in
        --clean)
            echo "==> Removing ${WOLFSSL_DIR}..."
            rm -rf "${WOLFSSL_DIR}"
            ;;
        *) echo "Unknown argument: ${arg}" >&2; exit 1 ;;
    esac
done

# ---- Clone -------------------------------------------------------------------

if [ ! -d "${WOLFSSL_DIR}" ]; then
    echo "==> Cloning wolfSSL @ ${WOLFSSL_TAG}..."
    git clone --depth 1 --branch "${WOLFSSL_TAG}" \
        https://github.com/wolfSSL/wolfssl.git "${WOLFSSL_DIR}"
else
    echo "==> wolfssl-src/ already exists, skipping clone"
fi

# ---- Apply patches -----------------------------------------------------------

if [ -d "${PATCHES_DIR}" ]; then
    for patch in "${PATCHES_DIR}"/*.patch; do
        [ -f "${patch}" ] || continue
        echo "==> Applying $(basename "${patch}")..."
        git -C "${WOLFSSL_DIR}" apply --check "${patch}" 2>/dev/null \
            && git -C "${WOLFSSL_DIR}" apply "${patch}" \
            || echo "    (already applied or does not apply cleanly, skipping)"
    done
fi

# ---- Configure and build ----------------------------------------------------

echo "==> Configuring wolfSSL..."
cd "${WOLFSSL_DIR}"
autoreconf -i -f

./configure \
    --enable-static --disable-shared --with-pic \
    --enable-aescbc --enable-aesctr --enable-aesgcm \
    --enable-sha --enable-sha224 --enable-sha384 --enable-sha512 \
    --enable-rsa --enable-rsapss --enable-keygen \
    --enable-ecc --enable-eccshamir \
    --enable-hkdf \
    --disable-dh \
    --disable-examples --disable-crypttests --disable-sp \
    CFLAGS="-fPIC -fvisibility=hidden \
            -DWOLFSSL_KEY_GEN -DHAVE_ECC_SIGN -DHAVE_ECC_VERIFY \
            -DHAVE_ECC_DHE -DHAVE_ECC_KEY_IMPORT -DHAVE_ECC_KEY_EXPORT \
            -DWC_RSA_PSS -DWC_RSA_NO_PADDING \
            -DWOLFSSL_SHA224 -DWOLFSSL_SHA384 -DWOLFSSL_SHA512 \
            -DHAVE_HKDF -DWOLFSSL_AES_COUNTER -DHAVE_AES_ECB \
            -DHAVE_ECC521 -DHAVE_ALL_CURVES \
            -DWOLFSSL_PUBLIC_MP -DWOLFSSL_AES_DIRECT \
            -DWOLFSSL_PSS_SALT_LEN_DISCOVER"

echo "==> Building libwolfssl.a..."
make -j"$(nproc)"

if [ -f src/.libs/libwolfssl.a ]; then
    echo "==> Done. libwolfssl.a is at ${WOLFSSL_DIR}/src/.libs/libwolfssl.a"
else
    echo "error: libwolfssl.a not found after build" >&2
    exit 1
fi

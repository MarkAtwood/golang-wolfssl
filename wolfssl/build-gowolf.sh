#!/bin/bash
# build-gowolf.sh — compile gowolfcrypto.c + libwolfssl.a into a .syso
#
# Usage: ./build-gowolf.sh [--no-install]
#
# Outputs goboringcrypto_linux_<GOARCH>.syso and copies it to
# src/crypto/internal/boring/syso/ unless --no-install is given.
#
# Prerequisites:
#   - Run bootstrap.sh first to clone, patch, and build wolfSSL.
#   - clang, ld (binutils), nm, objcopy must be on PATH.

set -euo pipefail

# ---- Paths (all relative to this script) ------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${SCRIPT_DIR}/.."
WOLFSSL_SRC="${SCRIPT_DIR}/wolfssl-src"
WOLFSSL_LIB="${WOLFSSL_SRC}/src/.libs/libwolfssl.a"
SHIM_SRC="${REPO_ROOT}/src/crypto/internal/boring/syso/gowolfcrypto.c.src"
SYSO_DIR="${REPO_ROOT}/src/crypto/internal/boring/syso"

# ---- Options ----------------------------------------------------------------

INSTALL=1
for arg in "$@"; do
    case "${arg}" in
        --no-install) INSTALL=0 ;;
        *) echo "Unknown argument: ${arg}" >&2; exit 1 ;;
    esac
done

# ---- Detect GOARCH ----------------------------------------------------------

case "$(uname -m)" in
    x86_64)  GOARCH=amd64 ;;
    aarch64) GOARCH=arm64 ;;
    *)
        echo "error: unsupported architecture: $(uname -m)" >&2
        exit 1
        ;;
esac
SYSO_NAME="goboringcrypto_linux_${GOARCH}.syso"

# ---- Prerequisite checks ----------------------------------------------------

if [ ! -f "${WOLFSSL_LIB}" ]; then
    echo "error: ${WOLFSSL_LIB} not found" >&2
    echo "  Run bootstrap.sh first to clone and build wolfSSL." >&2
    exit 1
fi

for tool in clang ld nm objcopy; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "error: required tool not found on PATH: ${tool}" >&2
        exit 1
    fi
done

# ---- Build in a temporary directory -----------------------------------------

BUILD_DIR="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '${BUILD_DIR}'" EXIT
cd "${BUILD_DIR}"

# Step 1: Compile the C shim.
echo "==> [1/4] Compiling gowolfcrypto.c..."
clang -c -fPIC \
    -O2 \
    -fno-strict-aliasing \
    -Wall -Wextra -Wno-unused-parameter \
    -I "${WOLFSSL_SRC}" \
    -I "${WOLFSSL_SRC}/wolfssl" \
    -o gowolfcrypto.o \
    "${SHIM_SRC}"

# Step 2: Merge shim + all of libwolfssl.a into one relocatable object.
echo "==> [2/4] Merging with libwolfssl.a..."
ld -r -nostdlib --whole-archive \
    gowolfcrypto.o \
    "${WOLFSSL_LIB}" \
    -o gowolfcrypto_combined.o

# Step 3: Collect _goboringcrypto_* text symbols.
echo "==> [3/4] Collecting API symbols..."
nm gowolfcrypto_combined.o \
    | awk '/ T _goboringcrypto_/ { print $3 }' \
    > globals.txt

count=$(wc -l < globals.txt)
echo "    ${count} _goboringcrypto_* symbols found"

if [ "${count}" -lt 100 ]; then
    echo "error: expected >=100 API symbols, got ${count}" >&2
    echo "  Check that gowolfcrypto.c compiled without errors." >&2
    exit 1
fi

# Step 4: Hide all non-API symbols.
echo "==> [4/4] Stripping internal symbols..."

objcopy --remove-section=.llvm_addrsig \
    gowolfcrypto_combined.o gowolfcrypto1.o 2>/dev/null \
    || cp gowolfcrypto_combined.o gowolfcrypto1.o

objcopy \
    --keep-global-symbols=globals.txt \
    --strip-unneeded \
    gowolfcrypto1.o \
    "${SYSO_NAME}"

# ---- Verify: zero non-API globals -------------------------------------------

leaked=$(nm "${SYSO_NAME}" \
    | awk '/ [TBDRCG] / && !/ T _goboringcrypto_/ { print }' \
    | wc -l)
if [ "${leaked}" -ne 0 ]; then
    echo "error: ${leaked} non-API global symbol(s) leaked into .syso:" >&2
    nm "${SYSO_NAME}" | awk '/ [TBDRCG] / && !/ T _goboringcrypto_/ { print }' >&2
    exit 1
fi

api_count=$(nm "${SYSO_NAME}" | awk '/ T _goboringcrypto_/ { n++ } END { print n+0 }')
echo "    Verification passed: ${api_count} API symbols, 0 non-API globals"
ls -lh "${SYSO_NAME}"

# ---- Install ----------------------------------------------------------------

if [ "${INSTALL}" -eq 1 ]; then
    cp "${SYSO_NAME}" "${SYSO_DIR}/${SYSO_NAME}"
    echo "==> Installed to ${SYSO_DIR}/${SYSO_NAME}"
fi

echo "==> Done."

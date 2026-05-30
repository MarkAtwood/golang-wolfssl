// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build boringcrypto && linux && (amd64 || arm64) && !android && !msan

package boring

/*
#include "goboringcrypto.h"

int
_goboringcrypto_gosha1(void *p, size_t n, void *out)
{
	GO_SHA_CTX ctx;
	ctx.internal = 0;
	if (!_goboringcrypto_SHA1_Init(&ctx)) return 0;
	int ok = _goboringcrypto_SHA1_Update(&ctx, p, n) &&
		_goboringcrypto_SHA1_Final(out, &ctx);
	_goboringcrypto_SHA1_Cleanup(&ctx);
	return ok;
}

int
_goboringcrypto_gosha224(void *p, size_t n, void *out)
{
	GO_SHA256_CTX ctx;
	ctx.internal = 0;
	if (!_goboringcrypto_SHA224_Init(&ctx)) return 0;
	int ok = _goboringcrypto_SHA224_Update(&ctx, p, n) &&
		_goboringcrypto_SHA224_Final(out, &ctx);
	_goboringcrypto_SHA256_Cleanup(&ctx);
	return ok;
}

int
_goboringcrypto_gosha256(void *p, size_t n, void *out)
{
	GO_SHA256_CTX ctx;
	ctx.internal = 0;
	if (!_goboringcrypto_SHA256_Init(&ctx)) return 0;
	int ok = _goboringcrypto_SHA256_Update(&ctx, p, n) &&
		_goboringcrypto_SHA256_Final(out, &ctx);
	_goboringcrypto_SHA256_Cleanup(&ctx);
	return ok;
}

int
_goboringcrypto_gosha384(void *p, size_t n, void *out)
{
	GO_SHA512_CTX ctx;
	ctx.internal = 0;
	if (!_goboringcrypto_SHA384_Init(&ctx)) return 0;
	int ok = _goboringcrypto_SHA384_Update(&ctx, p, n) &&
		_goboringcrypto_SHA384_Final(out, &ctx);
	_goboringcrypto_SHA512_Cleanup(&ctx);
	return ok;
}

int
_goboringcrypto_gosha512(void *p, size_t n, void *out)
{
	GO_SHA512_CTX ctx;
	ctx.internal = 0;
	if (!_goboringcrypto_SHA512_Init(&ctx)) return 0;
	int ok = _goboringcrypto_SHA512_Update(&ctx, p, n) &&
		_goboringcrypto_SHA512_Final(out, &ctx);
	_goboringcrypto_SHA512_Cleanup(&ctx);
	return ok;
}

*/
import "C"
import (
	"errors"
	"hash"
	"internal/byteorder"
	"runtime"
	"unsafe"
)

// NOTE: The cgo calls in this file are arranged to avoid marking the parameters as escaping.
// To do that, we call noescape (including via addr).
// We must also make sure that the data pointer arguments have the form unsafe.Pointer(&...)
// so that cgo does not annotate them with cgoCheckPointer calls. If it did that, it might look
// beyond the byte slice and find Go pointers in unprocessed parts of a larger allocation.
// To do both of these simultaneously, the idiom is unsafe.Pointer(&*addr(p)),
// where addr returns the base pointer of p, substituting a non-nil pointer for nil,
// and applying a noescape along the way.
// This is all to preserve compatibility with the allocation behavior of the non-boring implementations.

func SHA1(p []byte) (sum [20]byte) {
	if C._goboringcrypto_gosha1(unsafe.Pointer(&*addr(p)), C.size_t(len(p)), unsafe.Pointer(&*addr(sum[:]))) == 0 {
		panic("boringcrypto: SHA1 failed")
	}
	return
}

func SHA224(p []byte) (sum [28]byte) {
	if C._goboringcrypto_gosha224(unsafe.Pointer(&*addr(p)), C.size_t(len(p)), unsafe.Pointer(&*addr(sum[:]))) == 0 {
		panic("boringcrypto: SHA224 failed")
	}
	return
}

func SHA256(p []byte) (sum [32]byte) {
	if C._goboringcrypto_gosha256(unsafe.Pointer(&*addr(p)), C.size_t(len(p)), unsafe.Pointer(&*addr(sum[:]))) == 0 {
		panic("boringcrypto: SHA256 failed")
	}
	return
}

func SHA384(p []byte) (sum [48]byte) {
	if C._goboringcrypto_gosha384(unsafe.Pointer(&*addr(p)), C.size_t(len(p)), unsafe.Pointer(&*addr(sum[:]))) == 0 {
		panic("boringcrypto: SHA384 failed")
	}
	return
}

func SHA512(p []byte) (sum [64]byte) {
	if C._goboringcrypto_gosha512(unsafe.Pointer(&*addr(p)), C.size_t(len(p)), unsafe.Pointer(&*addr(sum[:]))) == 0 {
		panic("boringcrypto: SHA512 failed")
	}
	return
}

// NewSHA1 returns a new SHA1 hash.
func NewSHA1() hash.Hash {
	h := new(sha1Hash)
	h.Reset()
	runtime.SetFinalizer(h, (*sha1Hash).finalize)
	return h
}

type sha1Hash struct {
	ctx C.GO_SHA_CTX
	out [20]byte
}

func (h *sha1Hash) finalize() {
	C._goboringcrypto_SHA1_Cleanup(&h.ctx)
}

func (h *sha1Hash) noescapeCtx() *C.GO_SHA_CTX {
	return (*C.GO_SHA_CTX)(noescape(unsafe.Pointer(&h.ctx)))
}

func (h *sha1Hash) Reset() {
	C._goboringcrypto_SHA1_Cleanup(&h.ctx)
	C._goboringcrypto_SHA1_Init(h.noescapeCtx())
	runtime.KeepAlive(h)
}

func (h *sha1Hash) Size() int             { return 20 }
func (h *sha1Hash) BlockSize() int        { return 64 }
func (h *sha1Hash) Sum(dst []byte) []byte { return h.sum(dst) }

func (h *sha1Hash) Write(p []byte) (int, error) {
	if len(p) > 0 && C._goboringcrypto_SHA1_Update(h.noescapeCtx(), unsafe.Pointer(&*addr(p)), C.size_t(len(p))) == 0 {
		panic("boringcrypto: SHA1_Update failed")
	}
	runtime.KeepAlive(h)
	return len(p), nil
}

func (h0 *sha1Hash) sum(dst []byte) []byte {
	var h sha1Hash
	C._goboringcrypto_SHA1_Copy(&h.ctx, &h0.ctx)
	defer C._goboringcrypto_SHA1_Cleanup(&h.ctx)
	if C._goboringcrypto_SHA1_Final((*C.uint8_t)(noescape(unsafe.Pointer(&h.out[0]))), h.noescapeCtx()) == 0 {
		panic("boringcrypto: SHA1_Final failed")
	}
	runtime.KeepAlive(h0)
	return append(dst, h.out[:]...)
}

const (
	sha1Magic         = "sha\x01"
	sha1MarshaledSize = len(sha1Magic) + 5*4 + 64 + 8
)

func (h *sha1Hash) MarshalBinary() ([]byte, error) {
	return h.AppendBinary(make([]byte, 0, sha1MarshaledSize))
}

func (h *sha1Hash) AppendBinary(b []byte) ([]byte, error) {
	var hh [5]C.uint32_t
	var x [64]C.uint8_t
	var nx, nl, nh C.uint32_t
	C._goboringcrypto_SHA1_get_state(&h.ctx, &hh[0], &x[0], &nx, &nl, &nh)
	runtime.KeepAlive(h)
	b = append(b, sha1Magic...)
	for i := 0; i < 5; i++ {
		b = byteorder.BEAppendUint32(b, uint32(hh[i]))
	}
	buf := make([]byte, 64)
	for i := 0; i < 64; i++ {
		buf[i] = byte(x[i])
	}
	b = append(b, buf[:nx]...)
	b = append(b, make([]byte, 64-int(nx))...)
	// WolfSSL stores byte count in loLen/hiLen (not bit count like BoringSSL)
	b = byteorder.BEAppendUint64(b, uint64(nl)|uint64(nh)<<32)
	return b, nil
}

func (h *sha1Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(sha1Magic) || string(b[:len(sha1Magic)]) != sha1Magic {
		return errors.New("crypto/sha1: invalid hash state identifier")
	}
	if len(b) != sha1MarshaledSize {
		return errors.New("crypto/sha1: invalid hash state size")
	}
	b = b[len(sha1Magic):]
	var hh [5]C.uint32_t
	var x [64]C.uint8_t
	for i := 0; i < 5; i++ {
		b, hh[i] = b[4:], C.uint32_t(byteorder.BEUint32(b))
	}
	for i := 0; i < 64; i++ {
		x[i] = C.uint8_t(b[i])
	}
	b = b[64:]
	n := byteorder.BEUint64(b)
	// WolfSSL stores byte count directly (not bit count)
	nl := C.uint32_t(n)
	nh := C.uint32_t(n >> 32)
	nx := C.uint32_t(uint32(n) % 64)
	C._goboringcrypto_SHA1_set_state(&h.ctx, &hh[0], &x[0], nx, nl, nh)
	runtime.KeepAlive(h)
	return nil
}

// NewSHA224 returns a new SHA224 hash.
func NewSHA224() hash.Hash {
	h := new(sha224Hash)
	h.Reset()
	runtime.SetFinalizer(h, (*sha224Hash).finalize)
	return h
}

type sha224Hash struct {
	ctx C.GO_SHA256_CTX
	out [224 / 8]byte
}

func (h *sha224Hash) finalize() {
	C._goboringcrypto_SHA256_Cleanup(&h.ctx)
}

func (h *sha224Hash) noescapeCtx() *C.GO_SHA256_CTX {
	return (*C.GO_SHA256_CTX)(noescape(unsafe.Pointer(&h.ctx)))
}

func (h *sha224Hash) Reset() {
	C._goboringcrypto_SHA256_Cleanup(&h.ctx)
	C._goboringcrypto_SHA224_Init(h.noescapeCtx())
	runtime.KeepAlive(h)
}
func (h *sha224Hash) Size() int             { return 224 / 8 }
func (h *sha224Hash) BlockSize() int        { return 64 }
func (h *sha224Hash) Sum(dst []byte) []byte { return h.sum(dst) }

func (h *sha224Hash) Write(p []byte) (int, error) {
	if len(p) > 0 && C._goboringcrypto_SHA224_Update(h.noescapeCtx(), unsafe.Pointer(&*addr(p)), C.size_t(len(p))) == 0 {
		panic("boringcrypto: SHA224_Update failed")
	}
	runtime.KeepAlive(h)
	return len(p), nil
}

func (h0 *sha224Hash) sum(dst []byte) []byte {
	var h sha224Hash
	C._goboringcrypto_SHA224_Copy(&h.ctx, &h0.ctx)
	defer C._goboringcrypto_SHA256_Cleanup(&h.ctx)
	if C._goboringcrypto_SHA224_Final((*C.uint8_t)(noescape(unsafe.Pointer(&h.out[0]))), h.noescapeCtx()) == 0 {
		panic("boringcrypto: SHA224_Final failed")
	}
	runtime.KeepAlive(h0)
	return append(dst, h.out[:]...)
}

// NewSHA256 returns a new SHA256 hash.
func NewSHA256() hash.Hash {
	h := new(sha256Hash)
	h.Reset()
	runtime.SetFinalizer(h, (*sha256Hash).finalize)
	return h
}

type sha256Hash struct {
	ctx C.GO_SHA256_CTX
	out [256 / 8]byte
}

func (h *sha256Hash) finalize() {
	C._goboringcrypto_SHA256_Cleanup(&h.ctx)
}

func (h *sha256Hash) noescapeCtx() *C.GO_SHA256_CTX {
	return (*C.GO_SHA256_CTX)(noescape(unsafe.Pointer(&h.ctx)))
}

func (h *sha256Hash) Reset() {
	C._goboringcrypto_SHA256_Cleanup(&h.ctx)
	C._goboringcrypto_SHA256_Init(h.noescapeCtx())
	runtime.KeepAlive(h)
}
func (h *sha256Hash) Size() int             { return 256 / 8 }
func (h *sha256Hash) BlockSize() int        { return 64 }
func (h *sha256Hash) Sum(dst []byte) []byte { return h.sum(dst) }

func (h *sha256Hash) Write(p []byte) (int, error) {
	if len(p) > 0 && C._goboringcrypto_SHA256_Update(h.noescapeCtx(), unsafe.Pointer(&*addr(p)), C.size_t(len(p))) == 0 {
		panic("boringcrypto: SHA256_Update failed")
	}
	runtime.KeepAlive(h)
	return len(p), nil
}

func (h0 *sha256Hash) sum(dst []byte) []byte {
	var h sha256Hash
	C._goboringcrypto_SHA256_Copy(&h.ctx, &h0.ctx)
	defer C._goboringcrypto_SHA256_Cleanup(&h.ctx)
	if C._goboringcrypto_SHA256_Final((*C.uint8_t)(noescape(unsafe.Pointer(&h.out[0]))), h.noescapeCtx()) == 0 {
		panic("boringcrypto: SHA256_Final failed")
	}
	runtime.KeepAlive(h0)
	return append(dst, h.out[:]...)
}

const (
	magic224         = "sha\x02"
	magic256         = "sha\x03"
	marshaledSize256 = len(magic256) + 8*4 + 64 + 8
)

func sha256GetState(ctx *C.GO_SHA256_CTX) (h [8]uint32, x [64]byte, nx, nl, nh uint32) {
	var ch [8]C.uint32_t
	var cx [64]C.uint8_t
	var cnx, cnl, cnh C.uint32_t
	C._goboringcrypto_SHA256_get_state(ctx, &ch[0], &cx[0], &cnx, &cnl, &cnh)
	for i := 0; i < 8; i++ {
		h[i] = uint32(ch[i])
	}
	for i := 0; i < 64; i++ {
		x[i] = byte(cx[i])
	}
	return h, x, uint32(cnx), uint32(cnl), uint32(cnh)
}

func sha256SetState(ctx *C.GO_SHA256_CTX, h [8]uint32, x [64]byte, nx, nl, nh uint32) {
	var ch [8]C.uint32_t
	var cx [64]C.uint8_t
	for i := 0; i < 8; i++ {
		ch[i] = C.uint32_t(h[i])
	}
	for i := 0; i < 64; i++ {
		cx[i] = C.uint8_t(x[i])
	}
	C._goboringcrypto_SHA256_set_state(ctx, &ch[0], &cx[0], C.uint32_t(nx), C.uint32_t(nl), C.uint32_t(nh))
}

func (h *sha224Hash) MarshalBinary() ([]byte, error) {
	return h.AppendBinary(make([]byte, 0, marshaledSize256))
}

func (h *sha224Hash) AppendBinary(b []byte) ([]byte, error) {
	hh, x, nx, nl, nh := sha256GetState(&h.ctx)
	runtime.KeepAlive(h)
	b = append(b, magic224...)
	for i := 0; i < 8; i++ {
		b = byteorder.BEAppendUint32(b, hh[i])
	}
	b = append(b, x[:nx]...)
	b = append(b, make([]byte, 64-int(nx))...)
	// WolfSSL stores byte count in loLen/hiLen (not bit count like BoringSSL)
	b = byteorder.BEAppendUint64(b, uint64(nl)|uint64(nh)<<32)
	return b, nil
}

func (h *sha256Hash) MarshalBinary() ([]byte, error) {
	return h.AppendBinary(make([]byte, 0, marshaledSize256))
}

func (h *sha256Hash) AppendBinary(b []byte) ([]byte, error) {
	hh, x, nx, nl, nh := sha256GetState(&h.ctx)
	runtime.KeepAlive(h)
	b = append(b, magic256...)
	for i := 0; i < 8; i++ {
		b = byteorder.BEAppendUint32(b, hh[i])
	}
	b = append(b, x[:nx]...)
	b = append(b, make([]byte, 64-int(nx))...)
	// WolfSSL stores byte count in loLen/hiLen (not bit count like BoringSSL)
	b = byteorder.BEAppendUint64(b, uint64(nl)|uint64(nh)<<32)
	return b, nil
}

func (h *sha224Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic224) || string(b[:len(magic224)]) != magic224 {
		return errors.New("crypto/sha256: invalid hash state identifier")
	}
	if len(b) != marshaledSize256 {
		return errors.New("crypto/sha256: invalid hash state size")
	}
	b = b[len(magic224):]
	var hh [8]uint32
	for i := 0; i < 8; i++ {
		b, hh[i] = consumeUint32(b)
	}
	var x [64]byte
	copy(x[:], b[:64])
	b = b[64:]
	b2, n := consumeUint64(b)
	_ = b2
	// WolfSSL stores byte count directly (not bit count)
	sha256SetState(&h.ctx, hh, x, uint32(n)%64, uint32(n), uint32(n>>32))
	runtime.KeepAlive(h)
	return nil
}

func (h *sha256Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic256) || string(b[:len(magic256)]) != magic256 {
		return errors.New("crypto/sha256: invalid hash state identifier")
	}
	if len(b) != marshaledSize256 {
		return errors.New("crypto/sha256: invalid hash state size")
	}
	b = b[len(magic256):]
	var hh [8]uint32
	for i := 0; i < 8; i++ {
		b, hh[i] = consumeUint32(b)
	}
	var x [64]byte
	copy(x[:], b[:64])
	b = b[64:]
	b2, n := consumeUint64(b)
	_ = b2
	// WolfSSL stores byte count directly (not bit count)
	sha256SetState(&h.ctx, hh, x, uint32(n)%64, uint32(n), uint32(n>>32))
	runtime.KeepAlive(h)
	return nil
}

// NewSHA384 returns a new SHA384 hash.
func NewSHA384() hash.Hash {
	h := new(sha384Hash)
	h.Reset()
	runtime.SetFinalizer(h, (*sha384Hash).finalize)
	return h
}

type sha384Hash struct {
	ctx C.GO_SHA512_CTX
	out [384 / 8]byte
}

func (h *sha384Hash) finalize() {
	C._goboringcrypto_SHA512_Cleanup(&h.ctx)
}

func (h *sha384Hash) noescapeCtx() *C.GO_SHA512_CTX {
	return (*C.GO_SHA512_CTX)(noescape(unsafe.Pointer(&h.ctx)))
}

func (h *sha384Hash) Reset() {
	C._goboringcrypto_SHA512_Cleanup(&h.ctx)
	C._goboringcrypto_SHA384_Init(h.noescapeCtx())
	runtime.KeepAlive(h)
}
func (h *sha384Hash) Size() int             { return 384 / 8 }
func (h *sha384Hash) BlockSize() int        { return 128 }
func (h *sha384Hash) Sum(dst []byte) []byte { return h.sum(dst) }

func (h *sha384Hash) Write(p []byte) (int, error) {
	if len(p) > 0 && C._goboringcrypto_SHA384_Update(h.noescapeCtx(), unsafe.Pointer(&*addr(p)), C.size_t(len(p))) == 0 {
		panic("boringcrypto: SHA384_Update failed")
	}
	runtime.KeepAlive(h)
	return len(p), nil
}

func (h0 *sha384Hash) sum(dst []byte) []byte {
	var h sha384Hash
	C._goboringcrypto_SHA384_Copy(&h.ctx, &h0.ctx)
	defer C._goboringcrypto_SHA512_Cleanup(&h.ctx)
	if C._goboringcrypto_SHA384_Final((*C.uint8_t)(noescape(unsafe.Pointer(&h.out[0]))), h.noescapeCtx()) == 0 {
		panic("boringcrypto: SHA384_Final failed")
	}
	runtime.KeepAlive(h0)
	return append(dst, h.out[:]...)
}

// NewSHA512 returns a new SHA512 hash.
func NewSHA512() hash.Hash {
	h := new(sha512Hash)
	h.Reset()
	runtime.SetFinalizer(h, (*sha512Hash).finalize)
	return h
}

type sha512Hash struct {
	ctx C.GO_SHA512_CTX
	out [512 / 8]byte
}

func (h *sha512Hash) finalize() {
	C._goboringcrypto_SHA512_Cleanup(&h.ctx)
}

func (h *sha512Hash) noescapeCtx() *C.GO_SHA512_CTX {
	return (*C.GO_SHA512_CTX)(noescape(unsafe.Pointer(&h.ctx)))
}

func (h *sha512Hash) Reset() {
	C._goboringcrypto_SHA512_Cleanup(&h.ctx)
	C._goboringcrypto_SHA512_Init(h.noescapeCtx())
	runtime.KeepAlive(h)
}
func (h *sha512Hash) Size() int             { return 512 / 8 }
func (h *sha512Hash) BlockSize() int        { return 128 }
func (h *sha512Hash) Sum(dst []byte) []byte { return h.sum(dst) }

func (h *sha512Hash) Write(p []byte) (int, error) {
	if len(p) > 0 && C._goboringcrypto_SHA512_Update(h.noescapeCtx(), unsafe.Pointer(&*addr(p)), C.size_t(len(p))) == 0 {
		panic("boringcrypto: SHA512_Update failed")
	}
	runtime.KeepAlive(h)
	return len(p), nil
}

func (h0 *sha512Hash) sum(dst []byte) []byte {
	var h sha512Hash
	C._goboringcrypto_SHA512_Copy(&h.ctx, &h0.ctx)
	defer C._goboringcrypto_SHA512_Cleanup(&h.ctx)
	if C._goboringcrypto_SHA512_Final((*C.uint8_t)(noescape(unsafe.Pointer(&h.out[0]))), h.noescapeCtx()) == 0 {
		panic("boringcrypto: SHA512_Final failed")
	}
	runtime.KeepAlive(h0)
	return append(dst, h.out[:]...)
}

const (
	magic384         = "sha\x04"
	magic512_224     = "sha\x05"
	magic512_256     = "sha\x06"
	magic512         = "sha\x07"
	marshaledSize512 = len(magic512) + 8*8 + 128 + 8
)

func sha512GetState(ctx *C.GO_SHA512_CTX) (h [8]uint64, x [128]byte, nx uint32, nl, nh uint64) {
	var ch [8]C.uint64_t
	var cx [128]C.uint8_t
	var cnx C.uint32_t
	var cnl, cnh C.uint64_t
	C._goboringcrypto_SHA512_get_state(ctx, &ch[0], &cx[0], &cnx, &cnl, &cnh)
	for i := 0; i < 8; i++ {
		h[i] = uint64(ch[i])
	}
	for i := 0; i < 128; i++ {
		x[i] = byte(cx[i])
	}
	return h, x, uint32(cnx), uint64(cnl), uint64(cnh)
}

func sha512SetState(ctx *C.GO_SHA512_CTX, h [8]uint64, x [128]byte, nx uint32, nl, nh uint64) {
	var ch [8]C.uint64_t
	var cx [128]C.uint8_t
	for i := 0; i < 8; i++ {
		ch[i] = C.uint64_t(h[i])
	}
	for i := 0; i < 128; i++ {
		cx[i] = C.uint8_t(x[i])
	}
	C._goboringcrypto_SHA512_set_state(ctx, &ch[0], &cx[0], C.uint32_t(nx), C.uint64_t(nl), C.uint64_t(nh))
}

func (h *sha384Hash) MarshalBinary() ([]byte, error) {
	return h.AppendBinary(make([]byte, 0, marshaledSize512))
}

func (h *sha384Hash) AppendBinary(b []byte) ([]byte, error) {
	hh, x, nx, nl, nh := sha512GetState(&h.ctx)
	runtime.KeepAlive(h)
	b = append(b, magic384...)
	for i := 0; i < 8; i++ {
		b = byteorder.BEAppendUint64(b, hh[i])
	}
	b = append(b, x[:nx]...)
	b = append(b, make([]byte, 128-int(nx))...)
	// WolfSSL stores byte count in loLen/hiLen (not bit count like BoringSSL)
	b = byteorder.BEAppendUint64(b, nl|nh<<32)
	return b, nil
}

func (h *sha512Hash) MarshalBinary() ([]byte, error) {
	return h.AppendBinary(make([]byte, 0, marshaledSize512))
}

func (h *sha512Hash) AppendBinary(b []byte) ([]byte, error) {
	hh, x, nx, nl, nh := sha512GetState(&h.ctx)
	runtime.KeepAlive(h)
	b = append(b, magic512...)
	for i := 0; i < 8; i++ {
		b = byteorder.BEAppendUint64(b, hh[i])
	}
	b = append(b, x[:nx]...)
	b = append(b, make([]byte, 128-int(nx))...)
	// WolfSSL stores byte count in loLen/hiLen (not bit count like BoringSSL)
	b = byteorder.BEAppendUint64(b, nl|nh<<32)
	return b, nil
}

func (h *sha384Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic512) {
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	if string(b[:len(magic384)]) != magic384 {
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	if len(b) != marshaledSize512 {
		return errors.New("crypto/sha512: invalid hash state size")
	}
	b = b[len(magic512):]
	var hh [8]uint64
	for i := 0; i < 8; i++ {
		b, hh[i] = consumeUint64(b)
	}
	var x [128]byte
	copy(x[:], b[:128])
	b = b[128:]
	b2, n := consumeUint64(b)
	_ = b2
	// WolfSSL stores byte count directly (not bit count)
	sha512SetState(&h.ctx, hh, x, uint32(n)%128, n, 0)
	runtime.KeepAlive(h)
	return nil
}

func (h *sha512Hash) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic512) {
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	if string(b[:len(magic512)]) != magic512 {
		return errors.New("crypto/sha512: invalid hash state identifier")
	}
	if len(b) != marshaledSize512 {
		return errors.New("crypto/sha512: invalid hash state size")
	}
	b = b[len(magic512):]
	var hh [8]uint64
	for i := 0; i < 8; i++ {
		b, hh[i] = consumeUint64(b)
	}
	var x [128]byte
	copy(x[:], b[:128])
	b = b[128:]
	b2, n := consumeUint64(b)
	_ = b2
	// WolfSSL stores byte count directly (not bit count)
	sha512SetState(&h.ctx, hh, x, uint32(n)%128, n, 0)
	runtime.KeepAlive(h)
	return nil
}

func consumeUint64(b []byte) ([]byte, uint64) {
	return b[8:], byteorder.BEUint64(b)
}

func consumeUint32(b []byte) ([]byte, uint32) {
	return b[4:], byteorder.BEUint32(b)
}

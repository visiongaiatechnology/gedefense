//go:build linux && cgo

package main

/*
#cgo LDFLAGS: -l:libargon2.so.1
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int argon2id_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                      const uint32_t parallelism, const void *pwd,
                      const size_t pwdlen, const void *salt,
                      const size_t saltlen, void *hash, const size_t hashlen);
const char *argon2_error_message(int error_code);
*/
import "C"

import (
	"errors"
	"unsafe"
)

func argon2IDKey(password, salt []byte, timeCost, memoryKiB, parallelism uint32, keyLen int) ([]byte, error) {
	if len(password) == 0 || len(salt) < 16 || keyLen < 16 || keyLen > 64 {
		return nil, errors.New("invalid Argon2id parameters")
	}
	pwd := C.CBytes(password)
	saltPtr := C.CBytes(salt)
	out := C.malloc(C.size_t(keyLen))
	if pwd == nil || saltPtr == nil || out == nil {
		if pwd != nil {
			C.free(pwd)
		}
		if saltPtr != nil {
			C.free(saltPtr)
		}
		if out != nil {
			C.free(out)
		}
		return nil, errors.New("Argon2id allocation failed")
	}
	defer func() {
		C.memset(pwd, 0, C.size_t(len(password)))
		C.memset(saltPtr, 0, C.size_t(len(salt)))
		C.memset(out, 0, C.size_t(keyLen))
		C.free(pwd)
		C.free(saltPtr)
		C.free(out)
	}()
	code := C.argon2id_hash_raw(
		C.uint32_t(timeCost), C.uint32_t(memoryKiB), C.uint32_t(parallelism),
		pwd, C.size_t(len(password)), saltPtr, C.size_t(len(salt)), out, C.size_t(keyLen),
	)
	if code != 0 {
		message := C.GoString(C.argon2_error_message(code))
		return nil, errors.New(message)
	}
	return C.GoBytes(out, C.int(keyLen)), nil
}

var _ unsafe.Pointer

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func loadOrCreateToken(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("dashboard token path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := rejectSymlink(path); err != nil {
		return "", err
	}
	if b, err := os.ReadFile(path); err == nil {
		st, statErr := os.Stat(path)
		if statErr != nil {
			return "", statErr
		}
		if !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
			return "", errors.New("dashboard token must be a private regular file")
		}
		token := strings.TrimSpace(string(b))
		raw, decodeErr := base64.RawURLEncoding.DecodeString(token)
		if decodeErr != nil || len(raw) != 32 {
			return "", errors.New("dashboard token must encode exactly 256 bits")
		}
		return token, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	if err := atomicWriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", err
	}
	return token, nil
}

func tokenEqual(got, want string) bool {
	gotDigest := sha256.Sum256([]byte(got))
	wantDigest := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(gotDigest[:], wantDigest[:]) == 1
}

// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type passwordRecord struct {
	algorithm   string
	iterations  int
	memoryKiB   uint32
	timeCost    uint32
	parallelism uint32
	salt        []byte
	digest      []byte
}

// FIND-010 (VGT-AUDIT-20261114-GD51): password verification is memory-hard. One
// Argon2id call allocates 64 MiB (gateway/argon2_linux.go), so an unauthenticated
// flood of sign-in attempts used to start one such allocation per request and could
// exhaust the node before a single credential was checked. Every pre-authentication
// verification now takes a slot from one process-wide budget, and a per-source
// in-flight reservation is recorded before any KDF memory is touched. Waiting is
// bounded by the request context and by kdfQueueTimeout; a refused sign-in is
// answered with 429/503 and Retry-After and never reaches the memory-hard path.
const (
	maxConcurrentKDF            = 4
	maxConcurrentKDFPerIdentity = 2
	maxKDFIdentities            = 1024
	kdfQueueTimeout             = 2 * time.Second
)

var (
	errKDFOverloaded   = errors.New("password verification capacity exhausted")
	errKDFIdentityBusy = errors.New("too many concurrent sign-ins from this source")
)

type kdfGate struct {
	slots          chan struct{}
	mu             sync.Mutex
	active         map[string]int
	maxIdentities  int
	maxPerIdentity int
	queueTimeout   time.Duration
	inFlight       int
	maxObserved    int
}

func newKDFGate(limit int) *kdfGate {
	if limit <= 0 {
		limit = maxConcurrentKDF
	}
	return &kdfGate{
		slots:          make(chan struct{}, limit),
		active:         make(map[string]int),
		maxIdentities:  maxKDFIdentities,
		maxPerIdentity: maxConcurrentKDFPerIdentity,
		queueTimeout:   kdfQueueTimeout,
	}
}

func (g *gateway) ensureKDF() {
	g.kdfOnce.Do(func() {
		if g.kdf == nil {
			g.kdf = newKDFGate(maxConcurrentKDF)
		}
	})
}

// reserve records the per-identity in-flight attempt before any KDF work starts.
// The map only holds identities that are currently waiting for or running a
// verification, so a distributed flood cannot grow it without bound.
func (k *kdfGate) reserve(identity string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.active[identity] >= k.maxPerIdentity {
		return errKDFIdentityBusy
	}
	if k.active[identity] == 0 && len(k.active) >= k.maxIdentities {
		return errKDFOverloaded
	}
	k.active[identity]++
	return nil
}

func (k *kdfGate) releaseIdentity(identity string) {
	k.mu.Lock()
	if n := k.active[identity]; n <= 1 {
		delete(k.active, identity)
	} else {
		k.active[identity] = n - 1
	}
	k.mu.Unlock()
}

// acquire reserves the identity, then waits for one of the global KDF slots.
// The returned release function is idempotent so a deferred release can never
// return the same slot twice.
func (k *kdfGate) acquire(ctx context.Context, identity string) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := k.reserve(identity); err != nil {
		return nil, err
	}
	wait := k.queueTimeout
	if wait <= 0 {
		select {
		case k.slots <- struct{}{}:
			return k.enter(identity), nil
		default:
			k.releaseIdentity(identity)
			return nil, errKDFOverloaded
		}
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case k.slots <- struct{}{}:
		return k.enter(identity), nil
	case <-ctx.Done():
		k.releaseIdentity(identity)
		return nil, ctx.Err()
	case <-timer.C:
		k.releaseIdentity(identity)
		return nil, errKDFOverloaded
	}
}

func (k *kdfGate) enter(identity string) func() {
	k.mu.Lock()
	k.inFlight++
	if k.inFlight > k.maxObserved {
		k.maxObserved = k.inFlight
	}
	k.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			<-k.slots
			k.mu.Lock()
			if k.inFlight > 0 {
				k.inFlight--
			}
			k.mu.Unlock()
			k.releaseIdentity(identity)
		})
	}
}

// stats reports the current and high-water number of concurrent verifications.
// The high-water mark is what the backpressure regression test asserts on.
func (k *kdfGate) stats() (inFlight, maxObserved int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.inFlight, k.maxObserved
}

func readPrivateRegular(path string, min, max int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("file must be private, regular and non-symlink")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("file permissions must be 0600 or stricter")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < min || len(data) > max {
		return nil, errors.New("file size outside accepted bounds")
	}
	return data, nil
}

func loadPasswordRecord(path string) (passwordRecord, error) {
	data, err := readPrivateRegular(path, 32, 2048)
	if err != nil {
		return passwordRecord{}, err
	}
	value := strings.TrimSpace(string(data))
	parts := strings.Split(value, "$")
	if len(parts) == 5 && parts[0] == "v1" && parts[1] == "pbkdf2-sha256" {
		iterations, err := strconv.Atoi(parts[2])
		if err != nil || iterations < 300000 || iterations > 2000000 {
			return passwordRecord{}, errors.New("invalid PBKDF2 iteration count")
		}
		salt, err := decodeBase64(parts[3])
		if err != nil || len(salt) < 16 || len(salt) > 64 {
			return passwordRecord{}, errors.New("invalid PBKDF2 salt")
		}
		digest, err := decodeBase64(parts[4])
		if err != nil || len(digest) != 32 {
			return passwordRecord{}, errors.New("invalid PBKDF2 digest")
		}
		return passwordRecord{algorithm: "pbkdf2-sha256", iterations: iterations, salt: salt, digest: digest}, nil
	}
	if len(parts) == 7 && parts[0] == "v2" && parts[1] == "argon2id" && parts[2] == "v=19" {
		var memory, timeCost, parallelism uint32
		if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &parallelism); err != nil {
			return passwordRecord{}, errors.New("invalid Argon2id parameters")
		}
		if memory < 32768 || memory > 262144 || timeCost < 2 || timeCost > 10 || parallelism < 1 || parallelism > 8 {
			return passwordRecord{}, errors.New("Argon2id parameters outside policy")
		}
		salt, err := decodeBase64(parts[4])
		if err != nil || len(salt) < 16 || len(salt) > 64 {
			return passwordRecord{}, errors.New("invalid Argon2id salt")
		}
		digest, err := decodeBase64(parts[5])
		if err != nil || len(digest) != 32 || parts[6] != "" {
			return passwordRecord{}, errors.New("invalid Argon2id digest")
		}
		return passwordRecord{algorithm: "argon2id", memoryKiB: memory, timeCost: timeCost, parallelism: parallelism, salt: salt, digest: digest}, nil
	}
	// Canonical v2 records do not end in '$'; accept exactly six fields.
	if len(parts) == 6 && parts[0] == "v2" && parts[1] == "argon2id" && parts[2] == "v=19" {
		var memory, timeCost, parallelism uint32
		if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &parallelism); err != nil {
			return passwordRecord{}, errors.New("invalid Argon2id parameters")
		}
		if memory < 32768 || memory > 262144 || timeCost < 2 || timeCost > 10 || parallelism < 1 || parallelism > 8 {
			return passwordRecord{}, errors.New("Argon2id parameters outside policy")
		}
		salt, err := decodeBase64(parts[4])
		if err != nil || len(salt) < 16 || len(salt) > 64 {
			return passwordRecord{}, errors.New("invalid Argon2id salt")
		}
		digest, err := decodeBase64(parts[5])
		if err != nil || len(digest) != 32 {
			return passwordRecord{}, errors.New("invalid Argon2id digest")
		}
		return passwordRecord{algorithm: "argon2id", memoryKiB: memory, timeCost: timeCost, parallelism: parallelism, salt: salt, digest: digest}, nil
	}
	return passwordRecord{}, errors.New("invalid password record format")
}

func decodeBase64(value string) ([]byte, error) {
	if out, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return out, nil
	}
	return base64.StdEncoding.DecodeString(value)
}

// verifyPasswordGated is the only pre-authentication entry point to the memory-hard
// password verification: it reserves a process-wide KDF slot and a per-source in-flight
// reservation before the 64 MiB Argon2id allocation happens (FIND-010). A non-nil error
// means the attempt was never verified and the caller must answer with backpressure.
func (g *gateway) verifyPasswordGated(ctx context.Context, identity string, password []byte) (bool, error) {
	g.ensureKDF()
	release, err := g.kdf.acquire(ctx, identity)
	if err != nil {
		return false, err
	}
	defer release()
	g.passwordMu.RLock()
	rec := g.password
	g.passwordMu.RUnlock()
	return verifyPassword(password, rec), nil
}

func verifyPassword(password []byte, rec passwordRecord) bool {
	var derived []byte
	var err error
	switch rec.algorithm {
	case "argon2id":
		derived, err = argon2IDKey(password, rec.salt, rec.timeCost, rec.memoryKiB, rec.parallelism, len(rec.digest))
	case "pbkdf2-sha256":
		derived = pbkdf2SHA256(password, rec.salt, rec.iterations, len(rec.digest))
	default:
		return false
	}
	if err != nil {
		return false
	}
	ok := subtle.ConstantTimeCompare(derived, rec.digest) == 1
	zero(derived)
	return ok
}

func createArgon2PasswordRecord(password []byte) (string, error) {
	const memoryKiB uint32 = 65536
	const timeCost uint32 = 3
	const parallelism uint32 = 1
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	digest, err := argon2IDKey(password, salt, timeCost, memoryKiB, parallelism, 32)
	if err != nil {
		return "", err
	}
	defer zero(digest)
	return fmt.Sprintf("v2$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memoryKiB, timeCost, parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(digest)), nil
}

func persistArgon2PasswordRecord(path string, password []byte) error {
	_, err := persistAndParseArgon2PasswordRecord(path, password)
	return err
}

func persistAndParseArgon2PasswordRecord(path string, password []byte) (passwordRecord, error) {
	const memoryKiB uint32 = 65536
	const timeCost uint32 = 3
	const parallelism uint32 = 1
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return passwordRecord{}, err
	}
	digest, err := argon2IDKey(password, salt, timeCost, memoryKiB, parallelism, 32)
	if err != nil {
		return passwordRecord{}, err
	}
	record := fmt.Sprintf("v2$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memoryKiB, timeCost, parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(digest))
	if err := writeAtomic(path, []byte(record+"\n"), 0o600); err != nil {
		zero(digest)
		return passwordRecord{}, err
	}
	return passwordRecord{
		algorithm:   "argon2id",
		memoryKiB:   memoryKiB,
		timeCost:    timeCost,
		parallelism: parallelism,
		salt:        salt,
		digest:      digest,
	}, nil
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	blocks := (keyLen + sha256.Size - 1) / sha256.Size
	result := make([]byte, 0, blocks*sha256.Size)
	for block := 1; block <= blocks; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		result = append(result, t...)
		zero(u)
		zero(t)
	}
	return result[:keyLen]
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func randomToken(size int) (string, error) {
	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

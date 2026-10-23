package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// readDashboardToken reads and validates the dashboard token the way the start-up path does: a
// private regular file, no group or world bits, carrying exactly 256 bits of base64url. It is the
// single validation path, so a rotated file is held to the same standard as one created at start-up.
func readDashboardToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	st, statErr := os.Stat(path)
	if statErr != nil {
		return "", statErr
	}
	if !st.Mode().IsRegular() {
		return "", errors.New("dashboard token must be a private regular file")
	}
	// Owner-only, or group-readable after the documented identity split. World access is never allowed,
	// and the owner keeps write access so the control plane can replace the file atomically.
	if perm := st.Mode().Perm(); (perm != 0o600 && perm != 0o640) || perm&0o007 != 0 || perm&0o200 == 0 {
		return "", errors.New("dashboard token must be owner-only or group-readable without world access")
	}
	token := strings.TrimSpace(string(b))
	raw, decodeErr := base64.RawURLEncoding.DecodeString(token)
	if decodeErr != nil || len(raw) != 32 {
		return "", errors.New("dashboard token must encode exactly 256 bits")
	}
	return token, nil
}

// RotateDashboardToken writes a fresh 256-bit token and returns it. The running platform re-reads the
// file on every authenticated request, so replacing it ends every existing session immediately - which
// is the only reason a rotation is worth anything. An operator performs it by replacing the file;
// nothing has to be restarted.
func RotateDashboardToken(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("dashboard token path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := rejectSymlink(path); err != nil {
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

// adoptDashboardToken hands a freshly written token to the account that has to present it. The gateway
// refuses anything that is not owner-only - "backend token: file permissions must be 0600 or stricter" -
// so the token becomes the gateway's property with mode 0600.
//
// The control plane loses nothing by giving it away: it holds cap_dac_override, cap_chown and
// cap_fowner, so it can still read, replace and rotate a file it does not own. An empty owner means the
// token stays exactly as it always was.
//
// The caller supplies the account; nothing is detected. Deriving it from the presence of a user would
// make both the runtime behaviour and the test suite depend on the user table of the machine.
func adoptDashboardToken(path, owner string) error {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return nil
	}
	looked, err := user.Lookup(owner)
	if err != nil {
		return err
	}
	uid, uidErr := strconv.Atoi(looked.Uid)
	gid, gidErr := strconv.Atoi(looked.Gid)
	if uidErr != nil || gidErr != nil {
		return errors.New("dashboard token owner cannot be resolved")
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

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
	if token, err := readDashboardToken(path); err == nil {
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

// randomBytesHex returns n cryptographically random bytes as lowercase hex.
// A failure of the system random source is fatal: every caller uses the result
// as a name or token that must not be guessable.
func randomBytesHex(n int) (string, error) {
	if n <= 0 || n > 64 {
		return "", errors.New("random byte count is outside the accepted range")
	}
	buffer := make([]byte, n)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func tokenEqual(got, want string) bool {
	gotDigest := sha256.Sum256([]byte(got))
	wantDigest := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(gotDigest[:], wantDigest[:]) == 1
}

package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	coreProtocol         = "VGT3"
	maxCoreResponseBytes = 4096
)

type CoreClient struct {
	socket  string
	timeout time.Duration
	key     []byte
}

func NewCoreClient(socket, keyPath string, timeout time.Duration) (*CoreClient, error) {
	key, err := loadCoreIPCKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("core IPC key: %w", err)
	}
	return &CoreClient{socket: socket, timeout: timeout, key: key}, nil
}

func loadCoreIPCKey(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("core IPC key path must be absolute")
	}
	if err := rejectSymlink(path); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		// Development and unit-test path. Production installers create the key
		// beforehand with the strict root:gedefense 0640 shared-secret profile.
		return loadOrCreateBinaryKey(path)
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("core IPC key descriptor is invalid")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() {
		return nil, errors.New("core IPC key must be a regular file")
	}
	mode := info.Mode().Perm()
	productionProfile := stat.Uid == 0 && stat.Gid == uint32(os.Getegid()) && mode == 0o640
	localProfile := stat.Uid == uint32(os.Geteuid()) && mode == 0o600
	if !productionProfile && !localProfile {
		return nil, fmt.Errorf("core IPC key ownership/mode invalid: uid=%d gid=%d mode=%#o", stat.Uid, stat.Gid, mode)
	}
	b, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, errors.New("core IPC key must contain exactly 32 bytes")
	}
	return append([]byte(nil), b...), nil
}

func protocolFieldValid(v string) bool {
	return v != "" && len(v) <= 3072 && !strings.ContainsAny(v, " \t\r\n\x00\x1f")
}

func randomNonce() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func coreMAC(key []byte, fields ...string) string {
	mac := hmac.New(sha256.New, key)
	for i, field := range fields {
		if i > 0 {
			_, _ = mac.Write([]byte{0x1f})
		}
		_, _ = mac.Write([]byte(field))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func (c *CoreClient) command(parts ...string) (string, error) {
	if len(parts) == 0 || len(parts) > 16 {
		return "", errors.New("invalid core command arity")
	}
	for _, p := range parts {
		if !protocolFieldValid(p) {
			return "", errors.New("invalid core protocol field")
		}
	}
	nonce, err := randomNonce()
	if err != nil {
		return "", err
	}
	stamp := strconv.FormatInt(time.Now().Unix(), 10)
	requestFields := append([]string{coreProtocol, stamp, nonce}, parts...)
	mac := coreMAC(c.key, requestFields...)

	conn, err := net.DialTimeout("unix", c.socket, c.timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return "", fmt.Errorf("core IPC deadline configuration failed: %w", err)
	}
	line := strings.Join(append(requestFields, mac), " ") + "\n"
	if len(line) > 4096 {
		return "", errors.New("core request exceeds protocol limit")
	}
	if _, err = conn.Write([]byte(line)); err != nil {
		return "", err
	}
	responseReader := bufio.NewReaderSize(io.LimitReader(conn, maxCoreResponseBytes+1), maxCoreResponseBytes+1)
	response, err := responseReader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return parseCoreResponse(response, nonce, c.key)
}

func parseCoreResponse(response, nonce string, key []byte) (string, error) {
	if len(response) > maxCoreResponseBytes || !strings.HasSuffix(response, "\n") {
		return "", errors.New("core response exceeds protocol limit or is unterminated")
	}
	response = strings.TrimSpace(response)
	fields := strings.Fields(response)
	if len(fields) != 5 || fields[0] != coreProtocol+"R" || fields[1] != nonce {
		return "", errors.New("invalid authenticated core response")
	}
	status, encoded, gotMAC := fields[2], fields[3], fields[4]
	wantMAC := coreMAC(key, fields[0], fields[1], status, encoded)
	gotBytes, err1 := hex.DecodeString(gotMAC)
	wantBytes, err2 := hex.DecodeString(wantMAC)
	if err1 != nil || err2 != nil || !hmac.Equal(gotBytes, wantBytes) {
		return "", errors.New("core response authentication failed")
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(payload) > 2048 {
		return "", errors.New("invalid core response payload")
	}
	message := string(payload)
	if status != "OK" {
		if message == "" {
			message = "request rejected"
		}
		return "", fmt.Errorf("core rejected command: %s", message)
	}
	return message, nil
}

func syncCoreAllowlist(core *CoreClient, targets []string) error {
	if core == nil {
		return errors.New("core client is unavailable")
	}
	if len(targets) == 0 {
		return errors.New("management allowlist is empty")
	}
	for _, target := range targets {
		if err := core.AllowAdd(target); err != nil {
			return fmt.Errorf("allowlist synchronization failed for %s: %w", target, err)
		}
	}
	return nil
}

func (c *CoreClient) AllowAdd(target string) error {
	_, err := c.command("ALLOW_ADD", target)
	return err
}
func (c *CoreClient) AllowDelete(target string) error {
	_, err := c.command("ALLOW_DEL", target)
	return err
}

func (c *CoreClient) Ping() (string, error)      { return c.command("PING") }
func (c *CoreClient) Add(target string) error    { _, err := c.command("ADD", target); return err }
func (c *CoreClient) Delete(target string) error { _, err := c.command("DEL", target); return err }
func (c *CoreClient) ClearBlocklist() error {
	state, err := c.command("CLEAR_BLOCKLIST")
	if err != nil {
		return err
	}
	if state != "cleared" {
		return fmt.Errorf("core returned unexpected blocklist clear state %q", state)
	}
	return nil
}
func (c *CoreClient) VerifyBlocklistEmpty() error {
	state, err := c.command("VERIFY_EMPTY")
	if err != nil {
		return err
	}
	if state != "empty" {
		return fmt.Errorf("core returned unexpected blocklist state %q", state)
	}
	return nil
}
func (c *CoreClient) Stop(pid int, startTicks uint64, rule string) error {
	_, err := c.command("XDR_STOP", strconv.Itoa(pid), strconv.FormatUint(startTicks, 10), rule)
	return err
}
func (c *CoreClient) Kill(pid int, startTicks uint64, rule string) error {
	_, err := c.command("XDR_KILL", strconv.Itoa(pid), strconv.FormatUint(startTicks, 10), rule)
	return err
}

func validSysctlToken(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func (c *CoreClient) SysctlGet(key string) (string, error) {
	if !validSysctlKey(key) {
		return "", errors.New("invalid sysctl key")
	}
	value, err := c.command("SYSCTL_GET", key)
	if err != nil {
		return "", err
	}
	if !validSysctlToken(value) {
		return "", errors.New("core returned an invalid sysctl value")
	}
	return value, nil
}

func (c *CoreClient) SysctlCompareSet(key, expected, desired string) error {
	if !validSysctlKey(key) || !validSysctlToken(expected) || !validSysctlToken(desired) {
		return errors.New("invalid sysctl compare-set request")
	}
	state, err := c.command("SYSCTL_SET", key, expected, desired)
	if err != nil {
		return err
	}
	if state != desired {
		return fmt.Errorf("core returned unexpected sysctl state %q", state)
	}
	return nil
}

func validHardeningState(value string) bool {
	switch value {
	case "absent", "linux-server-balanced", "gaiaos-workstation-strict":
		return true
	default:
		return false
	}
}

func (c *CoreClient) HardeningProfileState() (string, error) {
	state, err := c.command("HARDENING_GET")
	if err != nil {
		return "", err
	}
	if !validHardeningState(state) {
		return "", errors.New("core returned an invalid persistent hardening state")
	}
	return state, nil
}

func (c *CoreClient) HardeningProfileCompareSet(expected, desired string) error {
	if !validHardeningState(expected) || !validHardeningState(desired) {
		return errors.New("invalid persistent hardening compare-set request")
	}
	state, err := c.command("HARDENING_SET", expected, desired)
	if err != nil {
		return err
	}
	if state != desired {
		return fmt.Errorf("core returned unexpected persistent hardening state %q", state)
	}
	return nil
}

func validSysctlKey(key string) bool {
	if key == "" || len(key) > 96 || strings.HasPrefix(key, ".") || strings.HasSuffix(key, ".") {
		return false
	}
	for _, character := range key {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '_' && character != '.' {
			return false
		}
	}
	return true
}

type QuarantineIdentity struct {
	Size          uint64 `json:"size"`
	Mode          uint32 `json:"mode"`
	UID           uint32 `json:"uid"`
	GID           uint32 `json:"gid"`
	Device        uint64 `json:"device"`
	Inode         uint64 `json:"inode"`
	ModifiedNanos int64  `json:"modified_nanos"`
	SHA256        string `json:"sha256"`
}

func (identity QuarantineIdentity) protocolToken() (string, error) {
	if err := validateQuarantineIdentity(identity); err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"v1:%d:%d:%d:%d:%d:%d:%d:%s",
		identity.Size,
		identity.Mode,
		identity.UID,
		identity.GID,
		identity.Device,
		identity.Inode,
		identity.ModifiedNanos,
		identity.SHA256,
	), nil
}

func parseQuarantineIdentity(value string) (QuarantineIdentity, error) {
	fields := strings.Split(value, ":")
	if len(fields) != 9 || fields[0] != "v1" {
		return QuarantineIdentity{}, errors.New("core returned an invalid quarantine identity")
	}
	parseUint := func(index, bits int) (uint64, error) {
		return strconv.ParseUint(fields[index], 10, bits)
	}
	size, err := parseUint(1, 64)
	if err != nil {
		return QuarantineIdentity{}, errors.New("core returned an invalid quarantine size")
	}
	mode, err := parseUint(2, 32)
	if err != nil {
		return QuarantineIdentity{}, errors.New("core returned an invalid quarantine mode")
	}
	uid, err := parseUint(3, 32)
	if err != nil {
		return QuarantineIdentity{}, errors.New("core returned an invalid quarantine uid")
	}
	gid, err := parseUint(4, 32)
	if err != nil {
		return QuarantineIdentity{}, errors.New("core returned an invalid quarantine gid")
	}
	device, err := parseUint(5, 64)
	if err != nil {
		return QuarantineIdentity{}, errors.New("core returned an invalid quarantine device")
	}
	inode, err := parseUint(6, 64)
	if err != nil {
		return QuarantineIdentity{}, errors.New("core returned an invalid quarantine inode")
	}
	modifiedNanos, err := strconv.ParseInt(fields[7], 10, 64)
	if err != nil {
		return QuarantineIdentity{}, errors.New("core returned an invalid quarantine timestamp")
	}
	identity := QuarantineIdentity{
		Size: size, Mode: uint32(mode), UID: uint32(uid), GID: uint32(gid),
		Device: device, Inode: inode, ModifiedNanos: modifiedNanos,
		SHA256: fields[8],
	}
	if err := validateQuarantineIdentity(identity); err != nil {
		return QuarantineIdentity{}, err
	}
	return identity, nil
}

func validateQuarantineIdentity(identity QuarantineIdentity) error {
	if identity.Size > 256<<20 || identity.Mode > 0o7777 ||
		len(identity.SHA256) != sha256.Size*2 {
		return errors.New("quarantine identity violates typed bounds")
	}
	digest, err := hex.DecodeString(identity.SHA256)
	if err != nil || len(digest) != sha256.Size {
		return errors.New("quarantine identity digest is invalid")
	}
	return nil
}

func validQuarantineObjectID(value string) bool {
	if len(value) != 19 || !strings.HasPrefix(value, "QV-") {
		return false
	}
	for _, character := range value[3:] {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func quarantinePathToken(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		len(path) == 0 || len(path) > 2048 || strings.ContainsRune(path, '\x00') {
		return "", errors.New("quarantine path is invalid")
	}
	token := base64.RawURLEncoding.EncodeToString([]byte(path))
	if !protocolFieldValid(token) {
		return "", errors.New("quarantine path token exceeds protocol bounds")
	}
	return token, nil
}

func (c *CoreClient) QuarantineInspect(path string) (QuarantineIdentity, error) {
	token, err := quarantinePathToken(path)
	if err != nil {
		return QuarantineIdentity{}, err
	}
	value, err := c.command("QUARANTINE_INSPECT", token)
	if err != nil {
		return QuarantineIdentity{}, err
	}
	return parseQuarantineIdentity(value)
}

func (c *CoreClient) QuarantineApply(
	path, objectID string,
	identity QuarantineIdentity,
) error {
	token, err := quarantinePathToken(path)
	if err != nil {
		return err
	}
	if !validQuarantineObjectID(objectID) {
		return errors.New("quarantine object ID is invalid")
	}
	identityToken, err := identity.protocolToken()
	if err != nil {
		return err
	}
	state, err := c.command("QUARANTINE_APPLY", token, objectID, identityToken)
	if err != nil {
		return err
	}
	return verifyQuarantineIdentityResponse(state, identity)
}

func (c *CoreClient) QuarantineVerify(
	objectID string,
	identity QuarantineIdentity,
) error {
	if !validQuarantineObjectID(objectID) {
		return errors.New("quarantine object ID is invalid")
	}
	identityToken, err := identity.protocolToken()
	if err != nil {
		return err
	}
	state, err := c.command("QUARANTINE_VERIFY", objectID, identityToken)
	if err != nil {
		return err
	}
	if state != "verified" {
		return errors.New("core returned an invalid quarantine verification state")
	}
	return nil
}

func (c *CoreClient) QuarantineRestore(
	path, objectID string,
	identity QuarantineIdentity,
) error {
	token, err := quarantinePathToken(path)
	if err != nil {
		return err
	}
	if !validQuarantineObjectID(objectID) {
		return errors.New("quarantine object ID is invalid")
	}
	identityToken, err := identity.protocolToken()
	if err != nil {
		return err
	}
	state, err := c.command("QUARANTINE_RESTORE", token, objectID, identityToken)
	if err != nil {
		return err
	}
	if state != "restored" {
		return errors.New("core returned an invalid quarantine restore state")
	}
	return nil
}

func verifyQuarantineIdentityResponse(
	value string,
	expected QuarantineIdentity,
) error {
	actual, err := parseQuarantineIdentity(value)
	if err != nil {
		return err
	}
	expectedToken, err := expected.protocolToken()
	if err != nil {
		return err
	}
	actualToken, err := actual.protocolToken()
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(actualToken), []byte(expectedToken)) {
		return errors.New("core returned a mismatched quarantine identity")
	}
	return nil
}

// STATUS: DIAMANT VGT SUPREME
//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type memoryQuarantineCore struct {
	files   map[string]QuarantineIdentity
	objects map[string]QuarantineIdentity
	paths   map[string]string
}

func newMemoryQuarantineCore() *memoryQuarantineCore {
	return &memoryQuarantineCore{
		files:   make(map[string]QuarantineIdentity),
		objects: make(map[string]QuarantineIdentity),
		paths:   make(map[string]string),
	}
}

func quarantineTestIdentity(seed string) QuarantineIdentity {
	digest := strings.Repeat(seed, 64)
	return QuarantineIdentity{
		Size: 12, Mode: 0o640, UID: 1000, GID: 1000,
		Device: 8, Inode: 42, ModifiedNanos: 123456789,
		SHA256: digest[:64],
	}
}

func (c *memoryQuarantineCore) QuarantineInspect(path string) (QuarantineIdentity, error) {
	identity, exists := c.files[path]
	if !exists {
		return QuarantineIdentity{}, errors.New("file unavailable")
	}
	return identity, nil
}

func (c *memoryQuarantineCore) QuarantineApply(
	path, objectID string,
	identity QuarantineIdentity,
) error {
	current, exists := c.files[path]
	if !exists || current != identity {
		return errors.New("identity changed")
	}
	if _, exists := c.objects[objectID]; exists {
		return errors.New("object collision")
	}
	delete(c.files, path)
	c.objects[objectID] = identity
	c.paths[objectID] = path
	return nil
}

func (c *memoryQuarantineCore) QuarantineVerify(
	objectID string,
	identity QuarantineIdentity,
) error {
	current, exists := c.objects[objectID]
	if !exists || current != identity {
		return errors.New("object verification failed")
	}
	return nil
}

func (c *memoryQuarantineCore) QuarantineRestore(
	path, objectID string,
	identity QuarantineIdentity,
) error {
	current, exists := c.objects[objectID]
	if !exists || current != identity || c.paths[objectID] != path {
		return errors.New("object restore failed")
	}
	if _, exists := c.files[path]; exists {
		return errors.New("restore destination occupied")
	}
	c.files[path] = identity
	delete(c.objects, objectID)
	delete(c.paths, objectID)
	return nil
}

func TestQuarantineTransactionLifecycleAndMultipleObjects(t *testing.T) {
	core := newMemoryQuarantineCore()
	core.files["/tmp/threat-a"] = quarantineTestIdentity("a")
	core.files["/tmp/threat-b"] = quarantineTestIdentity("b")
	applier := NewQuarantineTransactionApplier(core)
	engine, _, _ := newTestTransactionEngine(
		t, applier, func(EvidenceRecord) error { return nil },
	)

	previewA, err := engine.Preview(
		quarantineTransactionType, "Quarantine file A", "malware response",
		json.RawMessage(`{"path":"/tmp/threat-a"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	appliedA, err := engine.Apply(previewA.ID, "APPLY "+previewA.ID)
	if err != nil || appliedA.Status != "applied" {
		t.Fatalf("first quarantine failed: status=%s err=%v", appliedA.Status, err)
	}

	previewB, err := engine.Preview(
		quarantineTransactionType, "Quarantine file B", "malware response",
		json.RawMessage(`{"path":"/tmp/threat-b"}`),
	)
	if err != nil {
		t.Fatalf("parallel quarantine preview was rejected: %v", err)
	}
	if _, err := engine.Apply(previewB.ID, "APPLY "+previewB.ID); err != nil {
		t.Fatal(err)
	}
	status := engine.QuarantineStatus()
	if !status.Healthy || status.Count != 2 {
		t.Fatalf("unexpected quarantine status: %+v", status)
	}

	if _, err := engine.Reverse(appliedA.ID, "REVERSE "+appliedA.ID); err != nil {
		t.Fatal(err)
	}
	if _, exists := core.files["/tmp/threat-a"]; !exists {
		t.Fatal("reversed quarantine did not restore the original file")
	}
	if status := engine.QuarantineStatus(); !status.Healthy || status.Count != 1 {
		t.Fatalf("reversed object remained active: %+v", status)
	}
}

func TestQuarantineRejectsSecurityControlAndVirtualPaths(t *testing.T) {
	for _, path := range []string{
		"/", "/proc/1/mem", "/sys/kernel/security", "/dev/sda",
		"/run/secret", "/etc/vgt/gedefense/gedefense.toml",
		"/var/lib/vgt/gedefense/evidence.jsonl",
		"/opt/vgt/gedefense/current/bin/gedefense-control",
		"/tmp/../etc/passwd",
	} {
		raw, err := json.Marshal(quarantineRequest{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeQuarantineRequest(raw); err == nil {
			t.Fatalf("forbidden quarantine path accepted: %s", path)
		}
	}
}

func TestQuarantineIdentityProtocolRejectsTampering(t *testing.T) {
	identity := quarantineTestIdentity("c")
	token, err := identity.protocolToken()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseQuarantineIdentity(token)
	if err != nil || parsed != identity {
		t.Fatalf("identity round-trip failed: parsed=%+v err=%v", parsed, err)
	}
	if _, err := parseQuarantineIdentity(token + ":extra"); err == nil {
		t.Fatal("identity with trailing field was accepted")
	}
	if _, err := parseQuarantineIdentity(strings.Replace(token, identity.SHA256, "00", 1)); err == nil {
		t.Fatal("truncated identity digest was accepted")
	}
}

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignedForensicsExportDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	store, err := NewPolicyStore(PolicyConfig{
		StateFile: filepath.Join(dir, "policy.json"), SigningKeyFile: filepath.Join(dir, "policy.key"),
		PublicKeyFile: filepath.Join(dir, "policy.pub"), RequireSigned: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := defaultConfig()
	state := NewState("test", cfg)
	state.AddEvent(Event{Kind: "test", Message: "original"})
	document, err := store.SignForensics(state.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := os.ReadFile(filepath.Join(dir, "policy.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyForensicsBytes(encoded, publicKey); err != nil {
		t.Fatalf("valid export rejected: %v", err)
	}
	tampered := []byte(strings.Replace(string(encoded), "original", "modified", 1))
	if _, err := VerifyForensicsBytes(tampered, publicKey); err == nil {
		t.Fatal("tampered forensics export was accepted")
	}
}

func TestForensicsRequiresTrustedSigner(t *testing.T) {
	dir := t.TempDir()
	first, err := NewPolicyStore(PolicyConfig{StateFile: filepath.Join(dir, "a.json"), SigningKeyFile: filepath.Join(dir, "a.key"), PublicKeyFile: filepath.Join(dir, "a.pub"), RequireSigned: true})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewPolicyStore(PolicyConfig{StateFile: filepath.Join(dir, "b.json"), SigningKeyFile: filepath.Join(dir, "b.key"), PublicKeyFile: filepath.Join(dir, "b.pub"), RequireSigned: true})
	if err != nil {
		t.Fatal(err)
	}
	document, err := first.SignForensics(NewState("test", defaultConfig()).Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(document)
	wrongKey, _ := os.ReadFile(filepath.Join(dir, "b.pub"))
	if _, err := VerifyForensicsBytes(encoded, wrongKey); err == nil {
		t.Fatal("export signed by an untrusted key was accepted")
	}
	_ = second
}

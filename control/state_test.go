package main

import (
	"testing"
	"time"
)

func TestNormalizeAndExpireBlock(t *testing.T) {
	cfg := defaultConfig()
	s := NewState("test", cfg)
	b, err := s.AddBlock("203.0.113.4", "manual test", "test", time.Second, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	if b.Target != "203.0.113.4/32" {
		t.Fatalf("got %s", b.Target)
	}
	expired := s.Expired(time.Now().Add(2 * time.Second))
	if len(expired) != 1 {
		t.Fatalf("expected expiry")
	}
}

func TestNormalizeRejectsUnspecifiedAddress(t *testing.T) {
	for _, target := range []string{"0.0.0.0", "::", "0.0.0.0/0", "::/0"} {
		if _, err := normalizeTarget(target); err == nil {
			t.Fatalf("unspecified target %q was accepted", target)
		}
	}
}

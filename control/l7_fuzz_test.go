// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"path/filepath"
	"testing"
)

func FuzzL7NormalizerNeverPanics(f *testing.F) {
	f.Add("/", "hello", "text/plain")
	f.Add("/?q=%2527%2520OR%25201%253D1", `{"x":"<script>"}`, "application/json")
	f.Fuzz(func(t *testing.T, uri, body, contentType string) {
		cfg := l7TestConfig()
		if len(uri) == 0 || len(uri) > cfg.MaxURIBytes || len(body) > cfg.MaxBodyBytes || len(contentType) > 512 {
			t.Skip()
		}
		req := l7Request(uri)
		req.Method = "POST"
		req.Headers = []L7Header{{Name: "Content-Type", Value: contentType}}
		req.BodyBase64 = base64.StdEncoding.EncodeToString([]byte(body))
		_, _ = NewL7Normalizer(cfg).Normalize(req)
	})
}

func FuzzL7ResponseInspectionPreservesWireBytes(f *testing.F) {
	f.Add([]byte("plain response"), "identity")
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00}, "gzip")
	f.Add([]byte("opaque"), "br")
	f.Fuzz(func(t *testing.T, wire []byte, encoding string) {
		if len(wire) > 64<<10 || len(encoding) > 64 {
			t.Skip()
		}
		body := io.NopCloser(bytes.NewReader(wire))
		_, replay, _ := l7ResponseInspectionPrefix(body, encoding, 4096)
		if replay == nil {
			t.Fatal("response replay body must never be nil")
		}
		replayed, err := io.ReadAll(replay)
		if err != nil {
			t.Fatalf("replay read failed: %v", err)
		}
		if err := replay.Close(); err != nil {
			t.Fatalf("replay close failed: %v", err)
		}
		if !bytes.Equal(replayed, wire) {
			t.Fatalf("response inspection changed wire bytes: got=%d want=%d", len(replayed), len(wire))
		}
	})
}

func FuzzL7InlineUpstreamParserNeverEscapesLocalHost(f *testing.F) {
	f.Add("http://127.0.0.1:8080")
	f.Add("unix:///run/example/app.sock")
	f.Add("http://example.com:8080")
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 512 {
			t.Skip()
		}
		_, network, address, err := parseL7InlineUpstream(raw)
		if err != nil {
			return
		}
		switch network {
		case "tcp":
			host, _, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				t.Fatalf("accepted TCP upstream cannot be split: %v", splitErr)
			}
			ip := net.ParseIP(host)
			if ip == nil || !ip.IsLoopback() {
				t.Fatalf("accepted non-loopback TCP upstream %q", address)
			}
		case "unix":
			if !filepath.IsAbs(address) || filepath.Clean(address) != address {
				t.Fatalf("accepted unsafe Unix upstream %q", address)
			}
		default:
			t.Fatalf("accepted unexpected upstream network %q", network)
		}
	})
}

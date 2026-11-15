package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// POINT 4 / P4-T2: the Mode A client contract (docs/POINT4-WITNESS.md §4).
// httptest.NewTLSServer drives the real hardened client through an injected
// transport; the production transport/pin path is exercised through the same
// VerifyConnection predicate.

type witnessStubServer struct {
	t                *testing.T
	server           *httptest.Server
	privateKey       ed25519.PrivateKey
	publicKey        ed25519.PublicKey
	mu               sync.Mutex
	challengeCount   int
	checkpointCount  int
	sequence         uint64
	fixedNonce       string
	challengeStatus  int
	checkpointStatus int
	redirect         bool
	slow             time.Duration
	responseSize     int
	receiptMutate    func(*WitnessReceipt)
	receiptTamper    func(*WitnessReceipt)
}

func newWitnessStubServer(t *testing.T) *witnessStubServer {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stub := &witnessStubServer{t: t, privateKey: privateKey, publicKey: publicKey}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/challenge", stub.handleChallenge)
	mux.HandleFunc("/v1/checkpoint", stub.handleCheckpoint)
	stub.server = httptest.NewTLSServer(mux)
	t.Cleanup(stub.server.Close)
	return stub
}

func (s *witnessStubServer) handleChallenge(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.challengeCount++
	status := s.challengeStatus
	if s.redirect {
		status = http.StatusFound
	}
	if s.slow > 0 {
		time.Sleep(s.slow)
	}
	if s.responseSize > 0 {
		_, _ = w.Write([]byte(strings.Repeat("a", s.responseSize)))
		s.mu.Unlock()
		return
	}
	if s.redirect {
		s.mu.Unlock()
		w.Header().Set("Location", "/v1/challenge-again")
		w.WriteHeader(http.StatusFound)
		return
	}
	if status != 0 {
		s.mu.Unlock()
		w.WriteHeader(status)
		return
	}
	nonce := s.fixedNonce
	if nonce == "" {
		nonce = fmt.Sprintf("%032x", s.challengeCount)
	}
	s.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]string{"challenge": nonce})
}

func (s *witnessStubServer) handleCheckpoint(w http.ResponseWriter, r *http.Request) {
	if s.redirect {
		w.Header().Set("Location", "/v1/checkpoint")
		w.WriteHeader(http.StatusFound)
		return
	}
	s.mu.Lock()
	s.checkpointCount++
	status := s.checkpointStatus
	s.mu.Unlock()
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	var checkpoint WitnessCheckpoint
	if err := json.NewDecoder(r.Body).Decode(&checkpoint); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.sequence++
	receipt := WitnessReceipt{
		WitnessID: "witness-1", WitnessSeq: s.sequence, CheckpointID: checkpoint.CheckpointID,
		AcceptedAt: "2026-11-15T12:00:00Z",
	}
	mutate := s.receiptMutate
	tamper := s.receiptTamper
	s.mu.Unlock()
	if mutate != nil {
		mutate(&receipt)
	}
	payload, err := witnessReceiptCanonicalPayload(receipt)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	receipt.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.privateKey, witnessReceiptDigest(payload)))
	if tamper != nil {
		tamper(&receipt)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"receipt": receipt})
}

func (s *witnessStubServer) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.challengeCount, s.checkpointCount
}

// testCertificateSPKI returns the SHA-256 SPKI pin of the stub TLS certificate.
func (s *witnessStubServer) testCertificateSPKI() string {
	sum := sha256.Sum256(s.server.Certificate().RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// witnessClientFixture builds a client whose settings are valid but whose
// transport points at the local TLS stub.
func witnessClientFixture(t *testing.T, stub *witnessStubServer, mutate func(*WitnessFabricSettings, *witnessClientConfig)) *witnessHTTPClient {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "witness.pub")
	if err := os.WriteFile(keyPath, stub.publicKey, 0o600); err != nil {
		t.Fatal(err)
	}
	settings := defaultWitnessFabricSettings()
	settings.Enabled = true
	settings.Mode = witnessModeHTTP
	settings.Endpoint = "https://witness.example"
	settings.PinnedServerSPKI = stub.testCertificateSPKI()
	settings.PinnedServerKeyFile = keyPath
	settings.RetryAttempts = 0
	cfg := witnessClientConfig{
		Settings: settings, Transport: stub.server.Client().Transport, Endpoint: stub.server.URL,
		Now:   func() time.Time { return time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC) },
		Sleep: func(time.Duration) {},
	}
	if mutate != nil {
		mutate(&settings, &cfg)
	}
	cfg.Settings = settings
	client, err := newWitnessHTTPClient(cfg)
	if err != nil {
		t.Fatalf("client construction (pub=%d keyPath=%q): %v", len(stub.publicKey), keyPath, err)
	}
	return client
}

func witnessPushFixture(t *testing.T, client *witnessHTTPClient) WitnessCheckpoint {
	t.Helper()
	ledger, _ := evidenceFixture(t)
	challenge, err := client.Challenge(context.Background())
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	return witnessFixtureCheckpoint(t, ledger, func(checkpoint *WitnessCheckpoint) {
		checkpoint.Challenge = challenge
	})
}

func TestWitnessClientVerifiesSignedReceiptAndSequence(t *testing.T) {
	stub := newWitnessStubServer(t)
	client := witnessClientFixture(t, stub, nil)
	checkpoint := witnessPushFixture(t, client)
	receipt, err := client.Push(context.Background(), checkpoint)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if receipt.CheckpointID != checkpoint.CheckpointID || receipt.WitnessSeq != 1 {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	if err := VerifyWitnessReceipt(receipt, stub.publicKey); err != nil {
		t.Fatalf("the stub receipt does not verify: %v", err)
	}
	if client.LastWitnessSeq() != 1 {
		t.Fatalf("client sequence = %d, want 1", client.LastWitnessSeq())
	}
	// A second checkpoint receives sequence 2 and is accepted.
	second := witnessPushFixture(t, client)
	if _, err := client.Push(context.Background(), second); err != nil {
		t.Fatalf("second push: %v", err)
	}
	if client.LastWitnessSeq() != 2 {
		t.Fatalf("client sequence = %d, want 2", client.LastWitnessSeq())
	}
}

func TestWitnessClientRejectsLooseTransportConfiguration(t *testing.T) {
	stub := newWitnessStubServer(t)
	cases := map[string]func(*WitnessFabricSettings){
		"http downgrade": func(w *WitnessFabricSettings) { w.Endpoint = "http://witness.example" },
		"foreign port":   func(w *WitnessFabricSettings) { w.Endpoint = "https://witness.example:8443" },
		"ssrf loopback":  func(w *WitnessFabricSettings) { w.Endpoint = "https://127.0.0.1" },
		"ssrf metadata":  func(w *WitnessFabricSettings) { w.Endpoint = "https://169.254.169.254" },
		"no anchor": func(w *WitnessFabricSettings) {
			w.PinnedServerSPKI = ""
			w.PinnedServerKeyFile = ""
		},
		"relative key": func(w *WitnessFabricSettings) { w.PinnedServerKeyFile = "witness.pub" },
	}
	for name, mutate := range cases {
		settings := defaultWitnessFabricSettings()
		settings.Enabled = true
		settings.Mode = witnessModeHTTP
		settings.Endpoint = "https://witness.example"
		settings.PinnedServerSPKI = stub.testCertificateSPKI()
		mutate(&settings)
		_, err := newWitnessHTTPClient(witnessClientConfig{
			Settings: settings, Transport: stub.server.Client().Transport, Endpoint: stub.server.URL,
		})
		if err == nil {
			t.Errorf("%s: a loose transport configuration was accepted", name)
		}
	}
}

func TestWitnessClientProductionDialerBlocksSSRF(t *testing.T) {
	stub := newWitnessStubServer(t)
	settings := defaultWitnessFabricSettings()
	settings.Enabled = true
	settings.Mode = witnessModeHTTP
	settings.Endpoint = "https://witness.example"
	settings.PinnedServerSPKI = stub.testCertificateSPKI()
	client, err := newWitnessHTTPClient(witnessClientConfig{Settings: settings})
	if err != nil {
		t.Fatalf("newWitnessHTTPClient: %v", err)
	}
	transport, ok := client.http.Transport.(*http.Transport)
	if !ok || transport.DialContext == nil {
		t.Fatalf("expected production *http.Transport with DialContext, got %T", client.http.Transport)
	}
	for _, target := range []string{"127.0.0.1:443", "[::1]:443", "localhost:443", "169.254.169.254:443", "witness.example:8443"} {
		if conn, dialErr := transport.DialContext(context.Background(), "tcp", target); dialErr == nil {
			_ = conn.Close()
			t.Errorf("production dialer connected to forbidden target %q", target)
		}
	}
}

func TestWitnessClientRejectsPinMismatchAndRedirects(t *testing.T) {
	stub := newWitnessStubServer(t)
	client := witnessClientFixture(t, stub, func(settings *WitnessFabricSettings, _ *witnessClientConfig) {
		settings.PinnedServerSPKI = strings.Repeat("00", 32)
		settings.RetryAttempts = 2
	})
	if _, err := client.Challenge(context.Background()); err == nil {
		t.Fatal("a wrong SPKI pin was accepted")
	}
	if challenges, checkpoints := stub.counts(); challenges != 1 || checkpoints != 0 {
		t.Fatalf("a pin mismatch retried or sent a checkpoint: challenges=%d checkpoints=%d", challenges, checkpoints)
	}

	redirected := newWitnessStubServer(t)
	redirected.redirect = true
	redirectClient := witnessClientFixture(t, redirected, func(settings *WitnessFabricSettings, _ *witnessClientConfig) {
		settings.RetryAttempts = 2
	})
	if _, err := redirectClient.Challenge(context.Background()); err == nil {
		t.Fatal("a redirect was followed")
	}
	if challenges, _ := redirected.counts(); challenges != 1 {
		t.Fatalf("a refused redirect was retried: %d requests", challenges)
	}
}

func TestWitnessClientBoundsTimeoutAndResponseSize(t *testing.T) {
	stub := newWitnessStubServer(t)
	stub.slow = 1500 * time.Millisecond
	client := witnessClientFixture(t, stub, func(settings *WitnessFabricSettings, _ *witnessClientConfig) {
		settings.RequestTimeoutSeconds = 1
	})
	started := time.Now()
	if _, err := client.Challenge(context.Background()); err == nil {
		t.Fatal("a slow witness was accepted")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("the client timeout did not bound the request: %v", elapsed)
	}

	oversized := newWitnessStubServer(t)
	oversized.responseSize = witnessMaxResponseBytes + 1
	oversizedClient := witnessClientFixture(t, oversized, nil)
	if _, err := oversizedClient.Challenge(context.Background()); err == nil {
		t.Fatal("an oversized response was accepted")
	}
	if challenges, _ := oversized.counts(); challenges != 1 {
		t.Fatalf("an oversized response was retried: %d requests", challenges)
	}
}

func TestWitnessClientRetriesOnlyTransientAnswers(t *testing.T) {
	serverError := newWitnessStubServer(t)
	serverError.challengeStatus = http.StatusInternalServerError
	retrying := witnessClientFixture(t, serverError, func(settings *WitnessFabricSettings, _ *witnessClientConfig) {
		settings.RetryAttempts = 2
	})
	if _, err := retrying.Challenge(context.Background()); err == nil {
		t.Fatal("a 5xx answer was accepted")
	}
	if challenges, _ := serverError.counts(); challenges != 3 {
		t.Fatalf("5xx retry count = %d, want 3", challenges)
	}

	clientError := newWitnessStubServer(t)
	clientError.challengeStatus = http.StatusBadRequest
	notRetrying := witnessClientFixture(t, clientError, func(settings *WitnessFabricSettings, _ *witnessClientConfig) {
		settings.RetryAttempts = 3
	})
	if _, err := notRetrying.Challenge(context.Background()); err == nil {
		t.Fatal("a 4xx answer was accepted")
	}
	if challenges, _ := clientError.counts(); challenges != 1 {
		t.Fatalf("4xx was retried: %d requests", challenges)
	}
}

func TestWitnessChallengeCacheEnforcesOnceAndTTL(t *testing.T) {
	cache := newWitnessChallengeCache(120 * time.Second)
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	if err := cache.issue("", now); err == nil {
		t.Fatal("an empty nonce was accepted")
	}
	if err := cache.issue("deadbeef", now); err != nil {
		t.Fatalf("a fresh nonce was rejected: %v", err)
	}
	if err := cache.issue("deadbeef", now); err == nil {
		t.Fatal("a duplicate nonce was accepted")
	}
	if err := cache.claim("deadbeef", now.Add(60*time.Second)); err != nil {
		t.Fatalf("a fresh nonce could not be claimed: %v", err)
	}
	if err := cache.claim("deadbeef", now.Add(61*time.Second)); err == nil {
		t.Fatal("a nonce was claimable twice")
	}
	if err := cache.issue("cafebabe", now); err != nil {
		t.Fatal(err)
	}
	if err := cache.claim("cafebabe", now.Add(121*time.Second)); err == nil {
		t.Fatal("an expired nonce was claimable")
	}
	if err := cache.claim("feedface", now); err == nil {
		t.Fatal("an unknown nonce was claimable")
	}
}

func TestWitnessClientRejectsDuplicateAndEmptyChallenges(t *testing.T) {
	duplicate := newWitnessStubServer(t)
	duplicate.fixedNonce = "deadbeef"
	duplicateClient := witnessClientFixture(t, duplicate, nil)
	if _, err := duplicateClient.Challenge(context.Background()); err != nil {
		t.Fatalf("first challenge: %v", err)
	}
	if _, err := duplicateClient.Challenge(context.Background()); err == nil {
		t.Fatal("the witness repeated a nonce and the client accepted it")
	}

	empty := newWitnessStubServer(t)
	empty.fixedNonce = " "
	emptyClient := witnessClientFixture(t, empty, nil)
	if _, err := emptyClient.Challenge(context.Background()); err == nil {
		t.Fatal("an empty challenge was accepted")
	}
}

func TestWitnessClientRejectsInventoryOfInvalidReceipts(t *testing.T) {
	foreignCheckpoint := func(receipt *WitnessReceipt) {
		receipt.CheckpointID = strings.Repeat("cd", 16)
	}
	for name, mutate := range map[string]func(*WitnessReceipt){
		"wrong signature": func(receipt *WitnessReceipt) {
			receipt.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		},
		"foreign checkpoint": foreignCheckpoint,
	} {
		stub := newWitnessStubServer(t)
		if name == "wrong signature" {
			stub.receiptTamper = mutate
		} else {
			stub.receiptMutate = mutate
		}
		client := witnessClientFixture(t, stub, func(settings *WitnessFabricSettings, _ *witnessClientConfig) {
			// Keep the pin pure TLS so the receipt key is the verifier under test.
			settings.PinnedServerSPKI = ""
		})
		if _, err := client.Push(context.Background(), witnessPushFixture(t, client)); err == nil {
			t.Errorf("%s: an invalid receipt was accepted", name)
		}
		if client.LastWitnessSeq() != 0 {
			t.Errorf("%s: a rejected receipt advanced the sequence", name)
		}
	}

	backwards := newWitnessStubServer(t)
	client := witnessClientFixture(t, backwards, nil)
	if _, err := client.Push(context.Background(), witnessPushFixture(t, client)); err != nil {
		t.Fatalf("first push: %v", err)
	}
	backwards.mu.Lock()
	backwards.sequence = 0 // the next receipt repeats witness_seq 1
	backwards.mu.Unlock()
	if _, err := client.Push(context.Background(), witnessPushFixture(t, client)); err == nil {
		t.Fatal("a non-monotonic receipt sequence was accepted")
	}
}

// TestWitnessSPKIPinComparisonIsConstantTimeShape pins the helper the production
// VerifyConnection uses; it is shared by the injected-transport wrapper.
func TestWitnessSPKIPinComparison(t *testing.T) {
	stub := newWitnessStubServer(t)
	certificate := stub.server.Certificate()
	pin, err := hex.DecodeString(stub.testCertificateSPKI())
	if err != nil {
		t.Fatal(err)
	}
	if !witnessSPKIPinMatches(pin, certificate) {
		t.Fatal("the correct SPKI pin did not match")
	}
	if witnessSPKIPinMatches(make([]byte, sha256.Size), certificate) {
		t.Fatal("a zero SPKI pin matched")
	}
	if witnessSPKIPinMatches(pin, &x509.Certificate{}) {
		t.Fatal("an empty certificate matched a pin")
	}
}

// TestWitnessClientProductionTransportIsHardened pins the §4 transport contract
// the injected test transport does not itself exercise: no environment proxy, no
// redirects, TLS >= 1.2 and the configured timeout.
func TestWitnessClientProductionTransportIsHardened(t *testing.T) {
	settings := defaultWitnessFabricSettings()
	settings.Enabled = true
	settings.Mode = witnessModeHTTP
	settings.Endpoint = "https://witness.example"
	settings.PinnedServerSPKI = repeatHex("ab", 32)
	client, err := newWitnessHTTPClient(witnessClientConfig{Settings: settings})
	if err != nil {
		t.Fatalf("production client construction: %v", err)
	}
	transport, ok := client.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("production transport is %T, want *http.Transport", client.http.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("the witness transport honours environment proxies")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("the witness transport accepts a TLS version below 1.2")
	}
	if transport.TLSClientConfig.VerifyConnection == nil {
		t.Fatal("the SPKI pin is not enforced during the TLS handshake")
	}
	if client.http.CheckRedirect == nil {
		t.Fatal("redirects are not refused")
	}
	if err := client.http.CheckRedirect(&http.Request{}, nil); err == nil {
		t.Fatal("the redirect policy allows a redirect")
	}
	if client.http.Timeout != 10*time.Second {
		t.Fatalf("request timeout = %v, want 10s", client.http.Timeout)
	}
}

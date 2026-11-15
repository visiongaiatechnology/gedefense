package main

// POINT 4 / P4-T2: the hardened witness HTTP client (Mode A,
// docs/POINT4-WITNESS.md §4).
//
// The client is the only component that ever sends a checkpoint off the host. It
// therefore refuses to be configured loosely: https on port 443 only, no proxy
// from the environment, no redirects, TLS >= 1.2, a bounded request timeout and a
// 64 KiB response cap. The server identity is pinned either by the SHA-256 of its
// certificate SPKI (constant-time, before any checkpoint body is written) or by a
// pinned Ed25519 receipt key whose signature over VGT-GEDEFENSE-WITNESS-RECEIPT-V1
// is verified; both may be configured. Challenges are hex, bounded, fresh and
// single-use, and receipts must bind the exact checkpoint id and carry a strictly
// increasing witness_seq. Nothing here logs a path, token or key.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// witnessMaxResponseBytes caps every response the client will even read. A
	// witness answer is a small JSON object with one nonce or one receipt.
	witnessMaxResponseBytes = 64 << 10
	// witnessChallengeMaxHexBytes is the §4 upper bound of a nonce (128 bytes).
	witnessChallengeMaxHexBytes = 128
	witnessChallengeCacheSize   = 32
	witnessMaxWitnessIDBytes    = 128
	witnessMaxTokenFileBytes    = 4096
	witnessMaxKeyFileBytes      = 4096
	// witnessFutureSkew bounds how far a witness timestamp may be in the future.
	witnessFutureSkew = 5 * time.Minute
)

// errWitnessRedirectRefused marks a redirect the client will never follow. It is
// a sentinel so the retry classification works through the http.Client wrapper.
var errWitnessRedirectRefused = errors.New("witness redirect refused")

// witnessClientError classifies a failure so the engine can decide retry vs
// degraded without parsing a message.
type witnessClientError struct {
	reason    string
	permanent bool
	auth      bool
}

func (e *witnessClientError) Error() string { return "witness request failed: " + e.reason }

func witnessPermanent(err error) bool {
	var typed *witnessClientError
	return errors.As(err, &typed) && typed.permanent
}

func witnessAuthFailure(err error) bool {
	var typed *witnessClientError
	return errors.As(err, &typed) && typed.auth
}

// witnessClientConfig is the construction set. Transport is the test injection
// point; the production path builds its own hardened transport.
type witnessClientConfig struct {
	Settings  WitnessFabricSettings
	Transport http.RoundTripper
	// Endpoint overrides the settings endpoint. It exists so a test can point the
	// production code path at an httptest.NewTLSServer; the settings endpoint is
	// still validated first.
	Endpoint          string
	InitialWitnessSeq uint64
	Now               func() time.Time
	Sleep             func(time.Duration)
}

type witnessHTTPClient struct {
	endpoint    *url.URL
	http        *http.Client
	receiptKey  ed25519.PublicKey
	spkiPin     []byte
	bearer      string
	challenges  *witnessChallengeCache
	retry       int
	backoff     time.Duration
	sleep       func(time.Duration)
	now         func() time.Time
	maxResponse int64
	seqMu       sync.Mutex
	lastSeq     uint64
}

// readWitnessPrivateFile reads a 0600 regular, non-symlink file with a size cap.
// The mode check is what makes an operator key path a trust decision.
func readWitnessPrivateFile(path string, max int64) ([]byte, error) {
	if path == "" {
		return nil, errors.New("witness file path is empty")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("witness file unavailable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("witness file must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("witness file must not be group/other accessible")
	}
	if info.Size() <= 0 || info.Size() > max {
		return nil, errors.New("witness file size is outside its bound")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("witness file read failed: %w", err)
	}
	return raw, nil
}

// loadWitnessPinnedReceiptKey loads the pinned Ed25519 receipt key. The accepted
// shapes are the raw 32-byte key and its base64 encoding (feed signing format).
func loadWitnessPinnedReceiptKey(path string) (ed25519.PublicKey, error) {
	raw, err := readWitnessPrivateFile(path, witnessMaxKeyFileBytes)
	if err != nil {
		return nil, err
	}
	// Check exact 32-byte raw length before stripping trailing '\n' so a valid
	// Ed25519 public key whose final byte happens to be 0x0a is never truncated.
	if len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(append([]byte(nil), raw...)), nil
	}
	if len(raw) == ed25519.PublicKeySize+1 && raw[len(raw)-1] == '\n' {
		return ed25519.PublicKey(append([]byte(nil), raw[:ed25519.PublicKeySize]...)), nil
	}
	trimmed := strings.TrimSpace(string(raw))
	decoded, decodeErr := base64.StdEncoding.DecodeString(trimmed)
	if decodeErr != nil {
		decoded, decodeErr = base64.RawStdEncoding.DecodeString(trimmed)
	}
	if decodeErr != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("witness pinned receipt key must be a 32-byte raw Ed25519 public key or its base64 form")
	}
	return ed25519.PublicKey(decoded), nil
}

func loadWitnessBearerToken(path string) (string, error) {
	raw, err := readWitnessPrivateFile(path, witnessMaxTokenFileBytes)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || len(token) > witnessMaxTokenFileBytes || strings.ContainsAny(token, "\r\n\x00") {
		return "", errors.New("witness bearer token file is empty, malformed or oversized")
	}
	return token, nil
}

// witnessSPKIPinMatches compares the certificate SPKI hash with the pin in
// constant time.
func witnessSPKIPinMatches(pin []byte, cert *x509.Certificate) bool {
	if len(pin) != sha256.Size || cert == nil {
		return false
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return subtle.ConstantTimeCompare(sum[:], pin) == 1
}

// witnessPinnedRoundTripper re-checks the SPKI pin for an injected transport. The
// production transport pins during the handshake (VerifyConnection); this wrapper
// is the test path and a second line of defence.
type witnessPinnedRoundTripper struct {
	base http.RoundTripper
	pin  []byte
}

func (t *witnessPinnedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if len(t.pin) != 0 {
		if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 || !witnessSPKIPinMatches(t.pin, resp.TLS.PeerCertificates[0]) {
			_ = resp.Body.Close()
			return nil, &witnessClientError{reason: "server certificate SPKI pin mismatch", permanent: true}
		}
	}
	return resp, nil
}

func newWitnessHTTPClient(cfg witnessClientConfig) (*witnessHTTPClient, error) {
	settings := cfg.Settings
	if err := validateWitnessEndpoint(settings.Endpoint); err != nil {
		return nil, err
	}
	if settings.Endpoint == "" {
		return nil, errors.New("witness http mode requires an endpoint")
	}
	parsed, err := url.Parse(settings.Endpoint)
	if err != nil {
		return nil, errors.New("witness endpoint is not a valid URL")
	}
	if cfg.Endpoint != "" {
		parsed, err = url.Parse(cfg.Endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return nil, errors.New("witness test endpoint is not a valid https URL")
		}
	}
	var spkiPin []byte
	if settings.PinnedServerSPKI != "" {
		spkiPin, err = hex.DecodeString(settings.PinnedServerSPKI)
		if err != nil || len(spkiPin) != sha256.Size {
			return nil, errors.New("witness pinned server SPKI is not a SHA-256 value")
		}
	}
	var receiptKey ed25519.PublicKey
	if settings.PinnedServerKeyFile != "" {
		receiptKey, err = loadWitnessPinnedReceiptKey(settings.PinnedServerKeyFile)
		if err != nil {
			return nil, err
		}
	}
	if len(spkiPin) == 0 && receiptKey == nil {
		return nil, errors.New("witness http mode requires a pinned server SPKI or a pinned receipt key")
	}
	var bearer string
	if settings.AuthTokenFile != "" {
		bearer, err = loadWitnessBearerToken(settings.AuthTokenFile)
		if err != nil {
			return nil, err
		}
	}
	var clientCert *tls.Certificate
	if settings.ClientCertFile != "" {
		if _, err := readWitnessPrivateFile(settings.ClientKeyFile, witnessMaxKeyFileBytes*4); err != nil {
			return nil, err
		}
		cert, loadErr := tls.LoadX509KeyPair(settings.ClientCertFile, settings.ClientKeyFile)
		if loadErr != nil {
			return nil, errors.New("witness mTLS material could not be loaded")
		}
		clientCert = &cert
	}
	timeout := time.Duration(settings.RequestTimeoutSeconds) * time.Second
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	sleep := cfg.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	transport := cfg.Transport
	if transport == nil {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if clientCert != nil {
			tlsConfig.Certificates = []tls.Certificate{*clientCert}
		}
		if len(spkiPin) != 0 {
			pin := append([]byte(nil), spkiPin...)
			tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 || !witnessSPKIPinMatches(pin, state.PeerCertificates[0]) {
					return errors.New("witness server certificate SPKI pin mismatch")
				}
				return nil
			}
		}
		dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
		transport = &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				host, port, splitErr := net.SplitHostPort(address)
				if splitErr != nil || port != "443" {
					return nil, &witnessClientError{reason: "witness destination port refused", permanent: true}
				}
				if err := validateWitnessHost(host); err != nil {
					return nil, &witnessClientError{reason: err.Error(), permanent: true}
				}
				ips, lookupErr := net.DefaultResolver.LookupIPAddr(ctx, host)
				if lookupErr != nil || len(ips) == 0 {
					return nil, &witnessClientError{reason: "witness endpoint resolution failed"}
				}
				for _, candidate := range ips {
					addr, ok := netip.AddrFromSlice(candidate.IP)
					if !ok || !witnessIPAllowed(addr) {
						return nil, &witnessClientError{reason: "witness endpoint resolves to forbidden address", permanent: true}
					}
				}
				var lastDialErr error
				for _, candidate := range ips {
					addr, _ := netip.AddrFromSlice(candidate.IP)
					conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(addr.Unmap().String(), port))
					if dialErr == nil {
						return conn, nil
					}
					lastDialErr = dialErr
				}
				return nil, lastDialErr
			},
			TLSHandshakeTimeout: timeout,
			TLSClientConfig:     tlsConfig,
			MaxIdleConns:        2,
			IdleConnTimeout:     30 * time.Second,
			ForceAttemptHTTP2:   true,
		}
	} else if len(spkiPin) != 0 {
		transport = &witnessPinnedRoundTripper{base: transport, pin: append([]byte(nil), spkiPin...)}
	}
	client := &witnessHTTPClient{
		endpoint: parsed, receiptKey: receiptKey, spkiPin: append([]byte(nil), spkiPin...),
		bearer: bearer, challenges: newWitnessChallengeCache(time.Duration(settings.NonceTTLSeconds) * time.Second),
		retry: settings.RetryAttempts, backoff: time.Duration(settings.RetryBackoffSeconds) * time.Second,
		sleep: sleep, now: now, maxResponse: witnessMaxResponseBytes, lastSeq: cfg.InitialWitnessSeq,
		http: &http.Client{
			Transport: transport, Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errWitnessRedirectRefused
			},
		},
	}
	return client, nil
}

func (c *witnessHTTPClient) endpointURL(path string) string {
	return strings.TrimRight(c.endpoint.String(), "/") + path
}

func (c *witnessHTTPClient) doJSON(ctx context.Context, path string, body []byte) ([]byte, error) {
	attempts := c.retry + 1
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			backoff := c.backoff
			for i := 1; i < attempt; i++ {
				backoff *= 2
				if backoff > time.Hour {
					backoff = time.Hour
				}
			}
			c.sleep(backoff)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpointURL(path), bytes.NewReader(body))
		if err != nil {
			return nil, &witnessClientError{reason: "request could not be built", permanent: true}
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json")
		if c.bearer != "" {
			request.Header.Set("Authorization", "Bearer "+c.bearer)
		}
		response, err := c.http.Do(request)
		if err != nil {
			if errors.Is(err, errWitnessRedirectRefused) {
				return nil, &witnessClientError{reason: "redirect refused", permanent: true}
			}
			if witnessPermanent(err) {
				// A pin refusal is a trust decision, not a transient network
				// condition; retrying it would only produce a request storm.
				return nil, err
			}
			lastErr = &witnessClientError{reason: "network error"}
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, c.maxResponse+1))
		_ = response.Body.Close()
		if readErr != nil {
			lastErr = &witnessClientError{reason: "response could not be read"}
			continue
		}
		if int64(len(data)) > c.maxResponse {
			return nil, &witnessClientError{reason: "response exceeds the 64 KiB bound", permanent: true}
		}
		switch {
		case response.StatusCode >= 200 && response.StatusCode < 300:
			return data, nil
		case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
			// A pin/auth answer is not retried: a retry storm is exactly what a
			// misconfigured transport anchor would produce.
			return nil, &witnessClientError{reason: "authorization or pin rejected", permanent: true, auth: true}
		case response.StatusCode >= 300 && response.StatusCode < 400:
			// A redirect the transport did not follow (or one without a Location
			// header) is a permanent protocol violation, never a transient condition.
			return nil, &witnessClientError{reason: "redirect refused", permanent: true}
		case response.StatusCode >= 400 && response.StatusCode < 500:
			return nil, &witnessClientError{reason: "request permanently rejected", permanent: true}
		default:
			lastErr = &witnessClientError{reason: "witness server error"}
		}
	}
	return nil, lastErr
}

// Challenge fetches and accepts one fresh, single-use nonce.
func (c *witnessHTTPClient) Challenge(ctx context.Context) (string, error) {
	data, err := c.doJSON(ctx, "/v1/challenge", []byte("{}"))
	if err != nil {
		return "", err
	}
	var answer struct {
		Challenge string `json:"challenge"`
	}
	decoder := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&answer); err != nil {
		return "", &witnessClientError{reason: "challenge answer is malformed", permanent: true}
	}
	if err := c.challenges.issue(answer.Challenge, c.now()); err != nil {
		return "", &witnessClientError{reason: "challenge answer was rejected", permanent: true}
	}
	return answer.Challenge, nil
}

// Push sends one checkpoint and verifies the signed receipt. The checkpoint must
// carry a challenge issued by Challenge.
func (c *witnessHTTPClient) Push(ctx context.Context, checkpoint WitnessCheckpoint) (WitnessReceipt, error) {
	if err := c.challenges.claim(checkpoint.Challenge, c.now()); err != nil {
		return WitnessReceipt{}, &witnessClientError{reason: err.Error(), permanent: true}
	}
	body, err := EncodeWitnessCheckpoint(checkpoint)
	if err != nil {
		return WitnessReceipt{}, &witnessClientError{reason: "checkpoint is not encodable", permanent: true}
	}
	data, err := c.doJSON(ctx, "/v1/checkpoint", body)
	if err != nil {
		return WitnessReceipt{}, err
	}
	var answer struct {
		Receipt json.RawMessage `json:"receipt"`
	}
	decoder := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&answer); err != nil || len(answer.Receipt) == 0 {
		return WitnessReceipt{}, &witnessClientError{reason: "receipt answer is malformed", permanent: true}
	}
	receipt, err := DecodeWitnessReceipt(answer.Receipt)
	if err != nil {
		return WitnessReceipt{}, &witnessClientError{reason: "receipt was rejected: " + err.Error(), permanent: true}
	}
	if receipt.CheckpointID != checkpoint.CheckpointID {
		return WitnessReceipt{}, &witnessClientError{reason: "receipt does not bind the sent checkpoint", permanent: true}
	}
	if c.receiptKey != nil {
		if err := VerifyWitnessReceipt(receipt, c.receiptKey); err != nil {
			return WitnessReceipt{}, &witnessClientError{reason: "receipt signature was rejected", permanent: true}
		}
	}
	if acceptedAt, parseErr := time.Parse(time.RFC3339, receipt.AcceptedAt); parseErr != nil || acceptedAt.After(c.now().Add(witnessFutureSkew)) {
		return WitnessReceipt{}, &witnessClientError{reason: "receipt timestamp is not plausible", permanent: true}
	}
	c.seqMu.Lock()
	defer c.seqMu.Unlock()
	if receipt.WitnessSeq <= c.lastSeq {
		return WitnessReceipt{}, &witnessClientError{reason: "receipt sequence is not strictly monotonic", permanent: true}
	}
	c.lastSeq = receipt.WitnessSeq
	return receipt, nil
}

// LastWitnessSeq returns the highest verified witness sequence.
func (c *witnessHTTPClient) LastWitnessSeq() uint64 {
	c.seqMu.Lock()
	defer c.seqMu.Unlock()
	return c.lastSeq
}

// ChallengePending reports whether an accepted nonce is still waiting for a push.
func (c *witnessHTTPClient) ChallengePending() bool { return c.challenges.pending(c.now()) }

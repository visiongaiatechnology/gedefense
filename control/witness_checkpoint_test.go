// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// The contracts here describe one property: a witness checkpoint is a durable, coherent,
// domain-separated statement about a ledger head, and nothing else leaves the host.

func witnessMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func sealEvidenceHeadForTest(t *testing.T, ledger *EvidenceLedger, checkpoint evidenceCheckpoint) {
	t.Helper()
	raw, err := json.Marshal(checkpoint)
	witnessMust(t, err)
	sealed, err := ledger.crypto.Encrypt(ledger.headPath, "evidence-head", checkpoint.Sequence, raw)
	witnessMust(t, err)
	if err := os.WriteFile(ledger.headPath, append(sealed, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// witnessFixtureCheckpoint builds and signs a checkpoint for the ledger's current head. The fixed
// id and timestamp keep signatures comparable across calls.
func witnessFixtureCheckpoint(t *testing.T, ledger *EvidenceLedger, mutate func(*WitnessCheckpoint)) WitnessCheckpoint {
	t.Helper()
	view, err := ledger.Checkpoint()
	if err != nil {
		t.Fatalf("checkpoint view: %v", err)
	}
	policyDigest, err := PolicyDigest(RuntimeSettings{Revision: 17, UpdatedAt: time.Date(2026, 11, 15, 8, 0, 0, 0, time.UTC)})
	witnessMust(t, err)
	checkpoint := WitnessCheckpoint{
		Schema: WitnessCheckpointSchema, Version: witnessCheckpointVersion, NodeID: "test-node",
		CheckpointID: strings.Repeat("ab", 16), CreatedAt: "2026-11-15T12:00:00Z",
		LedgerEpoch: view.LedgerEpoch, Sequence: view.Sequence, HeadHash: view.HeadHash,
		Records: view.Records, SigningKeyFP: view.PublicKeyFingerprint, BootPosture: "OBSERVE",
		BootPostureDigest: strings.Repeat("11", 32), QuoteKind: "none", PolicyRevision: 17,
		PolicyDigest: policyDigest, SensorState: "online", Challenge: "deadbeef",
	}
	if mutate != nil {
		mutate(&checkpoint)
	}
	signed, err := SignWitnessCheckpoint(checkpoint, ledger.WitnessCheckpointSigner())
	if err != nil {
		t.Fatalf("sign witness checkpoint: %v", err)
	}
	return signed
}

func TestEvidenceLedgerEpochPersistsAcrossReloadAndRotation(t *testing.T) {
	ledger, path := evidenceFixture(t)
	appendEvidenceRecords(t, ledger, 3)
	view, err := ledger.Checkpoint()
	witnessMust(t, err)
	if view.LedgerEpoch != 0 || view.Sequence != 3 || view.Records != 3 || view.HeadHash == "" {
		t.Fatalf("unexpected checkpoint view: %+v", view)
	}
	if status := ledger.Status(); status.LedgerEpoch != 0 || status.PublicKeyFingerprint != view.PublicKeyFingerprint {
		t.Fatalf("status does not carry the witness identity: %+v", status)
	}
	if _, err := ledger.Rotate(context.Background(), "witness epoch fixture"); err != nil {
		t.Fatalf("rotation failed: %v", err)
	}
	if status := ledger.Status(); status.LedgerEpoch != 1 || status.Records != 0 || status.HeadHash != "" {
		t.Fatalf("rotation did not advance the epoch: %+v", status)
	}
	reloaded, err := reloadEvidence(t, path, 4<<20)
	witnessMust(t, err)
	if view, err = reloaded.Checkpoint(); err != nil || view.LedgerEpoch != 1 || view.Sequence != 0 {
		t.Fatalf("epoch after reload: %+v, %v", view, err)
	}
	appendEvidenceRecords(t, reloaded, 2)
	// A rotation interrupted by a crash must complete into the next epoch, not restart at 1.
	reloaded.mu.Lock()
	archiveID, manifestSHA, err := reloaded.sealLocked(context.Background(), "interrupted witness epoch")
	if err == nil {
		err = reloaded.writeRotationMarkerLocked(archiveID, manifestSHA)
	}
	reloaded.mu.Unlock()
	witnessMust(t, err)
	completed, err := reloadEvidence(t, path, 4<<20)
	witnessMust(t, err)
	if err := completed.Healthy(); err != nil {
		t.Fatalf("interrupted rotation was not completed: %v", err)
	}
	if view, err = completed.Checkpoint(); err != nil || view.LedgerEpoch != 2 {
		t.Fatalf("completed rotation epoch: %+v, %v", view, err)
	}
	appendEvidenceRecords(t, completed, 1)
	if err := completed.Verify(); err != nil {
		t.Fatalf("the chain after the completed rotation does not verify: %v", err)
	}
	if view, err = completed.Checkpoint(); err != nil || view.LedgerEpoch != 2 || view.Sequence != 1 {
		t.Fatalf("checkpoint after the completed rotation: %+v, %v", view, err)
	}
}

func TestALegacyHeadWithoutLedgerEpochReadsAsEpochZero(t *testing.T) {
	ledger, path := evidenceFixture(t)
	appendEvidenceRecords(t, ledger, 2)
	current, err := readEvidenceCheckpoint(path+".head", ledger.crypto)
	witnessMust(t, err)
	// Exactly the pre-POINT4 format: no ledger_epoch field at all.
	sealEvidenceHeadForTest(t, ledger, evidenceCheckpoint{Version: current.Version, Sequence: current.Sequence, HeadHash: current.HeadHash})
	reloaded, err := reloadEvidence(t, path, 4<<20)
	witnessMust(t, err)
	if err := reloaded.Healthy(); err != nil {
		t.Fatalf("a legacy checkpoint was quarantined: %v", err)
	}
	if view, err := reloaded.Checkpoint(); err != nil || view.LedgerEpoch != 0 || view.Sequence != 2 {
		t.Fatalf("legacy epoch: %+v, %v", view, err)
	}
	if _, err := reloaded.Append(EvidenceRecord{Severity: "info", Kind: "test.legacy", Source: "test", Message: "record"}); err != nil {
		t.Fatal(err)
	}
	again, err := reloadEvidence(t, path, 4<<20)
	witnessMust(t, err)
	if view, err := again.Checkpoint(); err != nil || view.LedgerEpoch != 0 || view.Sequence != 3 {
		t.Fatalf("legacy epoch did not stay 0: %+v, %v", view, err)
	}
	// The first rotation after the upgrade starts the counter at 1 and persists it.
	if _, err := again.Rotate(context.Background(), "legacy rotation"); err != nil {
		t.Fatal(err)
	}
	rotated, err := reloadEvidence(t, path, 4<<20)
	witnessMust(t, err)
	if view, err := rotated.Checkpoint(); err != nil || view.LedgerEpoch != 1 {
		t.Fatalf("legacy rotation epoch: %+v, %v", view, err)
	}
}

func TestCheckpointNeverAdvancesPastTheDurableHead(t *testing.T) {
	ledger, path := evidenceFixture(t)
	appendEvidenceRecords(t, ledger, 1)
	first, err := readEvidenceCheckpoint(path+".head", ledger.crypto)
	witnessMust(t, err)
	appendEvidenceRecords(t, ledger, 1)
	view, err := ledger.Checkpoint()
	witnessMust(t, err)
	durable, err := readEvidenceCheckpoint(path+".head", ledger.crypto)
	witnessMust(t, err)
	if view.Sequence != 2 || durable.Sequence != view.Sequence || durable.HeadHash != view.HeadHash || durable.LedgerEpoch != view.LedgerEpoch {
		t.Fatalf("checkpoint view is not the durable head: view=%+v durable=%+v", view, durable)
	}
	// Rewind the authenticated checkpoint behind the in-memory head: returning either head would
	// let a witness record a state the trusted writer never sealed.
	sealEvidenceHeadForTest(t, ledger, first)
	if _, err := ledger.Checkpoint(); err == nil {
		t.Fatal("a stale authenticated checkpoint was accepted as the head")
	}
	if err := ledger.Healthy(); err == nil {
		t.Fatal("a stale checkpoint did not quarantine the ledger")
	}
	quarantined, _ := evidenceFixture(t)
	appendEvidenceRecords(t, quarantined, 1)
	quarantined.mu.Lock()
	quarantined.integrityErr = errors.New("damaged")
	quarantined.mu.Unlock()
	if _, err := quarantined.Checkpoint(); err == nil {
		t.Fatal("a quarantined ledger produced a checkpoint view")
	}
}

func TestCheckpointIsAtomicUnderConcurrentAppends(t *testing.T) {
	ledger, _ := evidenceFixture(t)
	appendEvidenceRecords(t, ledger, 1)
	stop := make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := ledger.Append(EvidenceRecord{Severity: "info", Kind: "test.atomic", Source: "test", Message: "concurrent"}); err != nil {
				return
			}
		}
	}()
	previous := uint64(0)
	for i := 0; i < 64; i++ {
		view, err := ledger.Checkpoint()
		if err != nil {
			close(stop)
			writer.Wait()
			t.Fatalf("checkpoint during concurrent appends: %v", err)
		}
		if view.Sequence < previous || view.Records != view.Sequence || (view.Sequence > 0 && len(view.HeadHash) != 64) {
			close(stop)
			writer.Wait()
			t.Fatalf("incoherent checkpoint view: %+v", view)
		}
		previous = view.Sequence
	}
	close(stop)
	writer.Wait()
	final, err := ledger.Checkpoint()
	witnessMust(t, err)
	if final.Sequence != ledger.Status().Records {
		t.Fatalf("checkpoint and status disagree: view=%d status=%d", final.Sequence, ledger.Status().Records)
	}
}

func TestPublicKeyFingerprintMatchesThePublicKeyFile(t *testing.T) {
	ledger, path := evidenceFixture(t)
	public, err := os.ReadFile(ledger.publicPath)
	witnessMust(t, err)
	sum := sha256.Sum256(public)
	want := hex.EncodeToString(sum[:])
	fingerprint, err := ledger.PublicKeyFingerprint()
	witnessMust(t, err)
	if fingerprint != want || len(fingerprint) != 64 || strings.ToLower(fingerprint) != fingerprint {
		t.Fatalf("fingerprint %q is not sha256(pubkey) %q", fingerprint, want)
	}
	reloaded, err := reloadEvidence(t, path, 4<<20)
	witnessMust(t, err)
	if again, err := reloaded.PublicKeyFingerprint(); err != nil || again != fingerprint {
		t.Fatalf("fingerprint changed across reload: %q, %v", again, err)
	}
	if status := reloaded.Status(); status.PublicKeyFingerprint != fingerprint || status.PublicKey != hex.EncodeToString(public) {
		t.Fatalf("status key identity is wrong: %+v", status)
	}
	var nilLedger *EvidenceLedger
	if _, err := nilLedger.PublicKeyFingerprint(); err == nil {
		t.Fatal("a nil ledger produced a fingerprint")
	}
	if _, err := nilLedger.Checkpoint(); err == nil {
		t.Fatal("a nil ledger produced a checkpoint")
	}
}

func TestWitnessCheckpointSignatureIsDeterministicAndVerifies(t *testing.T) {
	if WitnessCheckpointSchema != "vgt-gedefense-witness-checkpoint-v1" {
		t.Fatalf("schema drifted: %q", WitnessCheckpointSchema)
	}
	ledger, _ := evidenceFixture(t)
	appendEvidenceRecords(t, ledger, 3)
	checkpoint := witnessFixtureCheckpoint(t, ledger, nil)
	if again := witnessFixtureCheckpoint(t, ledger, nil); again.Signature != checkpoint.Signature {
		t.Fatal("the same checkpoint produced two different signatures")
	}
	encoded, err := EncodeWitnessCheckpoint(checkpoint)
	witnessMust(t, err)
	decoded, err := DecodeWitnessCheckpoint(encoded)
	witnessMust(t, err)
	if decoded != checkpoint {
		t.Fatalf("round trip changed the checkpoint: %+v", decoded)
	}
	if err := VerifyWitnessCheckpoint(decoded, ledger.publicKey); err != nil {
		t.Fatalf("the checkpoint does not verify: %v", err)
	}
	if _, err := VerifyWitnessCheckpointJSON(encoded, ledger.publicKey); err != nil {
		t.Fatalf("the JSON form does not verify: %v", err)
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	witnessMust(t, err)
	if err := VerifyWitnessCheckpoint(checkpoint, otherPublic); err == nil {
		t.Fatal("a checkpoint verified against the wrong key")
	}
	tampered := checkpoint
	tampered.Sequence++
	tampered.Records++
	if err := VerifyWitnessCheckpoint(tampered, ledger.publicKey); err == nil {
		t.Fatal("a checkpoint with an edited sequence verified")
	}
	// The signature has to be bound to the checkpoint domain, not to the payload alone.
	payload, err := witnessCheckpointCanonicalPayload(checkpoint)
	witnessMust(t, err)
	bareDigest := sha256.Sum256(payload)
	wrongDomain := checkpoint
	wrongDomain.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ledger.privateKey, bareDigest[:]))
	if err := VerifyWitnessCheckpoint(wrongDomain, ledger.publicKey); err == nil {
		t.Fatal("a signature over the undomained payload verified")
	}
	// An empty ledger has no head but still has a coherent, signable checkpoint.
	emptyLedger, _ := evidenceFixture(t)
	empty := witnessFixtureCheckpoint(t, emptyLedger, nil)
	if empty.Sequence != 0 || empty.HeadHash != "" || empty.Records != 0 {
		t.Fatalf("empty ledger checkpoint: %+v", empty)
	}
	if err := VerifyWitnessCheckpoint(empty, emptyLedger.publicKey); err != nil {
		t.Fatalf("empty ledger checkpoint does not verify: %v", err)
	}
}

func TestWitnessCheckpointDecodeRejectsInsteadOfRepairing(t *testing.T) {
	ledger, _ := evidenceFixture(t)
	appendEvidenceRecords(t, ledger, 3)
	checkpoint := witnessFixtureCheckpoint(t, ledger, nil)
	canonical, err := EncodeWitnessCheckpoint(checkpoint)
	witnessMust(t, err)
	object := func(t *testing.T) map[string]any {
		t.Helper()
		decoder := json.NewDecoder(strings.NewReader(string(canonical)))
		decoder.UseNumber()
		var decoded map[string]any
		if err := decoder.Decode(&decoded); err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	mutations := map[string]func(map[string]any){
		"schema":            func(o map[string]any) { o["schema"] = "vgt-gedefense-witness-checkpoint-v2" },
		"version":           func(o map[string]any) { o["version"] = json.Number("2") },
		"version fraction":  func(o map[string]any) { o["version"] = json.Number("1.0") },
		"node id empty":     func(o map[string]any) { o["node_id"] = "" },
		"node id oversized": func(o map[string]any) { o["node_id"] = strings.Repeat("a", 129) },
		"node id path":      func(o map[string]any) { o["node_id"] = "../../etc/passwd" },
		"checkpoint id":     func(o map[string]any) { o["checkpoint_id"] = strings.Repeat("AB", 16) },
		"checkpoint short":  func(o map[string]any) { o["checkpoint_id"] = "abcd" },
		"created at offset": func(o map[string]any) { o["created_at"] = "2026-11-15T12:00:00+02:00" },
		"created at frac":   func(o map[string]any) { o["created_at"] = "2026-11-15T12:00:00.5Z" },
		"created at text":   func(o map[string]any) { o["created_at"] = "yesterday" },
		"epoch bound":       func(o map[string]any) { o["ledger_epoch"] = json.Number("9007199254740993") },
		"epoch negative":    func(o map[string]any) { o["ledger_epoch"] = json.Number("-1") },
		"sequence bound": func(o map[string]any) {
			o["sequence"] = json.Number("9007199254740993")
			o["records"] = json.Number("9007199254740993")
		},
		"sequence type":       func(o map[string]any) { o["sequence"] = "3" },
		"records mismatch":    func(o map[string]any) { o["records"] = json.Number("4") },
		"head without record": func(o map[string]any) { o["sequence"] = json.Number("0"); o["records"] = json.Number("0") },
		"head uppercase":      func(o map[string]any) { o["head_hash"] = strings.ToUpper(checkpoint.HeadHash) },
		"head short":          func(o map[string]any) { o["head_hash"] = checkpoint.HeadHash[:63] },
		"signing fp":          func(o map[string]any) { o["signing_key_fp"] = strings.Repeat("0", 63) },
		"boot posture":        func(o map[string]any) { o["boot_posture"] = "verified" },
		"boot posture empty":  func(o map[string]any) { o["boot_posture"] = "" },
		"boot digest":         func(o map[string]any) { o["boot_posture_digest"] = "not-hex" },
		"quote kind":          func(o map[string]any) { o["quote_kind"] = "tpm2-quote" },
		"policy revision":     func(o map[string]any) { o["policy_revision"] = json.Number("9007199254740993") },
		"policy digest":       func(o map[string]any) { o["policy_digest"] = "" },
		"sensor state":        func(o map[string]any) { o["sensor_state"] = "unknown" },
		"challenge odd":       func(o map[string]any) { o["challenge"] = "abc" },
		"challenge upper":     func(o map[string]any) { o["challenge"] = "DEADBEEF" },
		"challenge oversized": func(o map[string]any) { o["challenge"] = strings.Repeat("aa", 129) },
		"signature padded":    func(o map[string]any) { o["signature"] = checkpoint.Signature + "==" },
		"signature text":      func(o map[string]any) { o["signature"] = "AAAA" },
		"null field":          func(o map[string]any) { o["challenge"] = nil },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := object(t)
			mutate(changed)
			data, err := json.Marshal(changed)
			witnessMust(t, err)
			if _, err := DecodeWitnessCheckpoint(data); err == nil {
				t.Fatalf("mutation %q was decoded instead of rejected: %s", name, data)
			}
		})
	}
	// Every required field has to be present, not just non-zero.
	for _, field := range witnessCheckpointFieldNames {
		t.Run("missing "+field, func(t *testing.T) {
			changed := object(t)
			delete(changed, field)
			data, err := json.Marshal(changed)
			witnessMust(t, err)
			if _, err := DecodeWitnessCheckpoint(data); err == nil {
				t.Fatalf("checkpoint without %q was accepted", field)
			}
		})
	}
	duplicate := strings.Replace(string(canonical), "{", `{"schema":"`+WitnessCheckpointSchema+`",`, 1)
	unknown := object(t)
	unknown["extra"] = true
	unknownJSON, err := json.Marshal(unknown)
	witnessMust(t, err)
	malformed := map[string][]byte{
		"empty": nil, "array": []byte("[]"), "null": []byte("null"), "truncated": []byte("{"),
		"duplicate": []byte(duplicate), "unknown field": unknownJSON,
		"trailing":       append(append([]byte(nil), canonical...), []byte(`{}`)...),
		"trailing comma": append(append([]byte(nil), canonical...), ',', '}'),
		"oversized":      []byte(strings.Repeat("a", witnessCheckpointMaxBytes+1)),
	}
	for name, data := range malformed {
		if _, err := DecodeWitnessCheckpoint(data); err == nil {
			t.Fatalf("malformed document %q was accepted", name)
		}
	}
	if _, err := DecodeWitnessCheckpoint(canonical); err != nil {
		t.Fatalf("the unmodified canonical checkpoint was rejected: %v", err)
	}
}

func TestWitnessCheckpointCarriesNoPathsOrSecrets(t *testing.T) {
	ledger, _ := evidenceFixture(t)
	appendEvidenceRecords(t, ledger, 2)
	report := BootTrustReport{Status: "OBSERVE", Items: []BootTrustEvidence{{
		ID: "secure-boot", State: "verified", Digest: strings.Repeat("a", 64),
		Summary:  "kernel cmdline root=/dev/mapper/vgt-root",
		Source:   "/sys/firmware/efi/efivars/SecureBoot-8be4df61",
		Evidence: "token=SUPERSECRET",
	}}}
	policyDigest, err := PolicyDigest(RuntimeSettings{
		Revision: 17, UpdatedAt: time.Date(2026, 11, 15, 8, 0, 0, 0, time.UTC),
		ManagementAllowlist: []string{"10.0.0.5", "/var/lib/vgt/private"},
	})
	witnessMust(t, err)
	checkpoint := witnessFixtureCheckpoint(t, ledger, func(c *WitnessCheckpoint) {
		c.BootPosture = report.Status
		c.BootPostureDigest = BootPostureDigest(report)
		c.PolicyDigest = policyDigest
	})
	encoded, err := EncodeWitnessCheckpoint(checkpoint)
	witnessMust(t, err)
	text := string(encoded)
	for _, forbidden := range []string{"/", "\\", "root=", "SUPERSECRET", "10.0.0.5", "cmdline", "efivars", "BEGIN", "PRIVATE KEY", "source", "evidence", "summary"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("checkpoint JSON leaks %q: %s", forbidden, text)
		}
	}
	changed := BootTrustReport{Status: "OBSERVE", Items: []BootTrustEvidence{{
		ID: "secure-boot", State: "verified", Digest: strings.Repeat("a", 64),
		Summary: "different prose", Source: "/elsewhere", Evidence: "other secret",
	}}}
	if digest := BootPostureDigest(changed); digest != checkpoint.BootPostureDigest {
		t.Fatal("the boot posture digest depends on source or evidence text")
	}
	changed.Items[0].State = "failed"
	if digest := BootPostureDigest(changed); digest == checkpoint.BootPostureDigest {
		t.Fatal("the boot posture digest ignores the item state")
	}
}

func TestBootPostureDigestIsCanonicalAndStable(t *testing.T) {
	left := BootTrustReport{Items: []BootTrustEvidence{
		{ID: "kernel", State: "verified", Digest: strings.Repeat("1", 64)},
		{ID: "firmware", State: "observe", Digest: strings.Repeat("2", 64)},
	}}
	right := BootTrustReport{Items: []BootTrustEvidence{
		{ID: "firmware", State: "observe", Digest: strings.Repeat("2", 64)},
		{ID: "kernel", State: "verified", Digest: strings.Repeat("1", 64)},
	}}
	digest := BootPostureDigest(left)
	if len(digest) != 64 || digest != BootPostureDigest(left) || digest != BootPostureDigest(right) {
		t.Fatalf("boot posture digest is not canonical: %q", digest)
	}
	if empty := (BootTrustReport{}); BootPostureDigest(empty) != BootPostureDigest(empty) {
		t.Fatal("empty boot posture digest is not stable")
	}
	left.Items[0].Digest = strings.Repeat("3", 64)
	if BootPostureDigest(left) == digest {
		t.Fatal("the boot posture digest ignores an item digest")
	}
}

func TestPolicyDigestIsDeterministicAndCanonical(t *testing.T) {
	fixed := time.Date(2026, 11, 15, 8, 0, 0, 0, time.UTC)
	settings := RuntimeSettings{Revision: 17, UpdatedAt: fixed, ManagementAllowlist: []string{"10.0.0.5"}}
	digest, err := PolicyDigest(settings)
	witnessMust(t, err)
	if len(digest) != 64 {
		t.Fatalf("policy digest is not a SHA-256: %q", digest)
	}
	zoned := RuntimeSettings{Revision: 17, UpdatedAt: fixed.In(time.FixedZone("CEST", 2*3600)), ManagementAllowlist: []string{"10.0.0.5"}}
	if other, err := PolicyDigest(zoned); err != nil || other != digest {
		t.Fatalf("policy digest depends on the time zone: %q, %v", other, err)
	}
	canonical := settings
	canonical.UpdatedAt = canonical.UpdatedAt.UTC()
	data, err := json.Marshal(canonical)
	witnessMust(t, err)
	sum := sha256.Sum256(data)
	if want := hex.EncodeToString(sum[:]); digest != want {
		t.Fatalf("policy digest is not sha256(canonical runtime settings): %q != %q", digest, want)
	}
	changed := settings
	changed.Revision = 18
	if other, err := PolicyDigest(changed); err != nil || other == digest {
		t.Fatalf("policy digest ignores the settings revision: %q, %v", other, err)
	}
}

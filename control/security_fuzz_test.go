package main

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func FuzzCoreResponseParser(f *testing.F) {
	key := []byte("0123456789abcdef0123456789abcdef")
	nonce := "0123456789abcdef0123456789abcdef"
	payload := base64.RawURLEncoding.EncodeToString([]byte("empty"))
	tag := coreProtocol + "R"
	valid := strings.Join([]string{tag, nonce, "OK", payload, coreMAC(key, tag, nonce, "OK", payload)}, " ") + "\n"
	f.Add(valid)
	f.Add("")
	f.Add(strings.Repeat("A", maxCoreResponseBytes+1))
	f.Fuzz(func(t *testing.T, response string) {
		message, err := parseCoreResponse(response, nonce, key)
		if err == nil && len(message) > maxCoreResponsePayloadBytes {
			t.Fatalf("accepted oversized authenticated payload: %d", len(message))
		}
	})
}

func FuzzPolicyDocumentParser(f *testing.F) {
	f.Add([]byte(`{"envelope":{"version":1,"generation":0,"node_name":"n","enforcement":"observe","xdr_mode":"observe","updated_at":"2026-01-01T00:00:00Z","blocks":[]},"signature":""}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{} {}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		doc, err := decodePolicyDocument(data)
		if err == nil {
			if doc.Envelope.Version != policyDocumentVersion {
				t.Fatalf("accepted unsupported version %d", doc.Envelope.Version)
			}
			if _, err := canonicalPolicy(doc.Envelope); err != nil {
				t.Fatalf("accepted document cannot be canonicalized: %v", err)
			}
		}
	})
}

func FuzzEncryptedEnvelopeParser(f *testing.F) {
	f.Add([]byte(`{"schema":"vgt-encrypted-state-v1","cipher":"AES-256-GCM","purpose":"test","sequence":1,"aad_hash":"","nonce":"","ciphertext":""}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schema":"vgt-encrypted-state-v1"} trailing`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		envelope, err := decodeEncryptedStorageEnvelope(data)
		if err == nil && envelope.Schema == "" {
			// Structural decoding may accept zero values, but it must remain
			// distinguishable from the authenticated schema.
			return
		}
	})
}

func FuzzCoreTitanExecParser(f *testing.F) {
	f.Add("empty")
	f.Add("0|12345:1700000000000000000:64768:33188:4242:7:321:321:1000:1000:0:0:1:1:0:62617368")
	f.Add("3|99:1700000001000000000:64768:33261:77:0:4194000:4194000:0:0:5:0:2:1:5:")
	f.Add("0|12345:1700000000000000000:64768:33188:4242:7:321:321:1000:1000:0:0:1:2:4:fffe4142")
	f.Add("0|12345:1700000000000000000:64768:33188:4242:7:321:321:1000:1000:0:0:1:1:0:410042")
	f.Add("1|")
	f.Add("0|")
	f.Add("x|")
	f.Add(strings.Repeat("A", 4096))
	f.Fuzz(func(t *testing.T, payload string) {
		events, dropped, err := parseCoreTitanExecEvents(payload)
		if err != nil {
			if events != nil || dropped != 0 {
				t.Fatalf("rejected batch returned partial state: events=%d dropped=%d", len(events), dropped)
			}
			return
		}
		if len(events) > titanExecMaxEventsPerResponse {
			t.Fatalf("accepted more than the batch ceiling: %d", len(events))
		}
		for _, event := range events {
			if event.Hook != titanExecHookBprm && event.Hook != titanExecHookMmap {
				t.Fatalf("accepted invalid hook: %d", event.Hook)
			}
			if event.Action != titanExecActionAudit && event.Action != titanExecActionDeny {
				t.Fatalf("accepted invalid action: %d", event.Action)
			}
			if event.Reason > titanExecReasonMax {
				t.Fatalf("accepted invalid reason: %d", event.Reason)
			}
			if event.PID == 0 || event.TsNS == 0 {
				t.Fatal("accepted an event without pid or timestamp")
			}
			if event.Hook == titanExecHookMmap && event.Prot == 0 {
				t.Fatal("accepted an mmap event without a protection mask")
			}
			if event.Action == titanExecActionDeny &&
				(event.Reason == titanExecReasonNone || event.Reason == titanExecReasonReadFailure) {
				t.Fatal("accepted a deny without a policy ground")
			}
			if (event.Dev == 0) != (event.Ino == 0) {
				t.Fatal("accepted a half-null identity")
			}
			if len(event.Comm) > 16 {
				t.Fatalf("accepted oversized comm: %d bytes", len(event.Comm))
			}
		}
	})
}

func FuzzCoreStyxFlowParser(f *testing.F) {
	f.Add("empty")
	f.Add("0|0000000000001234:1700000000000000000:1024:0:4242:1000:cb007109:443:51000:7:4:6:1:18:0:6375726c")
	f.Add("3|0000000000000002:1700000000000000001:2048:0:99:0:20010db8000000000000000000000001:53:40000:3:6:17:1:0:2:")
	f.Add("1|")
	f.Add("x|")
	f.Add("0|")
	f.Add(strings.Repeat("A", 4096))
	f.Fuzz(func(t *testing.T, response string) {
		events, dropped, err := parseCoreStyxFlowEvents(response)
		if err != nil {
			if events != nil || dropped != 0 {
				t.Fatalf("rejected batch returned partial state: events=%d dropped=%d", len(events), dropped)
			}
			return
		}
		if len(events) > maxStyxFlowEventsPerResponse {
			t.Fatalf("accepted more than the batch ceiling: %d", len(events))
		}
		for _, event := range events {
			if event.Family != 4 && event.Family != 6 {
				t.Fatalf("accepted invalid family: %d", event.Family)
			}
			if event.Proto != 0 && event.Proto != 6 && event.Proto != 17 {
				t.Fatalf("accepted invalid protocol: %d", event.Proto)
			}
			if event.Proto == 0 && (event.DstPort != 0 || event.SrcPort != 0) {
				t.Fatal("accepted ports for neutral protocol")
			}
			if event.Proto != 6 && event.TCPFlags != 0 {
				t.Fatal("accepted TCP flags for a non-TCP flow")
			}
			if event.TimestampNS == 0 || event.Packets == 0 || event.Verdict > 5 {
				t.Fatal("accepted out-of-range counters")
			}
			if event.Direction != 1 && event.Direction != 2 {
				t.Fatalf("accepted invalid direction: %d", event.Direction)
			}
			if event.Family == 4 && (len(event.DstIP) != 4 || event.DstIP.To4() == nil) {
				t.Fatal("accepted non-canonical IPv4 destination")
			}
			if event.Family == 6 && len(event.DstIP) != 16 {
				t.Fatal("accepted non-canonical IPv6 destination")
			}
			if len(event.Comm) > 16 {
				t.Fatalf("accepted oversized comm: %d bytes", len(event.Comm))
			}
		}
	})
}

// FuzzParserCellPayload exercises the VGTGC2 payload/frame parser of POINT 2
// (P2-T3): the `k=v` field list, the CELL_LIST row framing and the authenticated
// response frame. A panic or an accepted frame whose payload escapes the
// documented bounds would be a remote pre-authentication problem for the helper
// channel, so the target asserts the closed shape of every accepted answer.
func FuzzParserCellPayload(f *testing.F) {
	key := []byte("0123456789abcdef0123456789abcdef")
	capabilityKeys := []string{"abi", "sandbox", "profiles", "max_concurrent", "input_bytes", "export_bytes", "ttl_max", "bpf_lsm"}
	validPayload := "abi=cell-runtime-v1\x1fsandbox=true\x1fprofiles=pdf-viewer\x1fmax_concurrent=16\x1finput_bytes=8388608\x1fexport_bytes=2097152\x1fttl_max=3600\x1fbpf_lsm=active"
	f.Add([]byte(validPayload))
	f.Add([]byte(""))
	f.Add([]byte("\x1f\x1f"))
	f.Add([]byte("count=0\n"))
	f.Add([]byte("count=1\nuuid=" + strings.Repeat("a", 32) + "\x1fgeneration=1\x1fcgroup_id=42\x1fprofile=pdf-viewer\x1fstate=isolated\x1fexpires_at=1700000000\x1fpid=99\x1fexport_size=0\n"))
	f.Add([]byte(strings.Repeat("A", parserCellResponseMaxBytes+1)))
	b64 := base64.RawURLEncoding.EncodeToString([]byte(validPayload))
	id := "0123456789abcdef"
	mac := hex.EncodeToString(parserCellMAC(key, strings.Join([]string{parserCellResponseTag, id, "OK", b64}, parserCellSep)))
	f.Add([]byte(parserCellResponseTag + parserCellSep + id + parserCellSep + "OK" + parserCellSep + b64 + parserCellSep + mac))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 2*parserCellResponseMaxBytes {
			t.Skip()
		}
		values, err := parseParserCellPayload(raw, capabilityKeys...)
		if err == nil {
			if len(values) != len(capabilityKeys) {
				t.Fatalf("accepted a payload with %d values for %d keys", len(values), len(capabilityKeys))
			}
			for index, value := range values {
				if !parserCellPayloadValueValid(value) {
					t.Fatalf("accepted a value outside the payload charset at %d", index)
				}
			}
		}
		cells, err := parseParserCellList(raw)
		if err == nil {
			if len(cells) > parserCellMaxListCells {
				t.Fatalf("accepted %d list rows above the bound", len(cells))
			}
			for _, cell := range cells {
				if len(cell.UUID) != 32 || cell.CgroupID == 0 || !parserCellStateValid(cell.State) {
					t.Fatalf("accepted an invalid list row: %+v", cell)
				}
			}
		}
		if _, err := parseParserCellResponse(string(raw), id, key); err == nil && len(raw) > parserCellResponseMaxBytes {
			t.Fatalf("accepted an oversized authenticated frame: %d", len(raw))
		}
	})
}

// FuzzCoreLockdownStatusParser exercises the POINT 5 / P5-T3 text-wire parsers
// of the LOCKDOWN_STATUS and LOCKDOWN_TRIGGER answers. A panic or an accepted
// answer that escapes the documented bounds would let a buggy or hostile core
// drive the emergency-lockdown status projection, so every accepted answer is
// checked against the closed vocabulary.
func FuzzCoreLockdownStatusParser(f *testing.F) {
	f.Add("state=off;epoch=0badc0de;mode=unlocked;flags=0;phases=;unsupported=")
	f.Add("state=active;epoch=0badc0de;mode=locked;flags=9;phases=net,usb,tb,brokers;unsupported=hardening")
	f.Add("triggered:0badc0de;phases=net,usb;unsupported=")
	f.Add("triggered:0badc0de;phases=net;unsupported=hardening")
	f.Add("")
	f.Add("state=active;epoch=zzzzzzzz;mode=locked;flags=1;phases=net;unsupported=")
	f.Add("triggered:0badc0de;phases=net;unsupported=net,net")
	f.Add(strings.Repeat("A", maxLockdownPayloadBytes+1))
	f.Fuzz(func(t *testing.T, payload string) {
		if len(payload) > maxLockdownPayloadBytes+1 {
			t.Skip()
		}
		if status, err := parseCoreLockdownStatus(payload); err == nil {
			if !validLockdownEpoch(status.Epoch) || (status.Mode != lockdownModeLocked && status.Mode != lockdownModeUnlocked) {
				t.Fatalf("accepted an invalid status: %+v", status)
			}
			switch status.State {
			case "off", "armed", "active", "degraded":
			default:
				t.Fatalf("accepted an unknown status state: %q", status.State)
			}
			if len(status.Applied) > lockdownMaxUnsupportedPhases || len(status.Unsupported) > lockdownMaxUnsupportedPhases {
				t.Fatal("accepted an unbounded phase list")
			}
		}
		if result, err := parseCoreLockdownTrigger(payload); err == nil {
			if !validLockdownEpoch(result.Epoch) {
				t.Fatalf("accepted an invalid trigger epoch: %q", result.Epoch)
			}
			if len(result.Applied) > lockdownMaxUnsupportedPhases || len(result.Unsupported) > lockdownMaxUnsupportedPhases {
				t.Fatal("accepted an unbounded trigger phase list")
			}
		}
	})
}

// FuzzCoreLockdownEventsParser exercises the Alles-oder-Nichts lifecycle-event
// batch (§5). A rejected batch must never return partial state, and an accepted
// one must stay inside the documented 16-record ceiling with closed enums.
func FuzzCoreLockdownEventsParser(f *testing.F) {
	f.Add("empty")
	f.Add("0|1:1700000000000:1:5:1:1")
	f.Add("3|1:1700000000000:1:5:1:1,2:1700000000001:3:7:6:5")
	f.Add("1|")
	f.Add("0|")
	f.Add("x|")
	f.Add("0|1:1700000000000:1:5:1:1:extra")
	f.Add("0|1:0:1:5:1:1")
	f.Add(strings.Repeat("A", maxLockdownPayloadBytes+1))
	f.Fuzz(func(t *testing.T, payload string) {
		if len(payload) > maxLockdownPayloadBytes+1 {
			t.Skip()
		}
		events, dropped, err := parseCoreLockdownEvents(payload)
		if err != nil {
			if events != nil || dropped != 0 {
				t.Fatalf("rejected batch returned partial state: events=%d dropped=%d", len(events), dropped)
			}
			return
		}
		if len(events) > maxLockdownEventsPerResponse {
			t.Fatalf("accepted more than the batch ceiling: %d", len(events))
		}
		for _, event := range events {
			if event.Seq == 0 || event.Timestamp == 0 {
				t.Fatal("accepted an event without sequence or timestamp")
			}
			if event.Source < 1 || event.Source > 4 || event.Reason < 1 || event.Reason > 8 ||
				event.Phase > 8 || event.Outcome < 1 || event.Outcome > 5 {
				t.Fatalf("accepted out-of-range event enums: %+v", event)
			}
		}
	})
}

// FuzzWitnessCheckpointDecode exercises the POINT 4 checkpoint decoder. An
// accepted document must always be a fully valid checkpoint (schema, exact field
// set, bounded counters, hex, enums, signature shape) and must re-encode without
// growing past its own size bound.
func FuzzWitnessCheckpointDecode(f *testing.F) {
	signature := strings.Repeat("A", 86)
	seed := `{"schema":"` + WitnessCheckpointSchema + `","version":1,"node_id":"n1","checkpoint_id":"` +
		strings.Repeat("ab", 16) + `","created_at":"2026-11-15T12:00:00Z","ledger_epoch":0,"sequence":3,"head_hash":"` +
		strings.Repeat("11", 32) + `","records":3,"signing_key_fp":"` + strings.Repeat("22", 32) +
		`","boot_posture":"OBSERVE","boot_posture_digest":"` + strings.Repeat("33", 32) +
		`","quote_kind":"none","policy_revision":17,"policy_digest":"` + strings.Repeat("44", 32) +
		`","sensor_state":"online","challenge":"deadbeef","signature":"` + signature + `"}`
	f.Add([]byte(seed))
	f.Add([]byte(`{}`))
	f.Add([]byte(seed + `{}`))
	f.Add([]byte(strings.Repeat("a", witnessCheckpointMaxBytes+1)))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > witnessCheckpointMaxBytes+1 {
			t.Skip()
		}
		checkpoint, err := DecodeWitnessCheckpoint(data)
		if err != nil {
			return
		}
		if err := ValidateWitnessCheckpoint(checkpoint); err != nil {
			t.Fatalf("decoder accepted an invalid checkpoint: %v", err)
		}
		if checkpoint.Records != checkpoint.Sequence {
			t.Fatal("decoder accepted records != sequence")
		}
		if checkpoint.Sequence == 0 && checkpoint.HeadHash != "" {
			t.Fatal("decoder accepted a head without records")
		}
		encoded, err := EncodeWitnessCheckpoint(checkpoint)
		if err != nil {
			t.Fatalf("accepted checkpoint does not re-encode: %v", err)
		}
		if len(encoded) > witnessCheckpointMaxBytes {
			t.Fatalf("accepted checkpoint re-encodes oversized: %d", len(encoded))
		}
	})
}

// FuzzWitnessReceiptDecode exercises the POINT 4 receipt decoder. An accepted
// receipt must always carry the canonical id/sequence/timestamp/signature shape
// and bind a 16-byte checkpoint id.
func FuzzWitnessReceiptDecode(f *testing.F) {
	seed := `{"witness_id":"witness-1","witness_seq":7,"checkpoint_id":"` + strings.Repeat("ab", 16) +
		`","accepted_at":"2026-11-15T12:00:00Z","signature":"` + strings.Repeat("A", 86) + `"}`
	f.Add([]byte(seed))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"receipt":` + seed + `}`))
	f.Add([]byte(strings.Repeat("A", witnessReceiptMaxBytes+1)))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > witnessReceiptMaxBytes+1 {
			t.Skip()
		}
		receipt, err := DecodeWitnessReceipt(data)
		if err != nil {
			return
		}
		if err := ValidateWitnessReceipt(receipt); err != nil {
			t.Fatalf("decoder accepted an invalid receipt: %v", err)
		}
		if receipt.WitnessSeq == 0 || receipt.WitnessSeq > witnessCheckpointMaxCounter {
			t.Fatalf("accepted out-of-range witness sequence: %d", receipt.WitnessSeq)
		}
		if len(receipt.CheckpointID) != 2*witnessCheckpointIDBytes {
			t.Fatalf("accepted a foreign checkpoint id: %q", receipt.CheckpointID)
		}
	})
}

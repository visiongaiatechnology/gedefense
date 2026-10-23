// STATUS: DIAMANT VGT SUPREME
package main

import (
	"encoding/base64"
	"testing"
)

func TestMalwareScanResultParserIsTypedAndBounded(t *testing.T) {
	clean, err := parseMalwareScanResult("clean:none:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:68:data")
	if err != nil || clean.State != "clean" || clean.Size != 68 {
		t.Fatalf("valid malware result rejected: %+v err=%v", clean, err)
	}
	for _, invalid := range []string{
		"unknown:none:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:68:data",
		"malicious:unsafe/path:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:68:data",
		"malicious:eicar:00:68:data",
		"malicious:eicar:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:9999999999:data",
	} {
		if _, err := parseMalwareScanResult(invalid); err == nil {
			t.Fatalf("invalid malware result accepted: %q", invalid)
		}
	}
}

func TestCoreMalwareEventParserIsTypedBoundedAndPathSafe(t *testing.T) {
	path := "/home/alice/payload.bin"
	token := base64.RawURLEncoding.EncodeToString([]byte(path))
	digest := "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
	batch, err := parseCoreMalwareEvents("2|4321:1000:" + token + ":malicious:eicar-test-signature:" + digest + ":68:data")
	if err != nil || batch.Dropped != 2 || len(batch.Events) != 1 {
		t.Fatalf("valid malware event batch rejected: %+v err=%v", batch, err)
	}
	event := batch.Events[0]
	if event.PID != 4321 || event.UID != 1000 || event.Path != path || event.State != "malicious" || event.SHA256 != digest {
		t.Fatalf("unexpected malware event: %+v", event)
	}
	for _, invalid := range []string{
		"0|0:1000:" + token + ":malicious:eicar-test-signature:" + digest + ":68:data",
		"0|4321:1000:" + token + ":clean:none:" + digest + ":68:data",
		"0|4321:1000:not-base64:malicious:eicar-test-signature:" + digest + ":68:data",
		"0|4321:1000:" + token + ":malicious:unsafe/reason:" + digest + ":68:data",
		"0|4321:1000:" + token + ":malicious:eicar-test-signature:00:68:data",
		"0|4321:1000:" + token + ":malicious:eicar-test-signature:" + digest + ":268435457:data",
		"bad|",
	} {
		if _, err := parseCoreMalwareEvents(invalid); err == nil {
			t.Fatalf("invalid malware event batch accepted: %q", invalid)
		}
	}
}

// STATUS: DIAMANT VGT SUPREME
package main

import "testing"

func TestParseCoreEgressDropEventsUsesStrictBounds(t *testing.T) {
	valid := "1482:1000:4:6:cb007109:66697265666f78,0:0:6:17:20010db8000000000000000000000001:"
	events, err := parseCoreEgressDropEvents(valid)
	if err != nil {
		t.Fatalf("valid events rejected: %v", err)
	}
	if len(events) != 2 || events[0].PID != 1482 || events[0].UID != 1000 ||
		events[0].Family != 4 || events[0].Protocol != 6 ||
		events[0].Destination.String() != "203.0.113.9" || events[0].Comm != "firefox" ||
		events[1].Destination.String() != "2001:db8::1" {
		t.Fatalf("unexpected decoded events: %#v", events)
	}
	for _, malicious := range []string{
		"1:0:4:6:cb007109",
		"-1:0:4:6:cb007109:61",
		"1:0:5:6:cb007109:61",
		"1:0:4:256:cb007109:61",
		"1:0:4:6:cb0071:61",
		"1:0:6:6:cb007109:61",
		"1:0:4:6:zz:61",
		"1:0:4:6:cb007109:00",
		"1:0:4:6:cb007109:4141414141414141414141414141414141",
	} {
		if _, err := parseCoreEgressDropEvents(malicious); err == nil {
			t.Fatalf("malformed event accepted: %q", malicious)
		}
	}
}

func TestXDRSensorModeReflectsIndependentKernelSensors(t *testing.T) {
	cases := map[string]struct {
		exec    bool
		egress  bool
		malware bool
	}{
		"fanotify-exec+ebpf-exec+cgroup-egress+procfs-fallback": {exec: true, egress: true, malware: true},
		"fanotify-exec+ebpf-exec+procfs-fallback":               {exec: true, egress: false, malware: true},
		"fanotify-exec+cgroup-egress+procfs-bounded-fallback":   {exec: false, egress: true, malware: true},
		"fanotify-exec+procfs-bounded-fallback":                 {exec: false, egress: false, malware: true},
		"malware-events-unavailable+procfs-bounded-fallback":    {exec: false, egress: false, malware: false},
	}
	for want, input := range cases {
		if got := xdrSensorMode(input.exec, input.egress, input.malware, false, false); got != want {
			t.Fatalf("sensor mode mismatch: got=%q want=%q", got, want)
		}
	}
	if got := xdrSensorMode(true, true, true, true, true); got != "fanotify-exec+bpf-lsm-cell+ebpf-exec+cgroup-egress+procfs-fallback" {
		t.Fatalf("Cell BPF-LSM sensor missing from mode: %q", got)
	}
	if got := xdrSensorMode(true, true, true, true, false); got != "fanotify-exec+cell-lsm-unavailable+ebpf-exec+cgroup-egress+procfs-fallback" {
		t.Fatalf("Cell BPF-LSM failure missing from mode: %q", got)
	}
}

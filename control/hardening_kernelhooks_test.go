// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-4 regression tests for the opt-in io_uring/memfd hardening catalogue
// and the documented recommendation schedule. They prove:
//   - the two new controls are opt-in (never part of a shipped default profile),
//   - the io_uring recommendation is 1 and is never 2 (2 breaks databases and
//     storage, so it must never become the default/recommended target),
//   - vm.memfd_noexec recommends the hardened opt-in value 2,
//   - the mask identity space stays compatible: bit 21 remains unassigned so the
//     existing `astraeaos-custom-200000` negative test keeps holding,
//   - the typed preview/apply/verify/reverse transaction path still works for a
//     custom selection of the new controls, including typed rollback,
//   - module.sig_enforce stays a reboot-only informational recommendation and
//     kernel.kexec_load_disabled stays owned by the existing lockdown path (no
//     duplicate live apply).

import (
	"encoding/json"
	"testing"
)

func TestHardeningIoUringAndMemfdCatalogueEntriesAreOptIn(t *testing.T) {
	ioUring, ok := sysctlControlDefinitions["kernel.io-uring"]
	if !ok {
		t.Fatal("the kernel.io-uring control is missing")
	}
	if ioUring.Mask != 1<<22 {
		t.Fatalf("the kernel.io-uring identity mask is %#x, want %#x", ioUring.Mask, uint32(1<<22))
	}
	if ioUring.Values["kernel.io_uring_disabled"] != "1" {
		t.Fatalf("the kernel.io-uring control does not manage kernel.io_uring_disabled=1: %+v", ioUring.Values)
	}
	memfd, ok := sysctlControlDefinitions["vm.memfd-noexec"]
	if !ok {
		t.Fatal("the vm.memfd-noexec control is missing")
	}
	if memfd.Mask != 1<<23 {
		t.Fatalf("the vm.memfd-noexec identity mask is %#x, want %#x", memfd.Mask, uint32(1<<23))
	}
	if memfd.Values["vm.memfd_noexec"] != "2" {
		t.Fatalf("the vm.memfd-noexec control does not manage vm.memfd_noexec=2: %+v", memfd.Values)
	}
	// Both controls stay opt-in: no shipped default profile may reference them.
	defaults := defaultHardeningFabricSettings(Config{}, "").Sysctl
	if len(defaults.Profiles) != 3 {
		t.Fatalf("the shipped profile count changed: %d", len(defaults.Profiles))
	}
	for _, profile := range defaults.Profiles {
		for _, control := range profile.Controls {
			if control == "kernel.io-uring" || control == "vm.memfd-noexec" {
				t.Fatalf("profile %q applies the opt-in control %q implicitly", profile.Name, control)
			}
		}
	}
	// Existing catalogue entries and their identity bits stay untouched.
	for control, want := range map[string]uint32{
		"kernel.aslr":                   1 << 0,
		"kernel.bpf":                    1 << 4,
		"kernel.userns":                 1 << 10,
		"network.ipv6-disable":          1 << 20,
		"network.rp-filter":             1 << 11,
		"filesystem.protected-symlinks": 1 << 15,
	} {
		definition, exists := sysctlControlDefinitions[control]
		if !exists {
			t.Fatalf("existing control %q disappeared", control)
		}
		if definition.Mask != want {
			t.Fatalf("existing control %q mask is %#x, want %#x", control, definition.Mask, want)
		}
	}
	if sysctlControlDefinitions["kernel.aslr"].Values["kernel.randomize_va_space"] != "2" ||
		sysctlControlDefinitions["network.syn-cookies"].Values["net.ipv4.tcp_syncookies"] != "1" {
		t.Fatal("an existing catalogue value changed")
	}
}

func TestHardeningMaskSpaceKeepsTheCompatibilityReservation(t *testing.T) {
	ceiling := sysctlControlMaskCeiling()
	if ceiling != 0x00df_ffff {
		t.Fatalf("control mask ceiling is %#x, want 0x00df_ffff", ceiling)
	}
	if sysctlControlReservedMaskBits != 1<<21 {
		t.Fatalf("the reserved identity bit is %#x, want %#x", sysctlControlReservedMaskBits, uint32(1<<21))
	}
	if sysctlControlReservedMaskBits&ceiling != 0 {
		t.Fatal("the reserved identity bit leaked into the catalogue ceiling")
	}
	// The V6.3.0 custom-profile names must validate, including both new controls.
	for _, state := range []string{
		"astraeaos-custom-400000", // only kernel.io-uring
		"astraeaos-custom-800000", // only vm.memfd-noexec
		"astraeaos-custom-c00000", // both
		"astraeaos-custom-1fffff", // the pre-AP-4 21-bit ceiling
		"astraeaos-custom-dfffff", // the full AP-4 ceiling
	} {
		if !validHardeningState(state) {
			t.Fatalf("catalogue state %q was rejected", state)
		}
	}
	// Unassigned/unknown bits stay rejected: 0x200000 (bit 21, reserved) is the
	// documented negative case of the existing M5.1 test.
	for _, state := range []string{
		"astraeaos-custom-200000",
		"astraeaos-custom-1000000",
		"astraeaos-custom-000000",
	} {
		if validHardeningState(state) {
			t.Fatalf("state %q outside the catalogue was accepted", state)
		}
	}
	// Control identity masks stay unique.
	seen := map[uint32]string{}
	for id, definition := range sysctlControlDefinitions {
		if definition.Mask == 0 {
			t.Fatalf("control %q has a zero identity mask", id)
		}
		if other, duplicate := seen[definition.Mask]; duplicate {
			t.Fatalf("controls %q and %q share mask %#x", id, other, definition.Mask)
		}
		seen[definition.Mask] = id
	}
	if len(sysctlControlDefinitions) != 23 {
		t.Fatalf("catalogue size is %d, want the 21 pre-AP-4 controls plus 2 AP-4 controls",
			len(sysctlControlDefinitions))
	}
}

func TestHardeningRecommendationSchedule(t *testing.T) {
	ioUring, ok := sysctlHardeningRecommendationFor("kernel.io_uring_disabled")
	if !ok {
		t.Fatal("the io_uring recommendation is missing")
	}
	if ioUring.Recommended != "1" {
		t.Fatalf("the io_uring recommendation is %q, want 1", ioUring.Recommended)
	}
	if ioUring.Recommended == "2" {
		t.Fatal("io_uring_disabled=2 must never be the recommendation (it breaks databases/storage)")
	}
	if !ioUring.Managed || !ioUring.OptIn || ioUring.Applies != sysctlAppliesLive {
		t.Fatalf("the io_uring recommendation is not a managed opt-in live control: %+v", ioUring)
	}
	memfd, ok := sysctlHardeningRecommendationFor("vm.memfd_noexec")
	if !ok {
		t.Fatal("the memfd recommendation is missing")
	}
	if memfd.Recommended != "2" || !memfd.Managed || !memfd.OptIn || memfd.Applies != sysctlAppliesLive {
		t.Fatalf("the memfd recommendation is not the hardened opt-in value 2: %+v", memfd)
	}
	// The informational recommendations must never be promoted to a live apply.
	sigEnforce, ok := sysctlHardeningRecommendationFor("module.sig_enforce")
	if !ok {
		t.Fatal("the module.sig_enforce recommendation is missing")
	}
	if sigEnforce.Managed || sigEnforce.Applies != sysctlAppliesReboot || sigEnforce.Recommended != "1" {
		t.Fatalf("module.sig_enforce must stay an unmanaged reboot-time recommendation: %+v", sigEnforce)
	}
	kexec, ok := sysctlHardeningRecommendationFor("kernel.kexec_load_disabled")
	if !ok {
		t.Fatal("the kexec_load_disabled recommendation is missing")
	}
	if kexec.Managed || kexec.Applies != sysctlAppliesLockdown || kexec.Recommended != "1" {
		t.Fatalf("kexec_load_disabled must stay owned by the lockdown path: %+v", kexec)
	}
	// Neither informational key may be reachable through the transaction
	// catalogue (a boot parameter is not writable at runtime, and the lockdown
	// path must not gain a second writer).
	for id, definition := range sysctlControlDefinitions {
		for key := range definition.Values {
			if key == "module.sig_enforce" || key == "kernel.kexec_load_disabled" {
				t.Fatalf("control %q exposes the informational key %q for live apply", id, key)
			}
		}
	}
	// Every managed recommendation must resolve to a real catalogue value pair.
	for _, recommendation := range sysctlHardeningRecommendationCatalogue() {
		if !recommendation.Managed {
			continue
		}
		found := false
		for _, definition := range sysctlControlDefinitions {
			if value, exists := definition.Values[recommendation.Key]; exists &&
				value == recommendation.Recommended {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("managed recommendation %q=%q has no matching catalogue control",
				recommendation.Key, recommendation.Recommended)
		}
	}
	if sysctlHardeningRecommendationCatalogue()[0].AllowedValues == nil {
		t.Fatal("the recommendation catalogue does not publish value domains")
	}
	if _, ok := sysctlHardeningRecommendationFor("kernel.invented"); ok {
		t.Fatal("an unknown recommendation key was accepted")
	}
}

func TestHardeningRecommendationValueDomain(t *testing.T) {
	for _, key := range []string{"kernel.io_uring_disabled", "vm.memfd_noexec"} {
		for _, allowed := range []string{"0", "1", "2"} {
			if !sysctlHardeningValueAllowed(key, allowed) {
				t.Fatalf("%s: value %q was rejected from the documented 0/1/2 domain", key, allowed)
			}
		}
		for _, rejected := range []string{"", "3", "-1", "2 ", "true", "02"} {
			if sysctlHardeningValueAllowed(key, rejected) {
				t.Fatalf("%s: value %q was accepted outside the documented domain", key, rejected)
			}
		}
	}
	if sysctlHardeningValueAllowed("module.sig_enforce", "2") {
		t.Fatal("module.sig_enforce accepted a value outside its 0/1 domain")
	}
	if sysctlHardeningValueAllowed("kernel.invented", "1") {
		t.Fatal("an unknown key has no valid value domain")
	}
}

func TestHardeningIoUringMemfdTypedPreviewApplyVerifyReverse(t *testing.T) {
	core := &memorySysctlCore{values: map[string]string{
		"kernel.io_uring_disabled": "0",
		"vm.memfd_noexec":          "0",
	}, persistent: "absent"}
	applier := NewSysctlTransactionApplier(core)
	plan, before, err := applier.Preview(json.RawMessage(`{"controls":["kernel.io-uring","vm.memfd-noexec"]}`))
	if err != nil {
		t.Fatalf("preview failed: %v", err)
	}
	var planned SysctlProfile
	if err := json.Unmarshal(plan, &planned); err != nil {
		t.Fatalf("plan is not a typed profile: %v", err)
	}
	// 0x400000 | 0x800000 = 0xc00000 -> deterministic custom profile name.
	if planned.Name != "astraeaos-custom-c00000" {
		t.Fatalf("unexpected deterministic profile name: %q", planned.Name)
	}
	if planned.Values["kernel.io_uring_disabled"] != "1" ||
		planned.Values["vm.memfd_noexec"] != "2" {
		t.Fatalf("typed plan carries the wrong values: %+v", planned.Values)
	}
	after, err := applier.Apply(plan, before)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if core.values["kernel.io_uring_disabled"] != "1" || core.values["vm.memfd_noexec"] != "2" {
		t.Fatalf("the opt-in values were not applied: %+v", core.values)
	}
	if core.values["kernel.io_uring_disabled"] == "2" {
		t.Fatal("the transaction engine applied the destructive io_uring value 2")
	}
	if core.persistent != "astraeaos-custom-c00000" {
		t.Fatalf("persistent profile is %q", core.persistent)
	}
	if err := applier.Verify(plan, after); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if err := applier.Reverse(before, after); err != nil {
		t.Fatalf("reverse failed: %v", err)
	}
	if core.values["kernel.io_uring_disabled"] != "0" || core.values["vm.memfd_noexec"] != "0" {
		t.Fatalf("reverse did not restore the previous values: %+v", core.values)
	}
	if core.persistent != "absent" {
		t.Fatalf("persistent profile was not reversed: %q", core.persistent)
	}
}

func TestHardeningIoUringMemfdTypedRollbackOnInjectedFailure(t *testing.T) {
	core := &memorySysctlCore{values: map[string]string{
		"kernel.io_uring_disabled": "0",
		"vm.memfd_noexec":          "0",
	}, persistent: "absent", failKey: "vm.memfd_noexec"}
	applier := NewSysctlTransactionApplier(core)
	plan, before, err := applier.Preview(json.RawMessage(`{"controls":["kernel.io-uring","vm.memfd-noexec"]}`))
	if err != nil {
		t.Fatalf("preview failed: %v", err)
	}
	if _, err := applier.Apply(plan, before); err == nil {
		t.Fatal("apply did not fail on the injected sysctl failure")
	}
	// The first key was applied, so the typed rollback must have restored it.
	if core.values["kernel.io_uring_disabled"] != "0" {
		t.Fatalf("typed rollback did not restore the first key: %+v", core.values)
	}
	if core.persistent != "absent" {
		t.Fatalf("rollback changed the persistent state: %q", core.persistent)
	}
}

func TestHardeningOptInSelectionRemainsTyped(t *testing.T) {
	applier := NewSysctlTransactionApplier(nil)
	profiles, defaultProfile, allowAdHoc := applier.profileSet()
	for _, invalid := range []string{
		`{"controls":["kernel.io-uring","kernel.io-uring"]}`,
		`{"controls":["kernel.io-uring","kernel.invented"]}`,
		`{"controls":[]}`,
		`{"profile":"linux-server-balanced","controls":["kernel.io-uring"]}`,
		`{"controls":["kernel.io-uring"],"unknown":true}`,
		`{"profile":"astraeaos-invented"}`,
	} {
		if _, err := decodeSysctlProfileRequest([]byte(invalid), profiles, defaultProfile, allowAdHoc); err == nil {
			t.Fatalf("invalid opt-in selection accepted: %s", invalid)
		}
	}
	profile, err := decodeSysctlProfileRequest(
		[]byte(`{"controls":["kernel.io-uring"]}`), profiles, defaultProfile, allowAdHoc)
	if err != nil {
		t.Fatalf("valid opt-in selection rejected: %v", err)
	}
	if profile.Name != "astraeaos-custom-400000" ||
		len(profile.Values) != 1 ||
		profile.Values["kernel.io_uring_disabled"] != "1" {
		t.Fatalf("unexpected opt-in profile: %+v", profile)
	}
	// The preference is documented: the io_uring value domain is 0/1/2 but the
	// catalogue always selects 1.
	for _, control := range []string{"kernel.io-uring", "vm.memfd-noexec"} {
		for key, value := range sysctlControlDefinitions[control].Values {
			if !sysctlHardeningValueAllowed(key, value) {
				t.Fatalf("control %q selects a value outside the documented domain: %s=%s", control, key, value)
			}
		}
	}
	if description := sysctlHardeningRecommendationCatalogue(); len(description) != 4 {
		t.Fatalf("recommendation schedule has %d entries, want 4", len(description))
	}
	// The catalogue's opt-in controls are exactly the two managed recommendations.
	for _, control := range []string{"kernel.io-uring", "vm.memfd-noexec"} {
		for key := range sysctlControlDefinitions[control].Values {
			recommendation, ok := sysctlHardeningRecommendationFor(key)
			if !ok || !recommendation.Managed || !recommendation.OptIn {
				t.Fatalf("catalogue key %q is not a documented managed opt-in recommendation", key)
			}
		}
	}
}

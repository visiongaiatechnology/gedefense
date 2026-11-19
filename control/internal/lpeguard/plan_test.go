package lpeguard

import "testing"

// TestSocketDenyFlagWord locks the bit contract from the blueprint: bit 0 stays
// the pre-existing NON_UNIX_SOCKET bit, the new bits are 1<<1..1<<6, and the
// published deny list keeps the documented order.
func TestSocketDenyFlagWord(t *testing.T) {
	t.Parallel()
	if BitAFPacket != 1<<1 || BitAFTIPC != 1<<2 || BitAFVSOCK != 1<<3 || BitSCTP != 1<<4 || BitDCCP != 1<<5 || BitRDS != 1<<6 {
		t.Fatalf("deny bit contract drifted: %08b", DenyMask)
	}
	if DenyMask != 0x7e {
		t.Fatalf("DenyMask = %#x, want 0x7e", DenyMask)
	}
	all, names := Flags(DenySettings{AFPacket: true, AFTIPC: true, AFVSOCK: true, SCTP: true, DCCP: true, RDS: true})
	if all != DenyMask {
		t.Fatalf("all-deny flags = %#x", all)
	}
	want := []string{"AF_PACKET", "SCTP", "DCCP", "RDS", "AF_TIPC", "AF_VSOCK"}
	if len(names) != len(want) {
		t.Fatalf("deny names = %v", names)
	}
	for index := range want {
		if names[index] != want[index] {
			t.Fatalf("deny names[%d] = %q, want %q", index, names[index], want[index])
		}
	}
	none, empty := Flags(DenySettings{})
	if none != 0 || len(empty) != 0 {
		t.Fatalf("empty deny settings produced %#x %v", none, empty)
	}
	if err := ValidateFlags(1 << 7); err == nil {
		t.Fatal("an unknown flag bit was accepted")
	}
	if err := ValidateFlags(DenyMask | BitNonUnixSocket); err != nil {
		t.Fatalf("the documented mask was rejected: %v", err)
	}
}

// TestSocketPolicyPlan rejects the host-wide zero cgroup and deduplicates.
func TestSocketPolicyPlan(t *testing.T) {
	t.Parallel()
	workers := []PolicyWorker{
		{CgroupID: 0, Comm: "root"},
		{CgroupID: 1234, Comm: "nginx", UID: 33},
		{CgroupID: 1234, Comm: "nginx", UID: 33},
		{CgroupID: 5678, Comm: "php-fpm", UID: 33},
	}
	plan := BuildSocketPolicyPlan(workers, DenySettings{AFPacket: true, SCTP: true})
	if len(plan) != 2 {
		t.Fatalf("plan rows = %d, want 2 (%+v)", len(plan), plan)
	}
	for _, row := range plan {
		if row.CgroupID == 0 {
			t.Fatal("a zero cgroup id reached the socket policy plan")
		}
		if row.Applied {
			t.Fatal("a rendered plan claimed to be applied")
		}
		if len(row.Deny) != 2 || row.Deny[0] != "AF_PACKET" || row.Deny[1] != "SCTP" {
			t.Fatalf("row deny list = %v", row.Deny)
		}
	}
}

// TestStyxWebIngressPlan locks the profile composition: loopback always, backend
// CIDRs canonicalized, DNS resolvers carried separately.
func TestStyxWebIngressPlan(t *testing.T) {
	t.Parallel()
	plan := BuildStyxWebIngressPlan(StyxProfileSettings{
		Enabled:      true,
		BackendCIDRs: []string{"10.0.0.0/8", "192.168.1.7/32", "not-a-cidr"},
		DNSServers:   []string{"9.9.9.9", "2620:fe::fe"},
	})
	if plan.Name != StyxProfileName || !plan.Enabled {
		t.Fatalf("plan identity = %+v", plan)
	}
	if len(plan.Allow) != 4 {
		t.Fatalf("allow list = %v", plan.Allow)
	}
	if plan.Allow[0] != "127.0.0.0/8" || plan.Allow[1] != "::1/128" {
		t.Fatalf("loopback allow entries = %v", plan.Allow[:2])
	}
	if len(plan.Backend) != 2 || plan.Backend[0] != "10.0.0.0/8" || plan.Backend[1] != "192.168.1.7/32" {
		t.Fatalf("backend list = %v", plan.Backend)
	}
	if len(plan.DNS) != 2 || plan.DNS[0] != "9.9.9.9/32" {
		t.Fatalf("dns list = %v", plan.DNS)
	}
	disabled := BuildStyxWebIngressPlan(StyxProfileSettings{})
	if disabled.Enabled {
		t.Fatal("a disabled profile rendered as enabled")
	}
	if len(disabled.Allow) != 2 {
		t.Fatalf("disabled plan still renders loopback: %v", disabled.Allow)
	}
}

// TestHardeningBaseline covers ASLR and module states.
func TestHardeningBaseline(t *testing.T) {
	t.Parallel()
	facts := HostFacts{
		ASLR:     "0",
		Modules:  map[string]bool{"sctp": true},
		Modprobe: "blacklist dccp\ninstall dccp /bin/false\n",
	}
	checks := EvaluateHardening(facts, HardeningSettings{EnforceASLR: true, BlockLPEModules: true})
	byKey := make(map[string]HardeningCheck, len(checks))
	for _, check := range checks {
		byKey[check.Key] = check
	}
	aslr, ok := byKey["kernel.randomize_va_space"]
	if !ok || aslr.State != "fail" || !aslr.Enforceable || aslr.Apply == "" {
		t.Fatalf("aslr check = %+v", aslr)
	}
	if sctp := byKey["module.sctp"]; sctp.State != "fail" || sctp.Actual != "loaded" {
		t.Fatalf("loaded sctp check = %+v", sctp)
	}
	if dccp := byKey["module.dccp"]; dccp.State != "pass" || dccp.Actual != "blocked" {
		t.Fatalf("blacklisted dccp check = %+v", dccp)
	}
	rdsCheck, ok := byKey["module.rds"]
	if !ok || rdsCheck.State != "watch" || rdsCheck.Actual != "not-loaded" {
		t.Fatalf("absent rds check = %+v", rdsCheck)
	}
	if !containsString(rdsCheck.Apply, "gedefense-lpe.conf") {
		t.Fatalf("apply plan is not concrete: %q", rdsCheck.Apply)
	}

	// A passing host reports pass and no fail.
	clean := EvaluateHardening(HostFacts{ASLR: "2", Modules: map[string]bool{}, Modprobe: "blacklist sctp\nblacklist dccp\nblacklist rds\n"}, HardeningSettings{EnforceASLR: true, BlockLPEModules: true})
	for _, check := range clean {
		if check.State == "fail" {
			t.Fatalf("clean host failed %s: %+v", check.Key, check)
		}
	}
	// Dropping the enforcement switches must not claim enforceability for ASLR.
	passive := evaluateASLR("0", false)
	if passive.Enforceable || passive.State != "fail" {
		t.Fatalf("passive aslr check = %+v", passive)
	}
}

func containsString(haystack, needle string) bool {
	for index := 0; index+len(needle) <= len(haystack); index++ {
		if haystack[index:index+len(needle)] == needle {
			return true
		}
	}
	return false
}

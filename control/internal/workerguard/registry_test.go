package workerguard

import "testing"

// TestRegistryFingerprintIsStableAndOrderInsensitive proves the engine's
// reconcile tick only resynchronizes while a crash source runs when the
// administrable identity set really changed.
func TestRegistryFingerprintIsStableAndOrderInsensitive(t *testing.T) {
	t.Parallel()
	left := Registry{Comms: []string{"php-fpm", "nginx"}, UIDs: []uint32{34, 33}}
	right := Registry{Comms: []string{"nginx", "php-fpm", "nginx"}, UIDs: []uint32{33, 34, 33}}
	if RegistryFingerprint(left) != RegistryFingerprint(right) {
		t.Fatalf("fingerprint is order/duplicate sensitive: %q vs %q", RegistryFingerprint(left), RegistryFingerprint(right))
	}
	changedComms := Registry{Comms: []string{"nginx"}, UIDs: []uint32{33, 34}}
	changedUIDs := Registry{Comms: []string{"php-fpm", "nginx"}, UIDs: []uint32{33}}
	if RegistryFingerprint(left) == RegistryFingerprint(changedComms) {
		t.Fatal("removing a comm did not change the fingerprint")
	}
	if RegistryFingerprint(left) == RegistryFingerprint(changedUIDs) {
		t.Fatal("removing a uid did not change the fingerprint")
	}
	if RegistryFingerprint(Registry{Comms: []string{"  "}}) != RegistryFingerprint(Registry{}) {
		t.Fatal("blank comm entries changed the fingerprint")
	}
}

// TestRemovedCommsAndUIDs drives the stale-map cleanup: only identities armed
// before and absent now may be deleted from the kernel maps.
func TestRemovedCommsAndUIDs(t *testing.T) {
	t.Parallel()
	previous := Registry{Comms: []string{"nginx", "php-fpm", "apache2"}, UIDs: []uint32{33, 34}}
	next := Registry{Comms: []string{"nginx", "httpd"}, UIDs: []uint32{34}}
	removedComms := RemovedComms(previous, next)
	if len(removedComms) != 2 || removedComms[0] != "php-fpm" || removedComms[1] != "apache2" {
		t.Fatalf("removed comms = %v", removedComms)
	}
	removedUIDs := RemovedUIDs(previous, next)
	if len(removedUIDs) != 1 || removedUIDs[0] != 33 {
		t.Fatalf("removed uids = %v", removedUIDs)
	}
	if got := RemovedComms(Registry{}, next); len(got) != 0 {
		t.Fatalf("empty previous registry removed %v", got)
	}
	if got := RemovedComms(previous, previous); len(got) != 0 {
		t.Fatalf("unchanged registry removed %v", got)
	}
}

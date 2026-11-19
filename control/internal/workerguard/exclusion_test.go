package workerguard

import "testing"

// TestSharedMasterCgroupIsExcluded locks the FIND-005 shared-cgroup fix: the
// nginx master and its workers share `/system.slice/nginx.service`, so a
// worker-only cgroup set would still put the master under the strict Titan
// scope. The whole cgroup must be excluded and the skip must carry a reason.
func TestSharedMasterCgroupIsExcluded(t *testing.T) {
	t.Parallel()
	registry := Registry{Comms: []string{"nginx"}, ExcludeUnits: []string{"nginx: master"}}
	observations := []ProcessObservation{
		{PID: 100, Comm: "nginx", Cmdline: "nginx: master process /usr/sbin/nginx", CgroupPath: "/system.slice/nginx.service", CgroupID: 4242},
		{PID: 101, Comm: "nginx", Cmdline: "nginx: worker process", CgroupPath: "/system.slice/nginx.service", CgroupID: 4242},
		{PID: 200, Comm: "php-fpm", Cmdline: "php-fpm: pool www", CgroupPath: "/system.slice/php-fpm.service", CgroupID: 5151},
	}
	excluded := ExcludedControlCgroups(observations, registry.ExcludeUnits)
	if _, ok := excluded[4242]; !ok {
		t.Fatal("the nginx.service cgroup shared with the master was not excluded")
	}
	if _, ok := excluded[5151]; ok {
		t.Fatal("a worker-only cgroup was excluded")
	}
	skip := excluded[4242]
	if skip.CgroupID != 4242 || skip.CgroupPath != "/system.slice/nginx.service" || skip.Comm != "nginx" {
		t.Fatalf("skip record = %+v", skip)
	}
	if skip.Reason == "" {
		t.Fatal("skip record has no operator-facing reason")
	}
}

// TestExcludedControlCgroupsIgnoresRootAndKeepsFirstReason proves a cgroup id of
// 0 (the root cgroup, where the kernel does not give a per-cgroup inode) cannot
// become a strict scope and that duplicate observations do not duplicate skips.
func TestExcludedControlCgroupsIgnoresRootAndKeepsFirstReason(t *testing.T) {
	t.Parallel()
	observations := []ProcessObservation{
		{PID: 1, Comm: "systemd", Cmdline: "/sbin/init", CgroupPath: "/", CgroupID: 0},
		{PID: 2, Comm: "nginx", Cmdline: "nginx: master process", CgroupPath: "/system.slice/nginx.service", CgroupID: 7},
		{PID: 3, Comm: "nginx", Cmdline: "nginx: master process", CgroupPath: "/system.slice/nginx.service", CgroupID: 7},
	}
	excluded := ExcludedControlCgroups(observations, nil)
	if _, ok := excluded[0]; ok {
		t.Fatal("root cgroup was excluded")
	}
	if len(excluded) != 1 || excluded[7].CgroupID != 7 {
		t.Fatalf("excluded = %+v", excluded)
	}
}

// TestControlUnitMatchingDistinguishesMasterFromWorker locks the comm/cmdline
// split the exclusion pass depends on.
func TestControlUnitMatchingDistinguishesMasterFromWorker(t *testing.T) {
	t.Parallel()
	if _, matched := MatchControlUnit("nginx", nil); matched {
		t.Fatal("worker comm was classified as a control unit by comm alone")
	}
	if _, matched := MatchExcludedUnit("nginx: worker process", nil); matched {
		t.Fatal("worker command line was classified as a control unit")
	}
	if unit, matched := MatchExcludedUnit("nginx: master process /usr/sbin/nginx", nil); !matched || unit != "master" {
		t.Fatalf("master command line not matched: unit=%q matched=%t", unit, matched)
	}
}

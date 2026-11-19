package workerguard

import "strings"

// ProcessObservation is the bounded per-process input of the strict-scope
// exclusion pass: the kernel-reported comm, the full command line and the
// resolved cgroup v2 identity of one live process.
type ProcessObservation struct {
	PID        int
	Comm       string
	Cmdline    string
	CgroupPath string
	CgroupID   uint64
}

// ExcludedControlCgroups returns the cgroup ids that must not enter the strict
// Titan scope because the same cgroup also hosts an excluded master/control
// process.
//
// This is the fix for the shared-cgroup blind spot: systemd puts the nginx
// master and its workers into one `nginx.service` cgroup, so excluding only the
// master PID would still apply the strict exec/mmap scope to the whole cgroup
// and could take the master down with the workers. Every cgroup that hosts a
// control process is therefore excluded and reported with the reason.
func ExcludedControlCgroups(observations []ProcessObservation, exclude []string) map[uint64]SkippedCgroup {
	excluded := make(map[uint64]SkippedCgroup, 8)
	for _, observation := range observations {
		if observation.CgroupID == 0 {
			continue
		}
		if _, matched := observationControlUnit(observation, exclude); !matched {
			continue
		}
		if _, dup := excluded[observation.CgroupID]; dup {
			continue
		}
		comm := strings.TrimSpace(observation.Comm)
		excluded[observation.CgroupID] = SkippedCgroup{
			CgroupID:   observation.CgroupID,
			CgroupPath: observation.CgroupPath,
			Comm:       comm,
			Reason:     "cgroup also hosts an excluded control/master process (" + comm + "); a strict Titan scope would cover the master and could take the service down",
		}
	}
	return excluded
}

// observationControlUnit reports whether one process is an excluded
// master/control unit, by comm first and by full command line second (the
// command line is what distinguishes `nginx: master process` from
// `nginx: worker process`).
func observationControlUnit(observation ProcessObservation, exclude []string) (string, bool) {
	if unit, matched := MatchControlUnit(observation.Comm, exclude); matched {
		return unit, true
	}
	return MatchExcludedUnit(observation.Cmdline, exclude)
}

// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// The module checklist of the startup self-check.
//
// Each entry answers two questions with the platform's own surfaces: does this module do its job,
// and is there a repair that is allowed to happen without an operator? The repairs are the canonical
// actions that already exist elsewhere - the self-check deliberately introduces no second way to
// change the kernel policy, the ledger or the allowlist.
//
// Three entries carry no automatic repair on purpose:
//   - a changed system file (FIM) is a trust decision, not a defect, and accepting a new baseline
//     automatically would turn the integrity check into a rubber stamp,
//   - the case store repairs itself while it loads, and a runtime rewrite of forensic history is
//     not something a background check should decide,
//   - the threat-intel feed re-synchronises on its own schedule; a failure there narrows detection
//     quality and is reported, but it does not stop the kernel from enforcing.
type StartupDeps struct {
	Release   *ReleaseController
	State     *State
	Core      *CoreClient
	Policy    *PolicyStore
	Settings  *SettingsStore
	XDR       *XDREngine
	L7        l7SelfTester
	Interface string
}

// l7SelfTester is the part of the L7 service the self-check needs: the canonical probe that sends one
// request through the real inspection path and reports whether the counter moved. It is an interface
// only so the checklist can be tested without standing up a listener.
type l7SelfTester interface {
	RunSelfTest(context.Context) L7SelfTestResult
}

func newStartupModules(deps StartupDeps) []startupModule {
	modules := make([]startupModule, 0, 10)

	if deps.Core != nil {
		modules = append(modules, startupModule{
			name: "core_ipc", blocking: true, continuous: true,
			description: "kernel core reachable over the authenticated IPC",
			probe: func(ctx context.Context) error {
				if _, err := deps.Core.Ping(); err != nil {
					return fmt.Errorf("%w: %v", errStartupNoCore, err)
				}
				return nil
			},
		})
	}

	if deps.Release != nil {
		modules = append(modules, startupModule{
			name: "kernel_enforcement", blocking: true, continuous: true,
			description: "verified kernel policy retained and confirmed",
			probe: func(ctx context.Context) error {
				status := deps.Release.Status()
				if !status.FailSafeVerified || status.KernelPolicyState != "verified-enforce" {
					return fmt.Errorf("kernel policy state is %q (verified=%t)", status.KernelPolicyState, status.FailSafeVerified)
				}
				return nil
			},
			heal: func(ctx context.Context) error {
				return deps.Release.ReconcileVerifiedPolicy()
			},
		})
	}

	if deps.State != nil && deps.Core != nil && deps.Settings != nil {
		modules = append(modules, startupModule{
			name: "management_allowlist", blocking: true, continuous: true,
			description: "management allowlist synchronised into the kernel",
			probe: func(ctx context.Context) error {
				if !deps.State.Snapshot().AllowlistReady {
					return fmt.Errorf("management allowlist is not synchronised")
				}
				return nil
			},
			heal: func(ctx context.Context) error {
				return syncCoreAllowlist(deps.Core, deps.Settings.Get().ManagementAllowlist)
			},
		})
	}

	if deps.State != nil {
		modules = append(modules, startupModule{
			name: "sensor_coverage", blocking: true, continuous: true,
			description: "mandatory sensors online",
			probe: func(ctx context.Context) error {
				coverage := deps.State.Snapshot().Coverage
				if coverage.OverallStatus == CoverageOnline {
					return nil
				}
				summary := strings.TrimSpace(coverage.Summary)
				if summary == "" {
					summary = "coverage status " + string(coverage.OverallStatus)
				}
				return fmt.Errorf("%s", summary)
			},
			// The traffic-derived sensor is the one that needs a repair. After a restart the L7
			// counter is empty, so the coverage derivation honestly reports "awaiting traffic" and
			// the platform stays paused until somebody happens to send a request through the path -
			// the update that was supposed to protect the host instead leaves it idle. One
			// canonical probe through the real inspection path is that request, and it is the same
			// action the operator triggers from the L7 page.
			heal: func(ctx context.Context) error {
				if deps.L7 == nil {
					return fmt.Errorf("no L7 inspection service is attached")
				}
				probeCtx, cancel := context.WithTimeout(ctx, l7SelfTestTimeout+time.Second)
				defer cancel()
				result := deps.L7.RunSelfTest(probeCtx)
				if result.Outcome != L7SelfTestPass {
					return fmt.Errorf("L7 self-test outcome %s: %s", result.Outcome, boundedSummary(result.Detail))
				}
				return nil
			},
		})
	}

	if deps.Policy != nil {
		modules = append(modules, startupModule{
			name: "signed_policy", blocking: true, continuous: true,
			description: "signed policy verified against the pinned key",
			probe: func(ctx context.Context) error {
				if !deps.Policy.Status().Verified {
					return fmt.Errorf("signed policy is not verified")
				}
				return nil
			},
			heal: func(ctx context.Context) error {
				_, err := deps.Policy.Load()
				return err
			},
		})
	}

	if deps.State != nil {
		modules = append(modules, startupModule{
			name: "evidence_ledger", blocking: true,
			description: "mandatory evidence ledger healthy and inside its budget",
			probe: func(ctx context.Context) error {
				ledger := deps.State.EvidenceLedger()
				if ledger == nil {
					return nil
				}
				if !deps.State.Snapshot().Evidence.Enabled {
					return nil
				}
				return ledger.Healthy()
			},
			heal: func(ctx context.Context) error {
				ledger := deps.State.EvidenceLedger()
				if ledger == nil {
					return nil
				}
				size, budget := ledger.Status().StoredBytes, ledger.Status().MaxBytes
				if budget > 0 && size*100 >= budget*evidenceRotationThresholdPercent {
					_, err := ledger.Rotate(ctx, "startup self-check sealed the segment at its retention budget")
					return err
				}
				return ledger.VerifyIncremental()
			},
		})
	}

	if deps.XDR != nil {
		modules = append(modules, startupModule{
			name: "incident_log", blocking: true,
			description: "forensic incident ledger usable",
			probe: func(ctx context.Context) error {
				_, err := deps.XDR.VerifyIncidentIntegrity(ctx)
				return err
			},
			heal: func(ctx context.Context) error {
				_, err := deps.XDR.RecoverIncidentLedger(ctx, "startup self-check sealed the incident segment")
				return err
			},
		})
	}

	if deps.State != nil {
		modules = append(modules, startupModule{
			name: "host_keyring", blocking: false, continuous: true,
			description: "forensic case history readable",
			probe: func(ctx context.Context) error {
				status := deps.State.Snapshot().Cases
				if status.Healthy {
					return nil
				}
				if status.Error != "" {
					return fmt.Errorf("%s", status.Error)
				}
				return fmt.Errorf("case history is not healthy")
			},
		})
		modules = append(modules, startupModule{
			name: "system_integrity", blocking: false, continuous: true,
			description: "monitored system files match the approved baseline",
			probe: func(ctx context.Context) error {
				fim := deps.State.Snapshot().FIM
				if !fim.Enabled || strings.EqualFold(strings.TrimSpace(fim.Health), "verified") {
					return nil
				}
				return fmt.Errorf("FIM reports %s; accepting a new baseline is an operator decision", fim.Health)
			},
		})
		modules = append(modules, startupModule{
			name: "threat_intel", blocking: false, continuous: true,
			description: "threat-intelligence feed current",
			probe: func(ctx context.Context) error {
				status := strings.TrimSpace(deps.State.Snapshot().FeedStatus)
				if status == "" || strings.EqualFold(status, "ok") {
					return nil
				}
				return fmt.Errorf("feed status %s", status)
			},
		})
	}

	return modules
}

// newStartupIdentity describes the host this platform was qualified on, and the release it was
// qualified with. A change in the host part means the platform is protecting something it has not been
// qualified against, and that is what the visible canary ladder is for. A change in the release part
// is an update on a host that already passed - it is re-verified by the self-check, not re-soaked.
func newStartupIdentity(state *State, iface string) func(context.Context) (startupIdentity, error) {
	return func(ctx context.Context) (startupIdentity, error) {
		kernel := "unknown"
		if raw, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
			kernel = strings.TrimSpace(string(raw))
		}
		node := ""
		if state != nil {
			node = state.Snapshot().NodeName
		}
		return startupIdentity{
			Host: strings.Join([]string{
				"kernel=" + kernel,
				"node=" + node,
				"interface=" + iface,
			}, "; "),
			Release: version,
		}, nil
	}
}

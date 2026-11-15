// STATUS: DIAMANT VGT SUPREME
package main

// POINT 1 / P1-T2 tests: the pure Titan exec-gate plan compiler. The walk rules
// (symlink/hardlink/non-executable), the documented evidence ladder, the caps, the
// strict lockout refusal and the deterministic fingerprint are pinned here.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func titanExecPlanWrite(t *testing.T, path string, mode os.FileMode, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func titanExecPlanSettings(roots ...string) TitanExecFabricSettings {
	return TitanExecFabricSettings{
		Enabled: true, Mode: TitanExecModeObserve, ExecRoots: roots,
		MaxEntries: 64, MaxScopes: 16,
	}
}

func titanExecPlanPackages(owned ...string) titanExecPlanDeps {
	packages := newFakeTitanPackages()
	for _, path := range owned {
		packages.own(path, "dpkg", "coreutils")
	}
	return titanExecPlanDeps{Packages: packages}
}

func TestTitanExecPlanWalksRootsWithBoundedRules(t *testing.T) {
	root := t.TempDir()
	tool := filepath.Join(root, "bin", "tool")
	titanExecPlanWrite(t, tool, 0o755, "#!/bin/sh\necho tool\n")
	nonExecutable := filepath.Join(root, "bin", "notes.txt")
	titanExecPlanWrite(t, nonExecutable, 0o644, "not executable")
	link := filepath.Join(root, "bin", "tool-link")
	if err := os.Symlink(tool, link); err != nil {
		t.Fatal(err)
	}
	plan, err := compileTitanExecPolicyPlan(context.Background(), titanExecPlanSettings(root), titanExecPlanPackages(tool))
	if err != nil {
		t.Fatalf("plan compile failed: %v", err)
	}
	if len(plan.Entries) != 1 || plan.Entries[0].Path != tool {
		t.Fatalf("walk did not resolve exactly the executable regular file: %+v", plan.Entries)
	}
	if plan.Entries[0].Action != titanExecActionAllow || plan.Entries[0].ObservedIno == 0 || plan.Entries[0].ObservedDev == 0 {
		t.Fatalf("entry shape is wrong: %+v", plan.Entries[0])
	}
	if plan.Rejected != 2 || plan.Unverified != 0 {
		t.Fatalf("rejected/unverified counters are wrong: rejected=%d unverified=%d", plan.Rejected, plan.Unverified)
	}
	if plan.WalkVisited < 3 {
		t.Fatalf("walk did not visit the files: %d", plan.WalkVisited)
	}
}

func TestTitanExecPlanDedupesHardLinksByInode(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "a-tool")
	titanExecPlanWrite(t, first, 0o755, "#!/bin/sh\n")
	second := filepath.Join(root, "b-tool")
	if err := os.Link(first, second); err != nil {
		t.Fatal(err)
	}
	plan, err := compileTitanExecPolicyPlan(context.Background(), titanExecPlanSettings(root), titanExecPlanPackages(first))
	if err != nil {
		t.Fatalf("plan compile failed: %v", err)
	}
	if len(plan.Entries) != 1 {
		t.Fatalf("hard links produced %d entries, want one per kernel inode: %+v", len(plan.Entries), plan.Entries)
	}
	// Evidence may be recorded under either hard link; the kernel policy is per inode.
	if plan.Entries[0].Path != first && plan.Entries[0].Path != second {
		t.Fatalf("hard link entry path is wrong: %+v", plan.Entries[0])
	}
	if plan.Entries[0].ObservedIno == 0 || plan.Unverified != 0 {
		t.Fatalf("hard link evidence was lost: %+v", plan)
	}
}

func TestTitanExecPlanRequiresDocumentedEvidence(t *testing.T) {
	root := t.TempDir()
	tool := filepath.Join(root, "bin", "tool")
	titanExecPlanWrite(t, tool, 0o755, "#!/bin/sh\necho evidence\n")

	// No verifier at all is missing evidence, never implicit trust.
	unverified, err := compileTitanExecPolicyPlan(context.Background(), titanExecPlanSettings(root), titanExecPlanDeps{})
	if err != nil {
		t.Fatalf("plan compile failed: %v", err)
	}
	if len(unverified.Entries) != 0 || unverified.Unverified != 1 {
		t.Fatalf("a file without evidence became an allowlist entry: %+v", unverified)
	}

	// A matching FIM baseline digest is evidence.
	fim := newFakeTitanFIM()
	fim.set(tool, "#!/bin/sh\necho evidence\n")
	backed, err := compileTitanExecPolicyPlan(context.Background(), titanExecPlanSettings(root), titanExecPlanDeps{FIM: fim})
	if err != nil {
		t.Fatalf("FIM evidence compile failed: %v", err)
	}
	if len(backed.Entries) != 1 || backed.Unverified != 0 {
		t.Fatalf("a verified FIM baseline was not accepted: %+v", backed)
	}

	// A changed file no longer matches the baseline.
	titanExecPlanWrite(t, tool, 0o755, "#!/bin/sh\necho tampered\n")
	mismatched, err := compileTitanExecPolicyPlan(context.Background(), titanExecPlanSettings(root), titanExecPlanDeps{FIM: fim})
	if err != nil {
		t.Fatalf("mismatched FIM compile failed: %v", err)
	}
	if len(mismatched.Entries) != 0 || mismatched.Unverified != 1 {
		t.Fatalf("a modified file kept its baseline authorization: %+v", mismatched)
	}

	// An unavailable package database lowers trust.
	broken := newFakeTitanPackages()
	broken.err = errors.New("package database unavailable")
	bundled, err := compileTitanExecPolicyPlan(context.Background(), titanExecPlanSettings(root), titanExecPlanDeps{Packages: broken})
	if err != nil {
		t.Fatalf("unavailable package evidence must not fail the plan: %v", err)
	}
	if len(bundled.Entries) != 0 || bundled.Unverified != 1 {
		t.Fatalf("unavailable package evidence raised trust: %+v", bundled)
	}
}

func TestTitanExecPlanExplicitAllowPathsSkipEvidence(t *testing.T) {
	root := t.TempDir()
	explicitFile := filepath.Join(root, "helpers", "explicit-tool")
	titanExecPlanWrite(t, explicitFile, 0o755, "#!/bin/sh\n")
	tree := filepath.Join(root, "tree")
	treeTool := filepath.Join(tree, "sub", "tree-tool")
	titanExecPlanWrite(t, treeTool, 0o755, "#!/bin/sh\n")
	titanExecPlanWrite(t, filepath.Join(tree, "sub", "readme"), 0o644, "text")
	settings := TitanExecFabricSettings{
		Enabled: true, Mode: TitanExecModeObserve,
		AllowPaths: []string{tree, explicitFile},
		MaxEntries: 32, MaxScopes: 8,
	}
	plan, err := compileTitanExecPolicyPlan(context.Background(), settings, titanExecPlanDeps{})
	if err != nil {
		t.Fatalf("explicit allow path compile failed: %v", err)
	}
	if len(plan.Entries) != 2 || plan.Unverified != 0 {
		t.Fatalf("explicit allow paths were not trusted: %+v", plan)
	}
	paths := map[string]bool{plan.Entries[0].Path: true, plan.Entries[1].Path: true}
	if !paths[explicitFile] || !paths[treeTool] {
		t.Fatalf("explicit allow path entries are wrong: %+v", plan.Entries)
	}

	// An explicitly named non-executable file is refused instead of silently ignored.
	nonExecutable := filepath.Join(root, "helpers", "data.txt")
	titanExecPlanWrite(t, nonExecutable, 0o644, "data")
	settings.AllowPaths = []string{nonExecutable}
	if _, err := compileTitanExecPolicyPlan(context.Background(), settings, titanExecPlanDeps{}); err == nil {
		t.Fatal("an explicit non-executable allow path was accepted")
	}
}

func TestTitanExecPlanRejectsSymlinkedConfiguredPaths(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real-bin")
	titanExecPlanWrite(t, filepath.Join(target, "tool"), 0o755, "#!/bin/sh\n")
	link := filepath.Join(root, "linked-bin")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	settings := titanExecPlanSettings(link)
	if _, err := compileTitanExecPolicyPlan(context.Background(), settings, titanExecPlanDeps{}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a symlinked exec root was not refused visibly: %v", err)
	}
	fileLink := filepath.Join(root, "tool-link")
	if err := os.Symlink(filepath.Join(target, "tool"), fileLink); err != nil {
		t.Fatal(err)
	}
	settings = TitanExecFabricSettings{Enabled: true, Mode: TitanExecModeObserve, AllowPaths: []string{fileLink}, MaxEntries: 8, MaxScopes: 8}
	if _, err := compileTitanExecPolicyPlan(context.Background(), settings, titanExecPlanDeps{}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a symlinked allow path was not refused visibly: %v", err)
	}
}

// STRICT denies everything that is not allowlisted, so an incomplete plan must be a
// plan error instead of a system lockout (§8).
func TestTitanExecPlanRefusesIncompleteStrictPolicy(t *testing.T) {
	root := t.TempDir()
	unverifiedTool := filepath.Join(root, "bin", "unverified")
	titanExecPlanWrite(t, unverifiedTool, 0o755, "#!/bin/sh\n")
	strict := titanExecPlanSettings(root)
	strict.Mode = TitanExecModeStrict
	if _, err := compileTitanExecPolicyPlan(context.Background(), strict, titanExecPlanDeps{}); err == nil || !strings.Contains(err.Error(), "without package/FIM evidence") {
		t.Fatalf("strict plan with unverified candidates was accepted: %v", err)
	}
	empty := filepath.Join(root, "empty")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	strict = titanExecPlanSettings(empty)
	strict.Mode = TitanExecModeStrict
	if _, err := compileTitanExecPolicyPlan(context.Background(), strict, titanExecPlanDeps{}); err == nil || !strings.Contains(err.Error(), "deny every exec") {
		t.Fatalf("empty strict plan was accepted: %v", err)
	}
	// The same tree is a valid observe plan: no lockout risk without strict.
	observe := titanExecPlanSettings(empty)
	if _, err := compileTitanExecPolicyPlan(context.Background(), observe, titanExecPlanDeps{}); err != nil {
		t.Fatalf("empty observe plan was rejected: %v", err)
	}
}

func TestTitanExecPlanEnforcesEntryCap(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "a-tool")
	second := filepath.Join(root, "b-tool")
	titanExecPlanWrite(t, first, 0o755, "#!/bin/sh\n")
	titanExecPlanWrite(t, second, 0o755, "#!/bin/sh\n")
	settings := titanExecPlanSettings(root)
	settings.MaxEntries = 1
	if _, err := compileTitanExecPolicyPlan(context.Background(), settings, titanExecPlanPackages(first, second)); err == nil || !strings.Contains(err.Error(), "max_entries") {
		t.Fatalf("entry cap was not enforced: %v", err)
	}
}

func TestTitanExecPlanDevRootsNeverBecomeKernelAllowances(t *testing.T) {
	root := t.TempDir()
	production := filepath.Join(root, "prod", "server")
	development := filepath.Join(root, "dev", "hot-reload")
	titanExecPlanWrite(t, production, 0o755, "#!/bin/sh\n")
	titanExecPlanWrite(t, development, 0o755, "#!/bin/sh\n")
	settings := titanExecPlanSettings(filepath.Join(root, "prod"))
	settings.DevRoots = []string{filepath.Join(root, "dev")}
	plan, err := compileTitanExecPolicyPlan(context.Background(), settings, titanExecPlanPackages(production, development))
	if err != nil {
		t.Fatalf("plan compile failed: %v", err)
	}
	if len(plan.Entries) != 1 || plan.Entries[0].Path != production {
		t.Fatalf("development roots flowed into the kernel allowlist: %+v", plan.Entries)
	}
}

func TestTitanExecPlanIsDeterministicAndReactsToIdentityChanges(t *testing.T) {
	root := t.TempDir()
	tool := filepath.Join(root, "bin", "tool")
	titanExecPlanWrite(t, tool, 0o755, "#!/bin/sh\nv1\n")
	settings := titanExecPlanSettings(root)
	deps := titanExecPlanPackages(tool)
	first, err := compileTitanExecPolicyPlan(context.Background(), settings, deps)
	if err != nil {
		t.Fatal(err)
	}
	second, err := compileTitanExecPolicyPlan(context.Background(), settings, deps)
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint == "" || first.Fingerprint != second.Fingerprint {
		t.Fatalf("identical plans do not share a fingerprint: %q != %q", first.Fingerprint, second.Fingerprint)
	}
	// A replaced binary at the same path must re-sync even though the path string is
	// unchanged, because the kernel policy is bound to the inode identity.
	titanExecPlanWrite(t, tool, 0o755, "#!/bin/sh\nv2\n")
	third, err := compileTitanExecPolicyPlan(context.Background(), settings, deps)
	if err != nil {
		t.Fatal(err)
	}
	if third.Fingerprint == first.Fingerprint {
		t.Fatal("a changed file identity kept the old plan fingerprint")
	}
	strict := settings
	strict.Mode = TitanExecModeStrict
	fourth, err := compileTitanExecPolicyPlan(context.Background(), strict, deps)
	if err != nil {
		t.Fatal(err)
	}
	if fourth.Fingerprint == third.Fingerprint {
		t.Fatal("a different mode kept the same plan fingerprint")
	}
	disabled := settings
	disabled.Enabled = false
	offPlan, err := compileTitanExecPolicyPlan(context.Background(), disabled, deps)
	if err != nil {
		t.Fatal(err)
	}
	if offPlan.Enabled || offPlan.Mode != 0 || len(offPlan.Entries) != 0 || len(offPlan.Scopes) != 0 {
		t.Fatalf("disabled plan still asks for kernel state: %+v", offPlan)
	}
}

func TestTitanExecPlanScopesMergeJitAndStrictCgroups(t *testing.T) {
	settings := TitanExecFabricSettings{
		Enabled: true, Mode: TitanExecModeObserve,
		JitCgroups: []uint64{11, 7}, StrictCgroups: []uint64{9, 7},
		MaxEntries: 16, MaxScopes: 8,
	}
	plan, err := compileTitanExecPolicyPlan(context.Background(), settings, titanExecPlanDeps{})
	if err != nil {
		t.Fatalf("scope compile failed: %v", err)
	}
	if len(plan.Scopes) != 3 {
		t.Fatalf("scope merge produced %d scopes: %+v", len(plan.Scopes), plan.Scopes)
	}
	byCgroup := map[uint64]titanExecPlanScope{}
	for _, scope := range plan.Scopes {
		byCgroup[scope.CgroupID] = scope
	}
	if got := byCgroup[7]; got.Mode != 3 || got.Flags != titanExecScopeFlagJitAllow {
		t.Fatalf("combined JIT+strict scope is wrong: %+v", got)
	}
	if got := byCgroup[9]; got.Mode != 3 || got.Flags != 0 {
		t.Fatalf("strict scope is wrong: %+v", got)
	}
	if got := byCgroup[11]; got.Mode != 1 || got.Flags != titanExecScopeFlagJitAllow {
		t.Fatalf("JIT-only scope must keep the global mode: %+v", got)
	}
}

func TestTitanExecPlanHonoursCancellation(t *testing.T) {
	root := t.TempDir()
	titanExecPlanWrite(t, filepath.Join(root, "tool"), 0o755, "#!/bin/sh\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := compileTitanExecPolicyPlan(ctx, titanExecPlanSettings(root), titanExecPlanPackages()); err == nil {
		t.Fatal("a cancelled plan compile still returned a plan")
	}
}

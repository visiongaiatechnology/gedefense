// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const version = "6.3.0"

func detectInterface(requested string) (string, error) {
	if requested != "" && requested != "auto" {
		if _, err := net.InterfaceByName(requested); err != nil {
			return "", err
		}
		return requested, nil
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	var downCandidate string
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		if i.Flags&net.FlagUp != 0 {
			return i.Name, nil
		}
		if downCandidate == "" {
			// Prefer a real NIC even if link is not up yet (common on live boot
			// before NetworkManager finishes). The control plane can still serve
			// the local dashboard; the Rust core resolves the data plane itself.
			downCandidate = i.Name
		}
	}
	if downCandidate != "" {
		return downCandidate, nil
	}
	// Last resort: allow local HTTPS dashboard bring-up without a NIC.
	return "lo", nil
}

type policyPersistence interface {
	Persist(nodeName, enforcement, xdrMode string, blocks []BlockEntry) error
	Status() PolicyStatus
}

// errPolicyUnverified is returned by every automatic writer of the signed policy when the
// current document could not be verified. An unverified document is forensic evidence, not
// the current intent: persisting on top of it would overwrite the evidence and put a fresh
// signature on a state nobody verified (FIND-013 / VGT-AUDIT-20261114-GD51). Only an explicit
// operator action - the RETURN:OBSERVE transition, which calls PolicyStore.Persist directly -
// may re-establish a signed policy.
var errPolicyUnverified = errors.New("signed policy is not verified; refusing to persist and re-sign an unverified policy document - explicit operator recovery (RETURN:OBSERVE) required")

func persistPolicy(policy policyPersistence, cfg Config, state *State) error {
	if policy == nil {
		return nil
	}
	if status := policy.Status(); !status.Verified {
		// This funnel serves the automatic writers (block expiry, automatic containment) and
		// the operator block/allowlist mutations. None of them may silently re-sign a document
		// the platform could not verify; the failure is fail-closed and reported once per
		// refusing path so it cannot look like a successful write.
		if state != nil {
			state.AddEvent(Event{
				Severity: "critical", Kind: "policy.persist_refused", Source: "policy",
				Message: "Refused to persist the signed policy: the current document is not verified and must not be re-signed automatically; explicit operator recovery (RETURN:OBSERVE) required",
			})
		}
		return errPolicyUnverified
	}
	enforcement, xdrMode := state.Modes()
	if err := policy.Persist(cfg.Node.Name, enforcement, xdrMode, state.BlocksSnapshot()); err != nil {
		state.SetPolicyStatus(policy.Status())
		return err
	}
	state.SetPolicyStatus(policy.Status())
	return nil
}

func main() {
	configPath := flag.String("config", "./gedefense.toml", "configuration file")
	chameleonManifest := flag.String("chameleon-manifest", "", "opt-in GeDefense Chameleon install manifest (default: public identity)")
	check := flag.Bool("check-config", false, "validate configuration and exit")
	preflight := flag.Bool("preflight", false, "run service-start preflight and exit")
	activationPreflight := flag.Bool("preflight-activation", false, "run strict beta activation preflight and exit")
	showVersion := flag.Bool("version", false, "print version")
	verifyForensics := flag.String("verify-forensics", "", "verify a signed forensics export")
	trustedPublicKey := flag.String("public-key", "", "trusted Ed25519 public key for offline verification")
	scanFile := flag.String("scan-file", "", "scan one absolute file through the privileged malware core")
	userScanFile := flag.String("user-scan-file", "", "scan one browser-quarantine file through the peer-bound malware socket")
	probeURL := flag.String("probe-ready", "", "wait for a loopback /readyz endpoint")
	probeLiveURL := flag.String("probe-live", "", "wait for a loopback /livez endpoint")
	probeTimeout := flag.Duration("probe-timeout", 30*time.Second, "maximum readiness probe duration")
	signReleaseDir := flag.String("sign-release-dir", "", "sign all production artifacts in a directory")
	releaseManifestOutput := flag.String("release-manifest-output", "", "output path for the signed release manifest")
	verifyReleaseManifest := flag.String("verify-release-manifest", "", "verify a signed release manifest")
	releaseArtifactDir := flag.String("release-artifact-dir", "", "artifact directory used during release manifest verification")
	releasePrivateKey := flag.String("release-private-key", "", "offline Ed25519 release private key")
	releasePublicKey := flag.String("release-public-key", "", "trusted Ed25519 release public key")
	initFeedSigning := flag.String("init-feed-signing", "", "generate the local feed-signing Ed25519 key pair in this directory and print the pinned public key")
	feedPublicKeyOut := flag.String("feed-public-key", "", "optional output path for the generated feed-signing public key")
	captureHelper := flag.Bool("capture-helper", false, "run the isolated read-only AF_PACKET / CN_PROC capture helper")
	captureHelperSocket := flag.String("capture-helper-socket", defaultCaptureHelperSocket, "Unix socket path for the isolated capture helper")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *captureHelper {
		if err := runCaptureHelper(*captureHelperSocket); err != nil {
			log.Fatalf("capture helper: %v", err)
		}
		return
	}
	if *signReleaseDir != "" {
		if *releaseManifestOutput == "" || *releasePrivateKey == "" || *releasePublicKey == "" {
			log.Fatal("release signing requires --release-manifest-output, --release-private-key, and --release-public-key")
		}
		if err := SignReleaseDirectory(*signReleaseDir, *releasePrivateKey, *releasePublicKey, *releaseManifestOutput); err != nil {
			log.Fatalf("release signing: %v", err)
		}
		fmt.Println("release manifest signed")
		return
	}
	if *verifyReleaseManifest != "" {
		if *releasePublicKey == "" {
			log.Fatal("--release-public-key is required for release verification")
		}
		document, err := VerifyReleaseManifest(*verifyReleaseManifest, *releasePublicKey, *releaseArtifactDir)
		if err != nil {
			log.Fatalf("release verification: %v", err)
		}
		fmt.Printf("release manifest valid; signer=%s version=%s artifacts=%d\n", document.Signer, document.Envelope.Version, len(document.Envelope.Artifacts))
		return
	}
	if *feedPublicKeyOut != "" && *initFeedSigning == "" {
		log.Fatal("--feed-public-key requires --init-feed-signing")
	}
	if *initFeedSigning != "" {
		publicKey, err := InitFeedSigning(*initFeedSigning, *feedPublicKeyOut)
		if err != nil {
			log.Fatalf("feed signing init: %v", err)
		}
		fmt.Printf("feed signing key pair created in %s\n", *initFeedSigning)
		fmt.Printf("feeds.trusted_signing_keys = \"%s\"\n", feedSigningPublicKeyBase64(publicKey))
		fmt.Printf("key fingerprint: %s\n", feedSigningFingerprint(publicKey))
		return
	}
	if *probeURL != "" {
		if *probeTimeout < time.Second || *probeTimeout > 5*time.Minute {
			log.Fatal("--probe-timeout must be between 1s and 5m")
		}
		if err := probeReady(*probeURL, *probeTimeout); err != nil {
			log.Fatal(err)
		}
		fmt.Println("readiness probe passed")
		return
	}
	if *probeLiveURL != "" {
		if *probeTimeout < time.Second || *probeTimeout > 5*time.Minute {
			log.Fatal("--probe-timeout must be between 1s and 5m")
		}
		if err := probeLive(*probeLiveURL, *probeTimeout); err != nil {
			log.Fatal(err)
		}
		fmt.Println("liveness probe passed")
		return
	}
	if *verifyForensics != "" {
		if *trustedPublicKey == "" {
			log.Fatal("--public-key is required with --verify-forensics")
		}
		document, verifyErr := VerifyForensicsFile(*verifyForensics, *trustedPublicKey)
		if verifyErr != nil {
			log.Fatalf("forensics verification: %v", verifyErr)
		}
		fmt.Printf("forensics signature valid; signer=%s node=%s exported_at=%s incidents=%d\n", document.Signer, document.Envelope.NodeName, document.Envelope.ExportedAt.Format(time.RFC3339), len(document.Envelope.Incidents))
		return
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("configuration: %v", err)
	}
	// V6.3.0 AP-8: opt-in Chameleon install profile. Empty path = documented
	// default public identity; a present-but-invalid manifest is fatal so an
	// operator who opted in never silently gets the public identity. The
	// installer-provided environment variable is only a discovery fallback for
	// the packaged control unit (the manifest itself stays a root-owned file).
	chameleonManifestPath := *chameleonManifest
	if chameleonManifestPath == "" {
		chameleonManifestPath = os.Getenv(chameleonManifestEnvVar)
	}
	chameleon, err := NewChameleonProfile(chameleonManifestPath)
	if err != nil {
		log.Fatalf("chameleon profile: %v", err)
	}
	if chameleon.Active() {
		installChameleonProfile(chameleon)
		cfg = chameleon.Apply(cfg)
	}
	if *userScanFile != "" {
		result, scanErr := chameleonUserMalwareScan(*userScanFile, 30*time.Second)
		if scanErr != nil {
			log.Fatalf("user malware scan: %v", scanErr)
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetEscapeHTML(true)
		if encodeErr := encoder.Encode(result); encodeErr != nil {
			log.Fatalf("malware result encoding: %v", encodeErr)
		}
		if result.State != "clean" {
			os.Exit(2)
		}
		return
	}
	if *scanFile != "" {
		if os.Geteuid() != 0 {
			log.Fatal("--scan-file requires administrative execution")
		}
		core, coreErr := NewCoreClient(cfg.Core.Socket, cfg.Core.AuthKeyFile, time.Duration(cfg.Core.RequestTimeoutMillis)*time.Millisecond)
		if coreErr != nil {
			log.Fatalf("core client: %v", coreErr)
		}
		result, scanErr := core.MalwareScan(*scanFile)
		if scanErr != nil {
			log.Fatalf("malware scan: %v", scanErr)
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetEscapeHTML(true)
		if encodeErr := encoder.Encode(result); encodeErr != nil {
			log.Fatalf("malware result encoding: %v", encodeErr)
		}
		if result.State != "clean" {
			os.Exit(2)
		}
		return
	}
	iface, err := detectInterface(cfg.Node.Interface)
	if err != nil {
		log.Fatalf("interface: %v", err)
	}
	cfg.Node.Interface = iface
	if *check {
		fmt.Printf("configuration valid; interface=%s listen=%s enforcement=%s xdr=%s\n", iface, cfg.Dashboard.Listen, cfg.Defense.Enforcement, cfg.XDR.Mode)
		return
	}
	if *preflight || *activationPreflight {
		report := runPreflight(cfg, *configPath, *activationPreflight)
		if err := writePreflightJSON(report); err != nil {
			log.Fatalf("preflight output: %v", err)
		}
		if !report.Passed {
			os.Exit(1)
		}
		return
	}

	// A second control-plane process must not open the revision-bound stores on the same
	// state directory in parallel (G-STATE-08). The lock is held for the process lifetime.
	instanceLock, err := acquireInstanceLock(cfg.Policy.StateFile)
	if err != nil {
		log.Fatalf("control-plane instance lock: %v", err)
	}
	defer func() {
		if releaseErr := instanceLock.Release(); releaseErr != nil {
			log.Printf("control-plane instance lock release: %v", releaseErr)
		}
	}()
	cp := &controlPlane{iface: iface}
	wireControlPlane(cp, cfg, *configPath, chameleon)
	defer cp.cancelCells()
	cp.startRuntime()
	defer cp.cancelXDR()

	cfg = cp.cfg
	cancelXDR := cp.cancelXDR
	srv := cp.srv
	release := cp.release
	state := cp.state
	core := cp.core
	policy := cp.policy
	settings := cp.settings
	xdr := cp.xdr
	titanEngine := cp.titanEngine
	kernelExposure := cp.kernelExposure
	l7Service := cp.l7Service
	l7EdgeService := cp.l7EdgeService
	stopWorkers := cp.stopWorkers
	stopTelemetry := cp.stopTelemetry

	errCh := make(chan error, 1)
	readyCh := make(chan struct{})
	go func() {
		log.Printf("GeDefense %s dashboard: %s (interface=%s gated_phase=observe)", version, cfg.Dashboard.Listen, iface)
		errCh <- srv.RunWithReady(readyCh)
	}()
	select {
	case <-readyCh:
		_ = sdNotify("READY=1\nSTATUS=GeDefense beta observe gate online")
	case e := <-errCh:
		log.Fatalf("server startup: %v", e)
	}
	watchdogCtx, cancelWatchdog := context.WithCancel(context.Background())
	defer cancelWatchdog()
	// The desktop indicator socket is not a protection component: if it cannot be served, the
	// platform keeps protecting and the journal names the reason. It is started after the API is
	// ready so the first telegram already describes a fully populated state.
	desktopCtx, cancelDesktop := context.WithCancel(context.Background())
	defer cancelDesktop()
	desktopStatus := NewDesktopStatusServer(cfg.Desktop, state)
	go func() {
		if desktopErr := desktopStatus.Start(desktopCtx); desktopErr != nil {
			log.Printf("desktop status socket unavailable: %v", desktopErr)
		}
	}()
	// The startup self-check. It verifies the modules that carry the protection, repairs the ones
	// with a canonical repair, and re-arms without the operator when the host is the one that was
	// qualified - so a restart no longer means five minutes of a paused automatic response and a
	// manual check.
	if cfg.Startup.Enabled {
		startupDeps := StartupDeps{
			Release: release, State: state, Core: core, Policy: policy, Settings: settings,
			XDR: xdr, Titan: titanEngine, Exposure: kernelExposure, Advisories: cfg.Advisories, Interface: iface,
		}
		// Assigned only when the service exists: a nil *L7Service stored in the interface field
		// would look present and only fail at the first probe.
		if l7Service != nil {
			startupDeps.L7 = l7Service
		}
		supervisor := &StartupSupervisor{
			modules:  newStartupModules(startupDeps),
			identity: newStartupIdentity(state, iface),
			reArm: func(reason string) (ReleaseStatus, error) {
				return release.ReArmVerified(reason)
			},
			status:       release.Status,
			now:          func() time.Time { return time.Now().UTC() },
			rounds:       cfg.Startup.Rounds,
			roundGap:     time.Duration(cfg.Startup.RoundGapSeconds) * time.Second,
			armInterval:  time.Duration(cfg.Startup.ArmIntervalSec) * time.Second,
			healAttempts: cfg.Startup.HealAttempts,
			qualifyPath:  cfg.Startup.QualificationFile,
		}
		go supervisor.Run(desktopCtx)
	}
	go startSystemdWatchdog(watchdogCtx, func() string {
		status := release.Status()
		return fmt.Sprintf("phase=%s ready=%t core_misses=%d", status.Phase, status.Ready, status.CoreMisses)
	})

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		log.Printf("received %s", s)
	case e := <-errCh:
		if !errors.Is(e, http.ErrServerClosed) {
			log.Fatalf("server: %v", e)
		}
	}
	_ = sdNotify("STOPPING=1\nSTATUS=GeDefense shutting down")
	cancelWatchdog()
	cancelXDR()
	close(stopWorkers)
	close(stopTelemetry)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if l7EdgeService != nil {
		if err := l7EdgeService.Shutdown(ctx); err != nil {
			log.Printf("l7 inline shutdown: %v", err)
		}
	}
	if l7Service != nil {
		if err := l7Service.Shutdown(ctx); err != nil {
			log.Printf("l7 shutdown: %v", err)
		}
	}
	_ = srv.Shutdown(ctx)
}

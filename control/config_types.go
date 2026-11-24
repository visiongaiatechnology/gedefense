package main

type Config struct {
	Node        NodeConfig
	Dashboard   DashboardConfig
	Core        CoreConfig
	Defense     DefenseConfig
	Policy      PolicyConfig
	Feeds       FeedConfig
	XDR         XDRConfig
	L7          L7Config
	Release     ReleaseConfig
	Runtime     RuntimeConfig
	Cells       CellsConfig
	Kinetic     KineticConfig
	Desktop     DesktopConfig
	Startup     StartupSupervisorConfig
	Advisories  AdvisoryConfig
	Titan       TitanConfig
	ParserCells ParserCellsConfig
}

type NodeConfig struct {
	Name      string
	Interface string
	Mode      string
}

type DashboardConfig struct {
	// TokenOwner names the account the dashboard token belongs to. Empty by default, so nothing changes
	// until an operator deliberately separates the gateway's account from the control plane's. When set,
	// the token becomes the property of that account with mode 0600 - the gateway refuses anything less
	// restrictive - while the control plane keeps reading and rotating it through cap_dac_override and
	// cap_chown. The core IPC key and the storage master key stay unreachable for the internet-facing
	// service either way.
	//
	// Configured, never detected: deriving it from the presence of an account would make both the
	// runtime behaviour and the test suite depend on the user table of the machine.
	TokenOwner         string
	Listen             string
	AllowRemote        bool
	AllowedHosts       []string
	TokenFile          string
	TLSCertFile        string
	TLSKeyFile         string
	RateLimitPerMinute int
	RateLimitBurst     int
	MaxSSEClients      int
}

type CoreConfig struct {
	Socket               string
	AuthKeyFile          string
	RequestTimeoutMillis int
}

type DefenseConfig struct {
	Allowlist         []string
	Enforcement       string
	DefaultTTLSeconds int
	MaxTTLSeconds     int
	MaxBlockEntries   int
	StrictASNDrop     bool
	DPIEnabled        bool
}

type PolicyConfig struct {
	StateFile      string
	SigningKeyFile string
	PublicKeyFile  string
	StorageKeyFile string
	RequireSigned  bool
}

type L7Config struct {
	Enabled bool
	Mode    string
	// CoverageRequired decides whether an idle L7 engine degrades the platform:
	// "auto" requires the traffic path only once something is attached, "required"
	// always does, "optional" never does.
	CoverageRequired     string
	Socket               string
	SocketGroup          string
	RequestTimeoutMillis int
	MaxConcurrent        int
	MaxEnvelopeBytes     int
	MaxBodyBytes         int
	MaxURIBytes          int
	MaxHeaderBytes       int
	MaxHeaders           int
	MaxValueBytes        int
	MaxInspectionBytes   int
	MaxDecodedValues     int
	MaxDecodeDepth       int
	MaxJSONDepth         int
	MaxFormFields        int
	MaxMultipartParts    int
	MaxUploadBytes       int
	AlertScore           int
	BlockScore           int
	// EnforceRules optionally limits which findings may authorise a block. Empty keeps the
	// historical behaviour: every finding that is not alert-only may block. Findings outside the
	// list are still recorded and still raise the alert score; only the block decision is scoped.
	EnforceRules                 []string
	ClientRatePerMinute          int
	ClientRateBurst              int
	SensitiveRatePerMinute       int
	SensitiveRateBurst           int
	SensitiveGlobalRatePerMinute int
	SensitiveGlobalRateBurst     int
	MaxTrackedClients            int
	SensitivePaths               []string
	RequirePeerCredentials       bool
	AllowedPeerUIDs              []uint32
	AllowedPeerGIDs              []uint32
	InlineEnabled                bool
	InlineSocket                 string
	InlineUpstream               string
	InlineMaxResponseBytes       int
	TLSEnabled                   bool
	TLSAllowedDomains            []string
	TLSFloodThreshold            int
	TLSSNIStrikeThreshold        int
	TLSAntiSpoof                 bool
	TLSMaxClientHelloBytes       int
	TLSJA3File                   string
}

type XDRConfig struct {
	Enabled                  bool
	Mode                     string
	ScanIntervalMillis       int
	NetworkIntervalSeconds   int
	IntegrityIntervalSeconds int
	AlertScore               int
	ContainScore             int
	KillScore                int
	MaxCommandBytes          int
	CommandPreviewBytes      int
	DedupeSeconds            int
	MaxIncidentLogBytes      int64
	IncidentLog              string
	LogKeyFile               string
	BaselineFile             string
	ProtectedPaths           []string
	AllowProcesses           []string
	// ProtectedSecurityRoots adds the security-relevant directories that exist on this host (web
	// roots, persistence locations, log directories) to the protected roots. See security_roots.go
	// for why the scope of the file-integrity monitor had to grow beyond the platform's own files.
	ProtectedSecurityRoots bool
	WorkerCount            int
	QueueCapacity          int
	MaxEvaluationsPerScan  int
	BehaviorEnabled        bool
	BehaviorWarmupSamples  int
	BehaviorZScoreMilli    int
	BehaviorMinConnections int
	BehaviorMaxProfiles    int
	BehaviorMaxPorts       int
	BehaviorProfileFile    string
	StorageKeyFile         string
}

type ReleaseConfig struct {
	Channel                   string
	MinimumObserveSeconds     int
	MinimumCanarySeconds      int
	CoreFailureThreshold      int
	MaxEvaluationDropPermille int
	EmergencyStopFile         string
	AutoDegrade               bool
}

type RuntimeConfig struct {
	SettingsFile   string
	KeyFile        string
	StorageKeyFile string
}

type CellsConfig struct {
	Enabled              bool
	Socket               string
	AuthKeyFile          string
	RequestTimeoutMillis int
	// Automatic isolation: when an incident scores at or above AutoConfineScore and its workload is
	// bound to a Gaia Cell, the cell is isolated through the transaction engine. Off by default - it
	// takes a capability away from a running workload and that is an operator decision.
	AutoConfine                bool
	AutoConfineAction          string
	AutoConfineScore           int
	AutoConfineIntervalSeconds int
	AutoConfineCooldownSeconds int
}

// ParserCellsConfig is the immutable bootstrap section of the ephemeral parser
// cells: socket, VGTGC2 key, the control-owned staging/import roots and the
// request deadline. It carries no policy - the administrable namespace
// (parser_cells) owns policy.
type ParserCellsConfig struct {
	Socket      string
	AuthKeyFile string
	InputDir    string
	// ImportsDir is the control-owned directory the untrusted burned-cell export is
	// imported into (0750 gedefense:gedefense, provisioned by packaging). The helper
	// staging directory parser-exports is root:gedefense and is NOT writable by the
	// unprivileged control plane: the export reaches control exclusively through the
	// sealed memfd descriptor of CELL_EXPORT_READ.
	ImportsDir           string
	RequestTimeoutMillis int
	// PeerUID is the SO_PEERCRED uid the helper listener must have. The helper is
	// a root unit, so the shipped value is 0; -1 disables the check (not supported
	// for production, documented for local test rigs only).
	PeerUID int
	// WaylandProfiles names the package-managed profiles that require a Wayland
	// session socket. Phase 1 cells run as the unprivileged parser uid (65534) and
	// cannot own a session socket, so a profile declared here is refused fail-closed
	// as capability-missing instead of failing deep inside the helper.
	WaylandProfiles []string
}

type KineticConfig struct {
	Enabled               bool
	EnforcementMode       string
	IPThreshold           int
	VelocityLimit         int
	RangeThreshold        int
	IPv6SubThreshold      int
	WideRangeThreshold    int
	PortscanThreshold     int
	SYNThreshold          int
	SYNAckRatio           int
	LowSlowMinSeconds     int
	SubnetMinSources      int
	IPv6SubnetMinSources  int
	WideMinSources        int
	AutoContainSingleIP   bool
	AutoContainIPv4Subnet bool
	AutoContainIPv6Subnet bool
	MaxTrackingIPs        int
	BanTTLSeconds         int
	MaxStrikesPerSec      int
	ServicePortsWeb       []uint16
	ServicePortsMail      []uint16
	ServicePortsAdmin     []uint16
	GeoIPCSV              string
	// GeoIPSigningKeys pins Ed25519 keys for the signed GeoIP update gate
	// (F-24). When configured, a detached geoip.csv.sig over the SHA-256 sidecar
	// must verify or the dataset is unavailable.
	GeoIPSigningKeys []string
}

type TitanConfig struct {
	Enabled     bool
	Mode        string
	Armed       bool
	AutoContain bool
	Roots       []string
	Allowlist   []string
	// DevelopmentRoots are tolerated, never authorized: a development path is a
	// known working area, not an owner approval.
	DevelopmentRoots []string
	ProtectedPaths   []string
	PolicyFile       string
	JournalFile      string
	MaxFileBytes     int64
	MaxEvents        int
	JournalMaxBytes  int64
}

type FeedConfig struct {
	Enabled          bool
	AutoApply        bool
	RefreshMinutes   int
	MaxDownloadBytes int64
	MaxEntries       int
	Sources          []string

	// Signed feed manifests (F-03 / CHAIN-009). When RequireSignedManifest is
	// true (the shipped default) a download is only accepted when a detached
	// Ed25519 manifest signed by one of TrustedSigningKeys binds its exact raw
	// bytes, its canonical indicator digest, a monotonic version and a hard
	// validity window. Without a provisioned trust anchor feeds fail closed and
	// never reach the kernel blocklist.
	RequireSignedManifest bool
	TrustedSigningKeys    []string
	ManifestPath          string
	ManifestMaxAgeMinutes int

	// Local operator signing (F-03 provisioning). When LocalSigning is true the
	// sync pipeline downloads every enabled source, persists the exact raw bytes
	// below SnapshotDir, signs the detached manifest for exactly those bytes with
	// the operator key in SigningKeyFile and publishes it to ManifestPath. The
	// fetch path then reads the snapshot instead of the network, so the bytes
	// that were signed and the bytes that are parsed can never diverge. The
	// operator key must be pinned in TrustedSigningKeys; otherwise feeds and
	// kernel apply fail closed.
	LocalSigning   bool
	SigningKeyFile string
	SnapshotDir    string
}

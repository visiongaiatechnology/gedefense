//! Point 1 (§5): Titan exec-gate status/state rendering for the privileged core.
//!
//! Split out of `titan_exec.rs` (module size cap). The state machine is pure:
//! only an active LSM, valid offsets and attached hooks may be called `applied`.

/// §5 status state values; `pending`/`failed` are control-plane states and are
/// never claimed by the core (`#[allow(dead_code)]` keeps the ABI complete).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum ExecState {
    Applied,
    Pending,
    Failed,
    Inactive,
    Unavailable,
}

impl ExecState {
    pub fn text(self) -> &'static str {
        match self {
            ExecState::Applied => "applied",
            ExecState::Pending => "pending",
            ExecState::Failed => "failed",
            ExecState::Inactive => "inactive",
            ExecState::Unavailable => "unavailable",
        }
    }
}

/// §5 `TITAN_EXEC_STATUS`: active LSM + valid offsets + attached hooks is the
/// only combination that may be called `applied`.
pub fn exec_state(enforcement_available: bool, lsm_active: bool, offsets_valid: bool) -> ExecState {
    if !lsm_active {
        ExecState::Inactive
    } else if !offsets_valid || !enforcement_available {
        ExecState::Unavailable
    } else {
        ExecState::Applied
    }
}

/// §5 status payload inputs.
pub struct StatusView<'a> {
    pub state: ExecState,
    pub mode: u8,
    pub flags: u8,
    pub path_bpf_lsm: bool,
    pub lsm_active: bool,
    pub offsets_valid: bool,
    pub entries: usize,
    pub scopes: usize,
    pub epoch: &'a str,
}

/// §5 status payload: fixed order, no duplicate keys, bounded numbers.
pub fn encode_exec_status(view: &StatusView<'_>) -> String {
    format!(
        "status={};mode={};flags={};path={};lsm={};offsets={};entries={};scopes={};epoch={}",
        view.state.text(),
        view.mode,
        view.flags,
        if view.path_bpf_lsm { "bpf-lsm" } else { "none" },
        if view.lsm_active { "active" } else { "inactive" },
        if view.offsets_valid { "valid" } else { "invalid" },
        view.entries,
        view.scopes,
        view.epoch
    )
}
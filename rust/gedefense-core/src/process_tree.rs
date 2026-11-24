//! M2.3 (6.2.0): bounded process-tree/process-group response for the core.
//!
//! Wire commands (ABI v2, exactly; see `process_control.rs` module docs):
//! `XDR_KILL_TREE <pid> <start_ticks> <rule>` -> `killed:<n>`,
//! `XDR_GROUP_STOP <pgid> <rule>` -> `stopped`,
//! `XDR_GROUP_CONT <pgid> <rule>` -> `resumed`.
//!
//! Every decision here is bounded and fail-closed: a `/proc` snapshot above
//! [`MAX_TREE_PROCESSES`], a tree above [`MAX_TREE_SIGNALS`] members or above
//! [`MAX_TREE_DEPTH`] ancestry levels is an error, never a partial silent
//! response. All targets are re-verified by start ticks around `pidfd_open`, so
//! a PID-reuse race loses a kill but can never hit an unrelated process. The
//! compiled protection allowlist cannot be widened by a caller.
//!
//! Wave 3c (structure-only) split: this parent keeps the public API and
//! re-exports the children — `tree` (`/proc` model and tree/group collection),
//! `signals` (protection allowlist and pidfd-verified signaling) and `requests`
//! (strict wire parsing and group `SIGSTOP`/`SIGCONT`). The synthetic-`/proc`
//! tests stay in `process_tree_tests.rs`.

mod requests;
mod signals;
mod tree;

pub(crate) use self::requests::*;
pub(crate) use self::signals::*;
pub(crate) use self::tree::*;

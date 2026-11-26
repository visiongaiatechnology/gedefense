//! M2.3 strict wire-request parsing for `XDR_KILL_TREE` and `XDR_GROUP_*`
//! and the process-group `SIGSTOP`/`SIGCONT` operations.

use crate::{process_control::valid_rule_token, BoxError};

/// Pure request parser for `XDR_KILL_TREE`; all tokens are strict.
pub(crate) fn parse_kill_tree_request(args: &[&str]) -> Result<(i32, u64, String), BoxError> {
    let [pid, start, rule] = args else {
        return Err("XDR_KILL_TREE requires pid, start ticks and rule".into());
    };
    let pid = pid
        .parse::<i32>()
        .map_err(|_| -> BoxError { "kill tree pid is not a decimal integer".into() })?;
    if pid <= 4 {
        return Err("kill tree pid is protected".into());
    }
    let start = start
        .parse::<u64>()
        .map_err(|_| -> BoxError { "kill tree start ticks are not a decimal integer".into() })?;
    if start == 0 {
        return Err("kill tree start ticks must be non-zero".into());
    }
    if !valid_rule_token(rule) {
        return Err("invalid rule token".into());
    }
    Ok((pid, start, rule.to_string()))
}

/// M2.2 immediate freeze: `kill(-pgid, SIGSTOP)` after refusing the own group
/// and the unsafe special groups. Bounded and reversible (`XDR_GROUP_CONT`).
pub(crate) fn stop_process_group(pgid: i32, rule: &str) -> Result<(), BoxError> {
    group_signal(pgid, libc::SIGSTOP, rule)
}

/// M2.2 reversal: `kill(-pgid, SIGCONT)` with the same guards as the freeze.
pub(crate) fn resume_process_group(pgid: i32, rule: &str) -> Result<(), BoxError> {
    group_signal(pgid, libc::SIGCONT, rule)
}

/// Strict parser for the group commands: positive PGID, valid rule token.
pub(crate) fn parse_group_request(args: &[&str]) -> Result<(i32, String), BoxError> {
    let [pgid, rule] = args else {
        return Err("group command requires pgid and rule".into());
    };
    let pgid = pgid
        .parse::<i32>()
        .map_err(|_| -> BoxError { "process-group id is not a decimal integer".into() })?;
    if pgid <= 1 {
        return Err("protected process group".into());
    }
    if !valid_rule_token(rule) {
        return Err("invalid rule token".into());
    }
    Ok((pgid, rule.to_string()))
}

fn group_signal(pgid: i32, signal: i32, rule: &str) -> Result<(), BoxError> {
    let (pgid, _) = parse_group_request(&[&pgid.to_string(), rule])?;
    // SAFETY: getpgrp has no arguments and cannot fail.
    let own_pgrp = unsafe { libc::getpgrp() };
    if pgid == own_pgrp || pgid == std::process::id() as i32 {
        return Err("own process group is protected".into());
    }
    if crate::process_tree::signals::process_group_has_protected_target(pgid)? {
        return Err("protected process group".into());
    }
    if signal != libc::SIGSTOP && signal != libc::SIGCONT {
        return Err("unsupported group signal".into());
    }
    let rc = unsafe { libc::kill(-pgid, signal) };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        return Err(std::io::Error::other(format!(
            "process-group signal failed pgid={pgid}: {error}"
        ))
        .into());
    }
    Ok(())
}

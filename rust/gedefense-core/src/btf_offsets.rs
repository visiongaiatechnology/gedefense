//! Point 1 (§4.1/§6): mini-BTF parser and Titan exec-gate runtime offsets.
//!
//! Reads `/sys/kernel/btf/vmlinux` (64 MiB bound), accepts BTF v1 with
//! `hdr_len >= 24`, walks STRUCT/UNION/FUNC/FUNC_PROTO (other documented kinds
//! are skipped by their exact length) and resolves the §4.1 byte offsets,
//! including both ctime layouts (`i_ctime_sec`/`i_ctime_nsec` split or
//! `i_ctime.tv_sec`/`tv_nsec`). Anonymous members recurse, `kind_flag`
//! bitfields are masked, TYPEDEF/CONST chains stripped. Every missing or
//! implausible type/field/size/width/arity is an `Err`: the gate reports
//! `unavailable` and attaches nothing (§8). Fixtures live in `main.rs` tests.
//!
//! Wave 3c (structure-only) split: this parent keeps the public API and
//! re-exports the children — `layout` (header constants and the frozen §4.1
//! offset-index table), `parser` (bounded BTF image parser), `titan` (§4.1
//! Titan exec-gate resolver) and `exec_inode` (V6.3.0 AP-1 executable-inode
//! resolver). The synthetic-BTF resolver tests live in `tests`.

mod exec_inode;
mod layout;
mod parser;
mod titan;
#[cfg(test)]
mod tests;

pub(crate) use self::exec_inode::*;
pub(crate) use self::layout::*;
pub(crate) use self::titan::*;
// `VmlinuxBtf` is exercised directly by the resolver tests (test builds).
#[cfg(test)]
pub(crate) use self::parser::*;

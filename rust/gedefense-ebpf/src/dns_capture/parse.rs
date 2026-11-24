//! Bounded QNAME root scan of the AP-6 DNS capture (child module of
//! `dns_capture`): fully unrolled constant-index steps only, so the verifier
//! walks straight-line code once and no dynamic stack index exists.

use super::DnsParseScratch;

/// Finds the QNAME root label (the first zero byte) with a **fully unrolled**
/// constant-index scan. The scan is unrolled on purpose: a rolled loop with a
/// dynamic position state exploded the verifier state space (>1 M processed
/// instructions on `6.18.33.2-microsoft-standard-WSL2`), while constant-index
/// steps are linear straight-line code the verifier walks once (the
/// `root_found`/`invalid` flags make every later step a no-op, so the branch
/// states merge).
///
/// The QNAME root is the first zero byte of the question name: label length
/// bytes are `1..=63` and label data bytes are checked to be hostname bytes, so
/// a zero byte can only be the root label. Returns the QNAME wire length
/// (root index + 1) or `None` when the root is outside the supplied length.
macro_rules! find_root_step {
    ($i:expr, $scratch:expr, $available:expr, $wire_len:ident, $root_found:ident, $invalid:ident) => {
        if !$root_found && !$invalid {
            if $i >= $available {
                $invalid = true;
            } else if $scratch.window[$i] == 0 {
                $wire_len = $i + 1;
                $root_found = true;
            }
        }
    };
}

#[inline(always)]
pub(crate) fn find_qname_root(scratch: &DnsParseScratch, available: usize) -> Option<usize> {
    let mut wire_len = 0usize;
    let mut root_found = false;
    let mut invalid = false;
    find_root_step!(0, scratch, available, wire_len, root_found, invalid);
    find_root_step!(1, scratch, available, wire_len, root_found, invalid);
    find_root_step!(2, scratch, available, wire_len, root_found, invalid);
    find_root_step!(3, scratch, available, wire_len, root_found, invalid);
    find_root_step!(4, scratch, available, wire_len, root_found, invalid);
    find_root_step!(5, scratch, available, wire_len, root_found, invalid);
    find_root_step!(6, scratch, available, wire_len, root_found, invalid);
    find_root_step!(7, scratch, available, wire_len, root_found, invalid);
    find_root_step!(8, scratch, available, wire_len, root_found, invalid);
    find_root_step!(9, scratch, available, wire_len, root_found, invalid);
    find_root_step!(10, scratch, available, wire_len, root_found, invalid);
    find_root_step!(11, scratch, available, wire_len, root_found, invalid);
    find_root_step!(12, scratch, available, wire_len, root_found, invalid);
    find_root_step!(13, scratch, available, wire_len, root_found, invalid);
    find_root_step!(14, scratch, available, wire_len, root_found, invalid);
    find_root_step!(15, scratch, available, wire_len, root_found, invalid);
    find_root_step!(16, scratch, available, wire_len, root_found, invalid);
    find_root_step!(17, scratch, available, wire_len, root_found, invalid);
    find_root_step!(18, scratch, available, wire_len, root_found, invalid);
    find_root_step!(19, scratch, available, wire_len, root_found, invalid);
    find_root_step!(20, scratch, available, wire_len, root_found, invalid);
    find_root_step!(21, scratch, available, wire_len, root_found, invalid);
    find_root_step!(22, scratch, available, wire_len, root_found, invalid);
    find_root_step!(23, scratch, available, wire_len, root_found, invalid);
    find_root_step!(24, scratch, available, wire_len, root_found, invalid);
    find_root_step!(25, scratch, available, wire_len, root_found, invalid);
    find_root_step!(26, scratch, available, wire_len, root_found, invalid);
    find_root_step!(27, scratch, available, wire_len, root_found, invalid);
    find_root_step!(28, scratch, available, wire_len, root_found, invalid);
    find_root_step!(29, scratch, available, wire_len, root_found, invalid);
    find_root_step!(30, scratch, available, wire_len, root_found, invalid);
    find_root_step!(31, scratch, available, wire_len, root_found, invalid);
    find_root_step!(32, scratch, available, wire_len, root_found, invalid);
    find_root_step!(33, scratch, available, wire_len, root_found, invalid);
    find_root_step!(34, scratch, available, wire_len, root_found, invalid);
    find_root_step!(35, scratch, available, wire_len, root_found, invalid);
    find_root_step!(36, scratch, available, wire_len, root_found, invalid);
    find_root_step!(37, scratch, available, wire_len, root_found, invalid);
    find_root_step!(38, scratch, available, wire_len, root_found, invalid);
    find_root_step!(39, scratch, available, wire_len, root_found, invalid);
    find_root_step!(40, scratch, available, wire_len, root_found, invalid);
    find_root_step!(41, scratch, available, wire_len, root_found, invalid);
    find_root_step!(42, scratch, available, wire_len, root_found, invalid);
    find_root_step!(43, scratch, available, wire_len, root_found, invalid);
    find_root_step!(44, scratch, available, wire_len, root_found, invalid);
    find_root_step!(45, scratch, available, wire_len, root_found, invalid);
    find_root_step!(46, scratch, available, wire_len, root_found, invalid);
    find_root_step!(47, scratch, available, wire_len, root_found, invalid);
    find_root_step!(48, scratch, available, wire_len, root_found, invalid);
    find_root_step!(49, scratch, available, wire_len, root_found, invalid);
    find_root_step!(50, scratch, available, wire_len, root_found, invalid);
    find_root_step!(51, scratch, available, wire_len, root_found, invalid);
    find_root_step!(52, scratch, available, wire_len, root_found, invalid);
    find_root_step!(53, scratch, available, wire_len, root_found, invalid);
    find_root_step!(54, scratch, available, wire_len, root_found, invalid);
    find_root_step!(55, scratch, available, wire_len, root_found, invalid);
    find_root_step!(56, scratch, available, wire_len, root_found, invalid);
    find_root_step!(57, scratch, available, wire_len, root_found, invalid);
    find_root_step!(58, scratch, available, wire_len, root_found, invalid);
    find_root_step!(59, scratch, available, wire_len, root_found, invalid);
    find_root_step!(60, scratch, available, wire_len, root_found, invalid);
    find_root_step!(61, scratch, available, wire_len, root_found, invalid);
    find_root_step!(62, scratch, available, wire_len, root_found, invalid);
    find_root_step!(63, scratch, available, wire_len, root_found, invalid);
    if invalid || !root_found {
        return None;
    }
    Some(wire_len)
}

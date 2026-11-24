//! Managed-namespace matching and the deterministic neutral identifier
//! derivation (HMAC-SHA256 over the install salt).

use super::*;
use std::collections::{BTreeSet, HashMap, HashSet};

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// Maximum derivation attempts per identifier before the profile refuses.
const MAX_DERIVATION_ATTEMPTS: u32 = 128;
/// Maximum accepted public identifier length. `.strtab` names are far shorter;
/// the bound keeps the byte tables and the audit document small.
const MAX_IDENTIFIER_BYTES: usize = 96;
/// Alphabet for the tail of a neutral identifier.
const NEUTRAL_ALPHABET: &[u8; 37] = b"abcdefghijklmnopqrstuvwxyz0123456789_";

/// Uppercase map-name prefixes that are part of the kernel-visible GeDefense
/// namespace. `gedefense_*` program names are matched separately.
///
/// The list is intentionally broader than the historical `FLOW_`/`STYX_`/
/// `TITAN_` set: every map the privileged core resolves through [`map_name`]
/// must be renamed here, otherwise the load would fail (fatal, never a silent
/// public identity).
const MANAGED_MAP_PREFIXES: [&str; 26] = [
    "ALLOWLIST_",
    "BLOCKLIST_",
    "BPF_GUARD_",
    "CELL_",
    "CRED_GUARD_",
    "CROSS_VIEW_",
    "DNS_CAPTURE_",
    "EGRESS_",
    "EXEC_",
    "FLOW_",
    "FLOW_AGG_",
    "INGRESS_",
    "KERNEL_HOOK_",
    "KERNEL_PROBE_",
    "LOCKDOWN_",
    "MALWARE_",
    "PACKET_",
    "PENDING_",
    "PERSIST_",
    "RANSOM_",
    "SEC_CRIT_",
    "STYX_",
    "TELEMETRY_",
    "TITAN_",
    "TRUSTED_EXEC_",
    "WORKER_",
];

/// Substrings a neutral identifier may never contain (case-insensitive).
const FORBIDDEN_IDENTIFIER_SUBSTRINGS: [&str; 5] =
    ["gedefense", "vgt", "styx", "titan", "geodefense"];

/// True when `name` belongs to the kernel-visible GeDefense identifier namespace
/// this profile is allowed to rename.
pub(super) fn is_managed_identifier(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_IDENTIFIER_BYTES {
        return false;
    }
    if name.starts_with("gedefense_") {
        return true;
    }
    MANAGED_MAP_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// Domain separator for the HMAC: programs and maps are derived independently.
pub(super) fn identifier_domain(name: &str) -> &'static [u8] {
    if name.starts_with("gedefense_") {
        b"prog:"
    } else {
        b"map:"
    }
}

/// True when a candidate neutral identifier has the documented shape.
pub(super) fn neutral_identifier_shape_is_valid(candidate: &str) -> bool {
    let mut bytes = candidate.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    candidate
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && !contains_forbidden_identifier(&candidate.to_ascii_lowercase())
}

pub(super) fn contains_forbidden_identifier(candidate: &str) -> bool {
    FORBIDDEN_IDENTIFIER_SUBSTRINGS
        .iter()
        .any(|forbidden| candidate.contains(forbidden))
}

// --------------------------------------------------------------- derivation

/// Derives the deterministic neutral identifier for one public name and
/// derivation counter. The output is exactly `length` bytes, starts with a
/// lowercase letter and otherwise only contains `[a-z0-9_]`.
pub(super) fn derive_neutral_identifier(
    salt: &[u8; 32],
    domain: &[u8],
    public_name: &str,
    counter: u32,
    length: usize,
) -> String {
    use hmac::Mac as _;
    let mut derived: Vec<u8> = Vec::with_capacity(length + 32);
    let mut block: u32 = 0;
    while derived.len() < length {
        let mut mac = HmacSha256::new_from_slice(salt).expect("HMAC accepts any key length");
        mac.update(domain);
        mac.update(public_name.as_bytes());
        mac.update(&counter.to_le_bytes());
        mac.update(&block.to_le_bytes());
        derived.extend_from_slice(&mac.finalize().into_bytes());
        block = block.wrapping_add(1);
    }
    let mut neutral = String::with_capacity(length);
    neutral.push((b'a' + (derived[0] % 26)) as char);
    for byte in &derived[1..length] {
        neutral.push(NEUTRAL_ALPHABET[*byte as usize % NEUTRAL_ALPHABET.len()] as char);
    }
    neutral
}

/// True when `candidate` is a valid, not-yet-used neutral identifier.
fn neutral_candidate_is_usable(candidate: &str, used: &HashSet<String>) -> bool {
    neutral_identifier_shape_is_valid(candidate) && !used.contains(candidate)
}

/// Builds the per-object plan: one deterministic neutral identifier per managed
/// public symbol name, unique across the object and never equal to a public
/// identifier. Collisions are retried with a counter inside the HMAC input.
pub(super) fn build_name_plan(
    names: &BTreeSet<String>,
    salt: &[u8; 32],
) -> Result<HashMap<String, String>, BoxError> {
    let mut used: HashSet<String> = names.iter().cloned().collect();
    let mut plan: HashMap<String, String> = HashMap::with_capacity(names.len());
    for name in names {
        let mut chosen = None;
        for counter in 0..MAX_DERIVATION_ATTEMPTS {
            let candidate =
                derive_neutral_identifier(salt, identifier_domain(name), name, counter, name.len());
            if neutral_candidate_is_usable(&candidate, &used) {
                chosen = Some(candidate);
                break;
            }
        }
        match chosen {
            Some(neutral) => {
                used.insert(neutral.clone());
                plan.insert(name.clone(), neutral);
            }
            None => {
                return Err(format!(
                    "chameleon could not derive a unique neutral identifier for {name}"
                )
                .into())
            }
        }
    }
    Ok(plan)
}

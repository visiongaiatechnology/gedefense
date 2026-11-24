//! QNAME wire-view reconstruction: complete-name label parsing, clipped
//! tail phase resolution and the presentation grouping view (AP-6).

use super::*;
use gedefense_common::{
    dns_capture_tail_len, dns_label_byte_allowed, DNS_CAPTURE_FLAG_SUBDOMAIN_TRUNCATED,
    DNS_CAPTURE_MAX_LABELS,
};

/// Parses a complete QNAME wire view into its labels.
fn parse_complete_qname(wire: &[u8]) -> Option<Vec<&[u8]>> {
    let mut labels: Vec<&[u8]> = Vec::with_capacity(4);
    let mut position = 0usize;
    loop {
        let length = *wire.get(position)?;
        if length == 0 {
            if position + 1 != wire.len() {
                return None;
            }
            break;
        }
        if length > 63 || labels.len() >= usize::from(DNS_CAPTURE_MAX_LABELS) {
            return None;
        }
        let start = position + 1;
        let end = start + usize::from(length);
        let label = wire.get(start..end)?;
        if !label.iter().copied().all(dns_label_byte_allowed) {
            return None;
        }
        labels.push(label);
        position = end;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels)
    }
}

/// Resolves the label phase of a clipped tail. The tail is the last
/// `min(wire_len, 15)` wire bytes and therefore ends with the root label. A phase
/// `p` is valid when treating `tail[p]` as a label length parses exactly to the
/// root at the tail end. Among valid phases the one with the most complete
/// labels wins (tie: smallest phase), which reconstructs the longest true suffix
/// of the QNAME; a phase that starts inside a label only parses by digit-byte
/// coincidence and is deprioritised by the label-count comparison.
fn parse_tail_labels(tail: &[u8], remaining_labels: usize) -> Option<Vec<&[u8]>> {
    if tail.len() < 2 || *tail.last()? != 0 {
        return None;
    }
    let mut best: Option<Vec<&[u8]>> = None;
    let mut phase = 0usize;
    while phase < tail.len() {
        if let Some(labels) = parse_complete_qname(&tail[phase..]) {
            if labels.len() <= remaining_labels {
                let better = match &best {
                    None => true,
                    Some(current) => labels.len() > current.len(),
                };
                if better {
                    best = Some(labels);
                }
            }
        }
        phase += 1;
    }
    best
}

/// Builds the presentation grouping view from the wire record, enforcing the
/// producer invariants (`None` = inconsistent record, never repaired).
pub(super) fn reconstruct_qname(event: &DnsCaptureEvent) -> Option<Vec<u8>> {
    let wire_len = event.qname_wire_len();
    if wire_len < 3 {
        return None;
    }
    let tail_len = dns_capture_tail_len(wire_len);
    let tail_start = wire_len - tail_len;
    let tail = event.qname_tail_bytes();
    if tail.len() != tail_len {
        return None;
    }
    let first_label_stored = event.subdomain_bytes();
    if first_label_stored.is_empty() {
        return None;
    }
    let first_label_truncated = event.flags & DNS_CAPTURE_FLAG_SUBDOMAIN_TRUNCATED != 0;
    let mut qname: Vec<u8> = Vec::with_capacity(DNS_CAPTURE_MAX_RECONSTRUCTED_BYTES);

    if tail_start == 0 {
        // Whole QNAME stored: parse it and cross-check every stored field.
        let labels = parse_complete_qname(tail)?;
        if event.label_count > 0 && labels.len() != usize::from(event.label_count) {
            return None;
        }
        let first = labels.first()?;
        if first_label_truncated {
            if usize::from(event.sub_len) != first_label_stored.len()
                || first.len() <= first_label_stored.len()
                || !first.starts_with(first_label_stored)
            {
                return None;
            }
        } else if first.len() != first_label_stored.len() || first != &first_label_stored {
            return None;
        }
        for (index, label) in labels.iter().enumerate() {
            if index > 0 {
                qname.push(b'.');
            }
            qname.extend_from_slice(label);
        }
        if qname.len() != usize::from(event.fqdn_len) {
            return None;
        }
        return Some(qname);
    }

    // Clipped QNAME: the tail is a label-aligned run of trailing labels.
    let remaining = if event.label_count > 0 {
        usize::from(event.label_count) - 1
    } else {
        usize::from(DNS_CAPTURE_MAX_LABELS)
    };
    let trailing = parse_tail_labels(tail, remaining)?;
    let trailing_chars: usize = trailing.iter().map(|label| label.len()).sum();
    let omitted_chars = usize::from(event.fqdn_len)
        .checked_sub(first_label_stored.len())?
        .checked_sub(trailing_chars)?;
    if first_label_truncated {
        // Omitted characters must cover the dropped first-label tail (>= 1).
        if omitted_chars < 1 {
            return None;
        }
    } else if omitted_chars > 0 {
        // Omitted characters are whole middle labels: at least one label, so at
        // least one character plus its dot.
        if omitted_chars < 2 {
            return None;
        }
    }
    qname.extend_from_slice(first_label_stored);
    for label in &trailing {
        qname.push(b'.');
        qname.extend_from_slice(label);
    }
    if qname.len() > usize::from(event.fqdn_len)
        || qname.len() > DNS_CAPTURE_MAX_RECONSTRUCTED_BYTES
    {
        return None;
    }
    Some(qname)
}

/// Maximum presentation bytes of the reconstructed grouping view
/// (first-label prefix + dots + the 15-byte tail's characters).
const DNS_CAPTURE_MAX_RECONSTRUCTED_BYTES: usize = 12 + 1 + 14;

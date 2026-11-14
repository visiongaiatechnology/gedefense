//! Host-side harness for the production XDP/TC L2 parser exposed by
//! `gedefense_common::parse_network_header`.
//!
//! Input protocol: up to `L2_PREFIX_BYTES` bytes are read from stdin and fed to
//! the exact parser the eBPF data plane runs, so any crash/fuzz finding is a real
//! parser finding. Empty stdin instead runs a deterministic seed corpus covering
//! every EtherType and the VLAN nesting combinations.

use gedefense_common::{parse_network_header, NetworkHeader, L2_PREFIX_BYTES};
use std::io::{self, Read};

const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88a8;

/// The parser must only ever report a header offset that still lies inside the
/// fixed prefix it was handed, and only for an IP EtherType.
fn assert_bounded(header: NetworkHeader) {
    match header {
        NetworkHeader::Ipv4(offset) | NetworkHeader::Ipv6(offset) => {
            assert!(
                (14..=L2_PREFIX_BYTES).contains(&offset),
                "network header offset {offset} escaped the fixed {L2_PREFIX_BYTES}-byte L2 prefix"
            );
        }
        NetworkHeader::Other => {}
    }
}

fn parse(prefix: &mut [u8; L2_PREFIX_BYTES]) -> NetworkHeader {
    std::hint::black_box(parse_network_header(prefix))
}

/// Deterministic seeds: exhaustive EtherType coverage at the untagged position
/// plus every single/double 802.1Q/802.1ad tag nesting and inner EtherType
/// class.
fn run_seed_corpus() {
    let mut prefix = [0u8; L2_PREFIX_BYTES];
    for protocol in 0u16..=u16::MAX {
        prefix[12..14].copy_from_slice(&protocol.to_be_bytes());
        assert_bounded(parse(&mut prefix));
    }

    // Single tag: the EtherType behind the tag decides between IPv4, IPv6, a
    // third (unsupported) tag and a non-IP payload.
    for outer in [ETH_P_8021Q, ETH_P_8021AD] {
        for inner in [ETH_P_IPV4, ETH_P_IPV6, ETH_P_8021Q, ETH_P_8021AD, 0x0000] {
            let mut tagged = [0u8; L2_PREFIX_BYTES];
            tagged[12..14].copy_from_slice(&outer.to_be_bytes());
            tagged[16..18].copy_from_slice(&inner.to_be_bytes());
            assert_bounded(parse(&mut tagged));

            // Double tag: two VLAN tags are the parser's documented maximum, so a
            // real IP header behind them must be found at offset 22 (and a third
            // tag must degrade to Other instead of walking past the prefix).
            let mut double = [0u8; L2_PREFIX_BYTES];
            double[12..14].copy_from_slice(&outer.to_be_bytes());
            double[16..18].copy_from_slice(&ETH_P_8021AD.to_be_bytes());
            double[20..22].copy_from_slice(&inner.to_be_bytes());
            let header = parse(&mut double);
            assert_bounded(header);
            if inner == ETH_P_IPV4 {
                assert_eq!(header, NetworkHeader::Ipv4(22));
            } else if inner == ETH_P_IPV6 {
                assert_eq!(header, NetworkHeader::Ipv6(22));
            } else if matches!(inner, ETH_P_8021Q | ETH_P_8021AD) {
                assert_eq!(header, NetworkHeader::Other);
            }
        }
    }
}

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin()
        .take((L2_PREFIX_BYTES + 1) as u64)
        .read_to_end(&mut input)?;
    if input.is_empty() {
        run_seed_corpus();
        return Ok(());
    }
    if input.len() == L2_PREFIX_BYTES {
        let mut prefix = [0u8; L2_PREFIX_BYTES];
        prefix.copy_from_slice(&input);
        assert_bounded(parse(&mut prefix));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn deterministic_seed_corpus_stays_inside_the_fixed_prefix() {
        super::run_seed_corpus();
    }
}

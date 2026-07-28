#![no_std]

pub const MAX_BLOCKLIST_ENTRIES_V4: u32 = 250_000;
pub const MAX_BLOCKLIST_ENTRIES_V6: u32 = 250_000;
pub const ACTION_DROP: u8 = 1;
pub const L2_PREFIX_BYTES: usize = 22;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88a8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkHeader {
    Ipv4(usize),
    Ipv6(usize),
    Other,
}

#[inline(always)]
fn ether_type(prefix: &[u8; L2_PREFIX_BYTES], offset: usize) -> u16 {
    u16::from_be_bytes([prefix[offset], prefix[offset + 1]])
}

/// Parses Ethernet plus at most two 802.1Q/802.1ad tags from a fixed-size
/// prefix. The fixed input size gives the eBPF verifier static bounds while
/// exposing the exact production parser to host-side fuzzing.
#[inline(always)]
pub fn parse_network_header(prefix: &[u8; L2_PREFIX_BYTES]) -> NetworkHeader {
    let mut protocol = ether_type(prefix, 12);
    let mut offset = 14usize;

    if protocol == ETH_P_8021Q || protocol == ETH_P_8021AD {
        protocol = ether_type(prefix, 16);
        offset = 18;
    }
    if protocol == ETH_P_8021Q || protocol == ETH_P_8021AD {
        protocol = ether_type(prefix, 20);
        offset = 22;
    }

    match protocol {
        ETH_P_IP => NetworkHeader::Ipv4(offset),
        ETH_P_IPV6 => NetworkHeader::Ipv6(offset),
        _ => NetworkHeader::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_double_tagged_network_headers() {
        let mut plain = [0u8; L2_PREFIX_BYTES];
        plain[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
        assert_eq!(parse_network_header(&plain), NetworkHeader::Ipv4(14));

        let mut tagged = [0u8; L2_PREFIX_BYTES];
        tagged[12..14].copy_from_slice(&ETH_P_8021Q.to_be_bytes());
        tagged[16..18].copy_from_slice(&ETH_P_8021AD.to_be_bytes());
        tagged[20..22].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        assert_eq!(parse_network_header(&tagged), NetworkHeader::Ipv6(22));
    }

    #[test]
    fn every_two_byte_protocol_value_is_bounded() {
        let mut prefix = [0u8; L2_PREFIX_BYTES];
        for protocol in 0u16..=u16::MAX {
            prefix[12..14].copy_from_slice(&protocol.to_be_bytes());
            match parse_network_header(&prefix) {
                NetworkHeader::Ipv4(offset) | NetworkHeader::Ipv6(offset) => {
                    assert!((14..=22).contains(&offset));
                }
                NetworkHeader::Other => {}
            }
        }
    }
}

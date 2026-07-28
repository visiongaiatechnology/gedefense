use gedefense_common::{parse_network_header, L2_PREFIX_BYTES};
use std::io::{self, Read};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin()
        .take((L2_PREFIX_BYTES + 1) as u64)
        .read_to_end(&mut input)?;
    if input.len() == L2_PREFIX_BYTES {
        let mut prefix = [0u8; L2_PREFIX_BYTES];
        prefix.copy_from_slice(&input);
        std::hint::black_box(parse_network_header(&prefix));
    }
    Ok(())
}

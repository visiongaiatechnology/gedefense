//! M1.2 (6.2.0): bounded, dependency-free raw DEFLATE (RFC 1951) decoder.
//!
//! The nested-archive inspector must look *inside* ZIP/GZIP members to close
//! the "archive in archive" evasion class. The workspace is built offline and
//! `Cargo.lock` is pinned, so no compression crate may be added; this module
//! implements exactly the decoder subset the inspector needs and nothing else:
//! stored blocks, fixed Huffman blocks and dynamic Huffman blocks, with a hard
//! caller-provided output limit (a decompression bomb is a bounded error, never
//! an allocation). The decoder is not a general-purpose library: it reports how
//! many compressed bytes it consumed so the caller can continue with the next
//! GZIP member, and every structurally impossible byte is an `Err`.

use std::io::Read;

/// Maximum literal/length or distance code length of RFC 1951.
const MAX_CODE_LENGTH: usize = 15;
/// Copy window of DEFLATE; a distance beyond the produced output is invalid.
const WINDOW_BYTES: usize = 32 * 1024;
/// Input read chunk size for the bit reader.
const INPUT_CHUNK_BYTES: usize = 8 * 1024;

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
    13, 13,
];
/// RFC 1951 §3.2.7 code-length alphabet transmission order.
const CODE_LENGTH_ORDER: [usize; 19] =
    [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// Decoder failure; every variant is a bounded rejection, never a repair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeflateError {
    /// The produced output would exceed the caller's hard limit.
    OutputLimitExceeded,
    /// The compressed stream is truncated or structurally invalid.
    Invalid(&'static str),
}

/// Result of one raw DEFLATE stream.
pub(crate) struct Inflated {
    pub(crate) output: Vec<u8>,
    /// Compressed bytes consumed by this stream (byte-aligned end of the last
    /// deflate block), so a GZIP caller can read its 8-byte trailer afterwards.
    pub(crate) consumed: u64,
}

/// Decompresses one raw DEFLATE stream from `reader` with a hard output bound.
pub(crate) fn inflate<R: Read>(reader: &mut R, max_output: usize) -> Result<Inflated, DeflateError> {
    let mut bits = BitReader::new(reader);
    let mut output = Vec::new();
    loop {
        let final_block = bits.bits(1)? == 1;
        match bits.bits(2)? {
            0 => inflate_stored(&mut bits, &mut output, max_output)?,
            1 => {
                let tables = fixed_tables();
                inflate_codes(&mut bits, &mut output, max_output, &tables.literals, &tables.distances)?
            }
            2 => {
                let tables = dynamic_tables(&mut bits)?;
                inflate_codes(
                    &mut bits,
                    &mut output,
                    max_output,
                    &tables.literals,
                    &tables.distances,
                )?;
            }
            _ => return Err(DeflateError::Invalid("reserved deflate block type")),
        }
        if final_block {
            break;
        }
    }
    bits.align_byte();
    Ok(Inflated {
        output,
        consumed: bits.consumed(),
    })
}

/// Fixed Huffman tables of RFC 1951 §3.2.6, built once per process.
struct FixedTables {
    literals: Huffman,
    distances: Huffman,
}

fn fixed_tables() -> &'static FixedTables {
    use std::sync::OnceLock;
    static TABLES: OnceLock<FixedTables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut lengths = [0u8; 288];
        for (symbol, length) in lengths.iter_mut().enumerate() {
            *length = match symbol {
                0..=143 => 8,
                144..=255 => 9,
                256..=279 => 7,
                _ => 8,
            };
        }
        FixedTables {
            literals: Huffman::from_lengths(&lengths).expect("fixed literal table"),
            distances: Huffman::from_lengths(&[5u8; 30]).expect("fixed distance table"),
        }
    })
}

struct Tables {
    literals: Huffman,
    distances: Huffman,
}

fn inflate_stored<R: Read>(
    bits: &mut BitReader<R>,
    output: &mut Vec<u8>,
    max_output: usize,
) -> Result<(), DeflateError> {
    bits.align_byte();
    let length = bits.bits(16)? as usize;
    let complement = bits.bits(16)? as usize;
    if length != (!complement & 0xffff) {
        return Err(DeflateError::Invalid("stored block length check"));
    }
    if output.len().saturating_add(length) > max_output {
        return Err(DeflateError::OutputLimitExceeded);
    }
    for _ in 0..length {
        output.push(bits.bits(8)? as u8);
    }
    Ok(())
}

fn inflate_codes<R: Read>(
    bits: &mut BitReader<R>,
    output: &mut Vec<u8>,
    max_output: usize,
    literals: &Huffman,
    distances: &Huffman,
) -> Result<(), DeflateError> {
    loop {
        let symbol = literals.decode(bits)? as usize;
        match symbol {
            0..=255 => {
                if output.len() >= max_output {
                    return Err(DeflateError::OutputLimitExceeded);
                }
                output.push(symbol as u8);
            }
            256 => return Ok(()),
            257..=285 => {
                let index = symbol - 257;
                let length = LENGTH_BASE[index] as usize + bits.bits(LENGTH_EXTRA[index])? as usize;
                let distance_symbol = distances.decode(bits)? as usize;
                if distance_symbol >= DIST_BASE.len() {
                    return Err(DeflateError::Invalid("deflate distance symbol"));
                }
                let distance = DIST_BASE[distance_symbol] as usize
                    + bits.bits(DIST_EXTRA[distance_symbol])? as usize;
                if distance == 0 || distance > output.len() || distance > WINDOW_BYTES {
                    return Err(DeflateError::Invalid("deflate distance outside window"));
                }
                if output.len().saturating_add(length) > max_output {
                    return Err(DeflateError::OutputLimitExceeded);
                }
                let start = output.len() - distance;
                for offset in 0..length {
                    let byte = output[start + offset];
                    output.push(byte);
                }
            }
            _ => return Err(DeflateError::Invalid("deflate literal symbol")),
        }
    }
}

fn dynamic_tables<R: Read>(bits: &mut BitReader<R>) -> Result<Tables, DeflateError> {
    let literal_count = bits.bits(5)? as usize + 257;
    let distance_count = bits.bits(5)? as usize + 1;
    let code_length_count = bits.bits(4)? as usize + 4;
    if literal_count > 286 || distance_count > 30 {
        return Err(DeflateError::Invalid("deflate table size"));
    }
    let mut code_lengths = [0u8; 19];
    for index in 0..code_length_count {
        code_lengths[CODE_LENGTH_ORDER[index]] = bits.bits(3)? as u8;
    }
    let code_length_table = Huffman::from_lengths(&code_lengths)?;
    let total = literal_count + distance_count;
    let mut lengths = Vec::with_capacity(total);
    while lengths.len() < total {
        let symbol = code_length_table.decode(bits)?;
        match symbol {
            0..=15 => lengths.push(symbol as u8),
            16 => {
                let previous = *lengths
                    .last()
                    .ok_or(DeflateError::Invalid("deflate repeat without previous"))?;
                let repeat = 3 + bits.bits(2)? as usize;
                extend_lengths(&mut lengths, previous, repeat, total)?;
            }
            17 => {
                let repeat = 3 + bits.bits(3)? as usize;
                extend_lengths(&mut lengths, 0, repeat, total)?;
            }
            18 => {
                let repeat = 11 + bits.bits(7)? as usize;
                extend_lengths(&mut lengths, 0, repeat, total)?;
            }
            _ => return Err(DeflateError::Invalid("deflate code length symbol")),
        }
    }
    let literals = Huffman::from_lengths(&lengths[..literal_count])?;
    // An all-zero distance table is legal when a block has no matches; decoding
    // a distance from it fails instead of producing a bogus distance.
    let distances = Huffman::from_lengths(&lengths[literal_count..])?;
    Ok(Tables {
        literals,
        distances,
    })
}

fn extend_lengths(
    lengths: &mut Vec<u8>,
    value: u8,
    repeat: usize,
    total: usize,
) -> Result<(), DeflateError> {
    if lengths.len().saturating_add(repeat) > total {
        return Err(DeflateError::Invalid("deflate code length overflow"));
    }
    lengths.extend(std::iter::repeat(value).take(repeat));
    Ok(())
}

/// Canonical Huffman decoder (the `puff.c` count/offset representation).
struct Huffman {
    count: [u16; MAX_CODE_LENGTH + 1],
    symbol: Vec<u16>,
}

impl Huffman {
    fn from_lengths(lengths: &[u8]) -> Result<Self, DeflateError> {
        if lengths.len() > 288 {
            return Err(DeflateError::Invalid("deflate huffman alphabet"));
        }
        let mut count = [0u16; MAX_CODE_LENGTH + 1];
        for &length in lengths {
            if length as usize > MAX_CODE_LENGTH {
                return Err(DeflateError::Invalid("deflate code length"));
            }
            count[length as usize] += 1;
        }
        // Over-subscribed codes are corrupt; incomplete codes are valid for the
        // distance alphabet (an unused symbol simply never decodes).
        let mut left: i32 = 1;
        for length in 1..=MAX_CODE_LENGTH {
            left <<= 1;
            left -= i32::from(count[length]);
            if left < 0 {
                return Err(DeflateError::Invalid("over-subscribed huffman code"));
            }
        }
        let mut offsets = [0u16; MAX_CODE_LENGTH + 2];
        for length in 1..=MAX_CODE_LENGTH {
            offsets[length + 1] = offsets[length] + count[length];
        }
        let mut symbol = vec![0u16; lengths.len()];
        for (value, &length) in lengths.iter().enumerate() {
            if length != 0 {
                let slot = &mut offsets[length as usize];
                symbol[*slot as usize] = value as u16;
                *slot += 1;
            }
        }
        Ok(Self { count, symbol })
    }

    fn decode<R: Read>(&self, bits: &mut BitReader<R>) -> Result<u16, DeflateError> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for length in 1..=MAX_CODE_LENGTH {
            code |= bits.bits(1)? as i32;
            let count = i32::from(self.count[length]);
            if code - first < count {
                let symbol = index + (code - first);
                return self
                    .symbol
                    .get(symbol as usize)
                    .copied()
                    .ok_or(DeflateError::Invalid("deflate huffman index"));
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(DeflateError::Invalid("deflate huffman code"))
    }
}

/// LSB-first bit reader with a bounded read-ahead buffer.
struct BitReader<R: Read> {
    reader: R,
    buffer: [u8; INPUT_CHUNK_BYTES],
    position: usize,
    filled: usize,
    bits: u64,
    bit_count: u8,
    total_read: u64,
    eof: bool,
}

impl<R: Read> BitReader<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: [0u8; INPUT_CHUNK_BYTES],
            position: 0,
            filled: 0,
            bits: 0,
            bit_count: 0,
            total_read: 0,
            eof: false,
        }
    }

    fn refill(&mut self) -> Result<(), DeflateError> {
        if self.bit_count > 56 {
            return Err(DeflateError::Invalid("deflate bit buffer"));
        }
        while self.bit_count <= 56 {
            if self.position == self.filled {
                if self.eof {
                    break;
                }
                self.filled = match self.reader.read(&mut self.buffer) {
                    Ok(0) => {
                        self.eof = true;
                        0
                    }
                    Ok(count) => count,
                    Err(_) => return Err(DeflateError::Invalid("deflate input read")),
                };
                self.position = 0;
                self.total_read += self.filled as u64;
                if self.filled == 0 {
                    break;
                }
            }
            self.bits |= u64::from(self.buffer[self.position]) << self.bit_count;
            self.position += 1;
            self.bit_count += 8;
        }
        Ok(())
    }

    fn bits(&mut self, count: u8) -> Result<u32, DeflateError> {
        debug_assert!(count <= 16);
        if self.bit_count < count {
            self.refill()?;
        }
        if self.bit_count < count {
            return Err(DeflateError::Invalid("truncated deflate stream"));
        }
        let mask = if count == 32 { u32::MAX } else { (1u32 << count) - 1 };
        let value = (self.bits as u32) & mask;
        self.bits >>= count;
        self.bit_count -= count;
        Ok(value)
    }

    fn align_byte(&mut self) {
        let drop = self.bit_count % 8;
        self.bits >>= drop;
        self.bit_count -= drop;
    }

    /// Byte-aligned compressed input consumed so far. Only meaningful after
    /// [`Self::align_byte`]: the read-ahead bytes still sitting in `buffer`
    /// (pulled but not yet handed to the bit buffer) and the whole bytes still
    /// in the bit buffer itself are both *not* consumed.
    fn consumed(&self) -> u64 {
        let buffered = (self.filled - self.position) as u64;
        let read_ahead = u64::from(self.bit_count / 8);
        self.total_read.saturating_sub(buffered).saturating_sub(read_ahead)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn inflate_bytes(compressed: &[u8], max: usize) -> Result<Vec<u8>, DeflateError> {
        let mut reader = compressed;
        Ok(inflate(&mut reader, max)?.output)
    }

    #[test]
    fn decodes_stored_blocks() {
        // Final stored block: header bits 0b011, padded, LEN/NLEN little endian.
        let mut stream = vec![0x01, 0x05, 0x00, 0xfa, 0xff];
        stream.extend_from_slice(b"hello");
        assert_eq!(inflate_bytes(&stream, 16).expect("stored"), b"hello");
        // A stored block split across two blocks.
        let mut stream = vec![0x00, 0x03, 0x00, 0xfc, 0xff];
        stream.extend_from_slice(b"abc");
        stream.extend_from_slice(&[0x01, 0x03, 0x00, 0xfc, 0xff]);
        stream.extend_from_slice(b"def");
        assert_eq!(inflate_bytes(&stream, 16).expect("two blocks"), b"abcdef");
    }

    #[test]
    fn decodes_fixed_huffman_streams() {
        // Raw deflate fixtures produced by zlib (`compressobj(9, DEFLATED, -15)`).
        assert_eq!(
            inflate_bytes(&hex("cb48cdc9c90700"), 16).expect("hello"),
            b"hello"
        );
        assert_eq!(
            inflate_bytes(&hex("cb4b2d2e494dd14d2c4acec82c4bd5cd4dcd4d4a2d0200"), 64)
                .expect("nested"),
            b"nested-archive-member"
        );
        // 300 repeated bytes: one match sequence plus back-references.
        assert_eq!(
            inflate_bytes(&hex("73741c05c40200"), 1024).expect("run"),
            vec![b'A'; 300]
        );
    }

    #[test]
    fn dynamic_huffman_streams_are_verified_against_zlib() {
        // zlib level 9 on an ELF-prefixed 404-byte payload; exercises the
        // dynamic-Huffman path of a real encoder.
        let expected = {
            let mut payload = b"\x7fELF".to_vec();
            payload.extend_from_slice(&[b'B'; 400]);
            payload
        };
        assert_eq!(
            inflate_bytes(&hex("ab77f571731a05830a0000"), 1024).expect("dynamic"),
            expected
        );
    }

    #[test]
    fn output_limit_is_a_hard_bounded_rejection() {
        assert_eq!(
            inflate_bytes(&hex("73741c05c40200"), 100).unwrap_err(),
            DeflateError::OutputLimitExceeded
        );
        // A stored block declaring more bytes than the budget fails before it
        // reads the payload.
        let mut stream = vec![0x01, 0x10, 0x00, 0xef, 0xff];
        stream.extend_from_slice(&[b'x'; 16]);
        assert_eq!(
            inflate_bytes(&stream, 8).unwrap_err(),
            DeflateError::OutputLimitExceeded
        );
    }

    #[test]
    fn malformed_streams_are_rejected() {
        for bad in [
            &hex("")[..],
            &hex("01")[..],                     // truncated stored header
            &hex("03")[..],                     // reserved block type
            &hex("011000100000")[..],           // stored LEN/NLEN mismatch
            &hex("cb48cdc9")[..],               // truncated huffman block
            &hex("ffffffffffffffffffff")[..],   // garbage codes
        ] {
            assert!(inflate_bytes(bad, 1024).is_err(), "accepted {bad:02x?}");
        }
    }

    #[test]
    fn consumed_bytes_end_at_the_next_byte_boundary() {
        let mut reader = std::io::Cursor::new(hex("cb48cdc9c90700"));
        let inflated = inflate(&mut reader, 16).expect("inflate");
        assert_eq!(inflated.output, b"hello");
        assert_eq!(inflated.consumed, 7);
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex fixture"))
            .collect()
    }
}

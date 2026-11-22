//! M1.2 (6.2.0): bounded GZIP reader for [`crate::archive_scan`].
//!
//! One or more RFC 1952 members are decoded with the in-tree raw-DEFLATE
//! decoder, each member is charged against the global expansion budget and
//! re-scanned, and the decoded bytes are handed back to the recursive inspector
//! (so `payload.tar.gz` is unwrapped to `payload.tar` and inspected as TAR).
//! Trailing bytes that are not another GZIP member are fail-closed malformed.

use crate::archive_scan::{ArchiveError, Finding, Inspector};
use crate::archive_deflate::{inflate, DeflateError};
use std::io::{Read, Seek, SeekFrom};

const GZIP_MAGIC: &[u8; 2] = b"\x1f\x8b";
/// Hard cap for one GZIP header extension; a larger one is malformed.
const MAX_HEADER_EXTENSION_BYTES: u64 = 4 * 1024 * 1024;

/// Inspects one GZIP stream from `reader` (whole-file or member slice).
pub(crate) fn inspect<R: Read + Seek>(
    inspector: &mut Inspector<'_>,
    reader: &mut R,
) -> Result<Option<Finding>, ArchiveError> {
    loop {
        let mut header = [0u8; 10];
        if reader.read_exact(&mut header).is_err() {
            return Err(ArchiveError::Malformed("gzip header truncated"));
        }
        if &header[..2] != GZIP_MAGIC {
            return Err(ArchiveError::Malformed("gzip magic"));
        }
        if header[2] != 8 {
            return Err(ArchiveError::Unsupported("gzip compression method"));
        }
        let flags = header[3];
        if flags & 0x04 != 0 {
            let mut extra = [0u8; 2];
            reader
                .read_exact(&mut extra)
                .map_err(|_| ArchiveError::Malformed("gzip extra truncation"))?;
            skip_bounded(reader, u16::from_le_bytes(extra) as u64)?;
        }
        if flags & 0x08 != 0 {
            skip_c_string(reader)?;
        }
        if flags & 0x10 != 0 {
            skip_c_string(reader)?;
        }
        if flags & 0x02 != 0 {
            skip_bounded(reader, 2)?;
        }
        let data_start = reader
            .stream_position()
            .map_err(|_| ArchiveError::Malformed("gzip position"))?;
        // Inflate one member. `consumed` locates the 8-byte trailer.
        let inflated = match inflate(reader, crate::archive_scan::MAX_TOTAL_EXPANDED as usize) {
            Ok(inflated) => inflated,
            Err(DeflateError::OutputLimitExceeded) => return Err(ArchiveError::ExpandedLimit),
            Err(_) => return Err(ArchiveError::Malformed("gzip deflate stream")),
        };
        let trailer_start = data_start
            .checked_add(inflated.consumed)
            .ok_or(ArchiveError::Malformed("gzip offset overflow"))?;
        reader
            .seek(SeekFrom::Start(trailer_start))
            .map_err(|_| ArchiveError::Malformed("gzip trailer seek"))?;
        let mut trailer = [0u8; 8];
        reader
            .read_exact(&mut trailer)
            .map_err(|_| ArchiveError::Malformed("gzip trailer"))?;
        let isize = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
        if isize != 0 && u64::from(isize) != (inflated.output.len() as u32) as u64 {
            return Err(ArchiveError::Malformed("gzip ISIZE mismatch"));
        }
        inspector.charge_expanded(inflated.output.len())?;
        if let Some(finding) = inspector.scan_member(&inflated.output)? {
            return Ok(Some(finding));
        }
        // Another member? Probe two bytes and rewind if they are a GZIP magic;
        // any other trailing data is fail-closed uninspectable.
        let next = reader
            .stream_position()
            .map_err(|_| ArchiveError::Malformed("gzip position"))?;
        let mut probe = [0u8; 2];
        let read = reader.read(&mut probe).unwrap_or(0);
        if read == 0 {
            return Ok(None);
        }
        reader
            .seek(SeekFrom::Start(next))
            .map_err(|_| ArchiveError::Malformed("gzip rewind"))?;
        if read < 2 || &probe != GZIP_MAGIC {
            return Err(ArchiveError::Malformed("gzip trailing data"));
        }
    }
}

fn skip_bounded<R: Read>(reader: &mut R, length: u64) -> Result<(), ArchiveError> {
    if length > MAX_HEADER_EXTENSION_BYTES {
        return Err(ArchiveError::Malformed("gzip header extension oversized"));
    }
    let mut remaining = length;
    let mut buffer = [0u8; 512];
    while remaining > 0 {
        let wanted = remaining.min(buffer.len() as u64) as usize;
        reader
            .read_exact(&mut buffer[..wanted])
            .map_err(|_| ArchiveError::Malformed("gzip header skip"))?;
        remaining -= wanted as u64;
    }
    Ok(())
}

fn skip_c_string<R: Read>(reader: &mut R) -> Result<(), ArchiveError> {
    let mut byte = [0u8; 1];
    for _ in 0..4096 {
        reader
            .read_exact(&mut byte)
            .map_err(|_| ArchiveError::Malformed("gzip header string"))?;
        if byte[0] == 0 {
            return Ok(());
        }
    }
    Err(ArchiveError::Malformed("gzip header string oversized"))
}

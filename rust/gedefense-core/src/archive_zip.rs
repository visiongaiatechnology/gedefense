//! M1.2 (6.2.0): bounded ZIP reader for [`crate::archive_scan`].
//!
//! Supports the two storage methods that matter on Linux (stored and deflate),
//! random-access central-directory parsing with 32-bit offsets, and rejects
//! everything it cannot inspect (ZIP64, encryption, other methods, unsafe names)
//! as a bounded `ArchiveError` instead of silently skipping members.

use crate::archive_scan::{safe_entry_name, ArchiveError, Finding, Inspector};
use std::io::{Cursor, Read, Seek, SeekFrom};

// Shared budgets keep this module free of a second definition.
use crate::archive_scan::{MAX_ENTRIES, MAX_ENTRY_BYTES, MAX_RATIO};

const EOCD_SEARCH_BYTES: u64 = 64 * 1024 + 22;
/// Hard cap for one central directory (10 000 entries need ~460 KiB minimum).
const MAX_CENTRAL_DIRECTORY_BYTES: u64 = 4 * 1024 * 1024;
const ZIP_EOCD: &[u8; 4] = b"PK\x05\x06";
const ZIP_CENTRAL: &[u8; 4] = b"PK\x01\x02";
const ZIP_LOCAL: &[u8; 4] = b"PK\x03\x04";

/// Inspects one ZIP archive from `reader` (whole-file or member slice).
pub(crate) fn inspect<R: Read + Seek>(
    inspector: &mut Inspector<'_>,
    reader: &mut R,
    size: u64,
) -> Result<Option<Finding>, ArchiveError> {
    if size < 22 {
        return Err(ArchiveError::Malformed("zip shorter than EOCD"));
    }
    let search = size.min(EOCD_SEARCH_BYTES);
    let mut tail = vec![0u8; search as usize];
    reader
        .seek(SeekFrom::Start(size - search))
        .map_err(|_| ArchiveError::Malformed("zip tail seek"))?;
    reader
        .read_exact(&mut tail)
        .map_err(|_| ArchiveError::Malformed("zip tail read"))?;
    let eocd = tail
        .windows(4)
        .rposition(|window| window == ZIP_EOCD)
        .ok_or(ArchiveError::Malformed("zip EOCD missing"))?;
    if eocd + 22 > tail.len() {
        return Err(ArchiveError::Malformed("zip EOCD truncated"));
    }
    let record = &tail[eocd..];
    let entries = u16::from_le_bytes([record[10], record[11]]) as u64;
    let directory_size = u32::from_le_bytes([record[12], record[13], record[14], record[15]]);
    let directory_offset = u32::from_le_bytes([record[16], record[17], record[18], record[19]]);
    // ZIP64 markers cannot be inspected with the bounded 32-bit parser; a
    // nested ZIP64 is fail-closed suspicious, never silently skipped.
    if entries == u64::from(u16::MAX) || directory_size == u32::MAX || directory_offset == u32::MAX
    {
        return Err(ArchiveError::Unsupported("zip64 directory"));
    }
    if entries > MAX_ENTRIES {
        return Err(ArchiveError::EntryLimit);
    }
    if directory_size as u64 > MAX_CENTRAL_DIRECTORY_BYTES {
        return Err(ArchiveError::EntryLimit);
    }
    let directory_start = directory_offset as u64;
    if directory_start + directory_size as u64 > size {
        return Err(ArchiveError::Malformed("zip central directory outside file"));
    }
    let mut directory = vec![0u8; directory_size as usize];
    reader
        .seek(SeekFrom::Start(directory_start))
        .map_err(|_| ArchiveError::Malformed("zip directory seek"))?;
    reader
        .read_exact(&mut directory)
        .map_err(|_| ArchiveError::Malformed("zip directory read"))?;
    let mut offset = 0usize;
    for _ in 0..entries {
        if directory.get(offset..offset + ZIP_CENTRAL.len()) != Some(&ZIP_CENTRAL[..]) {
            return Err(ArchiveError::Malformed("zip central header magic"));
        }
        let entry = &directory[offset..];
        let flags = u16::from_le_bytes([entry[8], entry[9]]);
        let method = u16::from_le_bytes([entry[10], entry[11]]);
        let compressed = u32::from_le_bytes([entry[20], entry[21], entry[22], entry[23]]) as u64;
        let expanded = u32::from_le_bytes([entry[24], entry[25], entry[26], entry[27]]) as u64;
        let name_len = u16::from_le_bytes([entry[28], entry[29]]) as usize;
        let extra_len = u16::from_le_bytes([entry[30], entry[31]]) as usize;
        let comment_len = u16::from_le_bytes([entry[32], entry[33]]) as usize;
        let local_offset = u32::from_le_bytes([entry[42], entry[43], entry[44], entry[45]]) as u64;
        let name_end = 46 + name_len;
        let whole = name_end + extra_len + comment_len;
        if entry.len() < whole {
            return Err(ArchiveError::Malformed("zip central entry truncated"));
        }
        let name = &entry[46..name_end];
        inspector.count_entry()?;
        if flags & 0x0001 != 0 {
            return Err(ArchiveError::Unsupported("encrypted zip entry"));
        }
        if flags & 0x0040 != 0 {
            return Err(ArchiveError::Unsupported("zip strong encryption"));
        }
        if !safe_entry_name(name) {
            return Err(ArchiveError::UnsafePath);
        }
        if compressed > MAX_ENTRY_BYTES || expanded > MAX_ENTRY_BYTES {
            return Err(ArchiveError::EntrySize);
        }
        if compressed > 0 && expanded / compressed.max(1) > MAX_RATIO {
            return Err(ArchiveError::Ratio);
        }
        if !matches!(method, 0 | 8) {
            return Err(ArchiveError::Unsupported("zip compression method"));
        }
        if local_offset + 30 > size {
            return Err(ArchiveError::Malformed("zip local header outside file"));
        }
        let mut local = [0u8; 30];
        reader
            .seek(SeekFrom::Start(local_offset))
            .map_err(|_| ArchiveError::Malformed("zip local seek"))?;
        reader
            .read_exact(&mut local)
            .map_err(|_| ArchiveError::Malformed("zip local read"))?;
        if &local[..4] != ZIP_LOCAL {
            return Err(ArchiveError::Malformed("zip local header magic"));
        }
        let local_name = u16::from_le_bytes([local[26], local[27]]) as u64;
        let local_extra = u16::from_le_bytes([local[28], local[29]]) as u64;
        let data_start = local_offset + 30 + local_name + local_extra;
        if data_start + compressed > size {
            return Err(ArchiveError::Malformed("zip member data outside file"));
        }
        let mut data = vec![0u8; compressed as usize];
        reader
            .seek(SeekFrom::Start(data_start))
            .map_err(|_| ArchiveError::Malformed("zip data seek"))?;
        reader
            .read_exact(&mut data)
            .map_err(|_| ArchiveError::Malformed("zip data read"))?;
        let member = if method == 0 {
            data
        } else {
            let mut cursor = Cursor::new(data.as_slice());
            match crate::archive_deflate::inflate(
                &mut cursor,
                expanded.min(MAX_ENTRY_BYTES) as usize + 1,
            ) {
                Ok(inflated) => inflated.output,
                Err(crate::archive_deflate::DeflateError::OutputLimitExceeded) => {
                    return Err(ArchiveError::ExpandedLimit)
                }
                Err(_) => return Err(ArchiveError::Malformed("zip deflate stream")),
            }
        };
        if member.len() as u64 != expanded {
            return Err(ArchiveError::Malformed("zip member size mismatch"));
        }
        inspector.charge_expanded(member.len())?;
        if let Some(finding) = inspector.scan_member(&member)? {
            return Ok(Some(finding));
        }
        offset += whole;
    }
    Ok(None)
}

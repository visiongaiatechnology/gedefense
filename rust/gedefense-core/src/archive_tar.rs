//! M1.2 (6.2.0): bounded TAR reader for [`crate::archive_scan`].
//!
//! Handles ustar/GNU headers (checksum-verified), regular files, directories,
//! symlink/hardlink targets and the PAX/GNU long-name extensions; every special
//! member (device, FIFO, sparse, unknown type) is fail-closed uninspectable.
//! Member data is charged against the global budget and re-scanned, and a member
//! that is itself an archive recurses through [`Inspector::scan_member`].

use crate::archive_scan::{safe_entry_name, ArchiveError, Finding, Inspector, MAX_TOTAL_EXPANDED};
use std::fs::File;
use std::io::Read;

const TAR_MAGIC_OFFSET: usize = 257;
const TAR_MAGIC: &[u8; 5] = b"ustar";
const TAR_HEADER_BYTES: u64 = 512;
const MAX_TAR_EXTENSION_BYTES: u64 = 64 * 1024;

/// Inspects a plain TAR file; the whole file is read only within the total
/// expansion budget, so a huge backup TAR is a bounded rejection.
pub(crate) fn inspect_file(
    inspector: &mut Inspector<'_>,
    file: &mut File,
    size: u64,
) -> Result<Option<Finding>, ArchiveError> {
    if size > MAX_TOTAL_EXPANDED {
        return Err(ArchiveError::ExpandedLimit);
    }
    let mut bytes = vec![0u8; size as usize];
    file.read_exact(&mut bytes)
        .map_err(|_| ArchiveError::Malformed("tar read"))?;
    inspect_bytes(inspector, &bytes)
}

/// Inspects TAR bytes (whole file or a decoded member).
pub(crate) fn inspect_bytes(
    inspector: &mut Inspector<'_>,
    bytes: &[u8],
) -> Result<Option<Finding>, ArchiveError> {
    let mut offset = 0usize;
    let mut pending_name: Option<Vec<u8>> = None;
    let mut zero_blocks = 0usize;
    while offset + TAR_HEADER_BYTES as usize <= bytes.len() {
        let header = &bytes[offset..offset + TAR_HEADER_BYTES as usize];
        if header.iter().all(|byte| *byte == 0) {
            zero_blocks += 1;
            offset += TAR_HEADER_BYTES as usize;
            if zero_blocks >= 2 {
                break;
            }
            continue;
        }
        zero_blocks = 0;
        if &header[TAR_MAGIC_OFFSET..TAR_MAGIC_OFFSET + TAR_MAGIC.len()] != TAR_MAGIC {
            return Err(ArchiveError::Malformed("tar magic"));
        }
        verify_checksum(header)?;
        let type_flag = header[156];
        let size = parse_size(&header[124..136])?;
        if size > crate::archive_scan::MAX_ENTRY_BYTES
            && !matches!(type_flag, b'x' | b'g' | b'L' | b'K')
        {
            return Err(ArchiveError::EntrySize);
        }
        let data_start = offset + TAR_HEADER_BYTES as usize;
        let padded = size
            .checked_add(TAR_HEADER_BYTES - 1)
            .map(|value| value / TAR_HEADER_BYTES * TAR_HEADER_BYTES)
            .ok_or(ArchiveError::Malformed("tar size overflow"))?;
        let next = data_start
            .checked_add(padded as usize)
            .ok_or(ArchiveError::Malformed("tar offset overflow"))?;
        if next > bytes.len() {
            return Err(ArchiveError::Malformed("tar member outside archive"));
        }
        let data = &bytes[data_start..data_start + size as usize];
        match type_flag {
            b'0' | 0 => {
                inspector.count_entry()?;
                if !safe_entry_name(header_name(header, pending_name.as_deref())) {
                    return Err(ArchiveError::UnsafePath);
                }
                pending_name = None;
                inspector.charge_expanded(data.len())?;
                if let Some(finding) = inspector.scan_member(data)? {
                    return Ok(Some(finding));
                }
            }
            b'5' => {
                inspector.count_entry()?;
                if !safe_entry_name(header_name(header, pending_name.as_deref())) {
                    return Err(ArchiveError::UnsafePath);
                }
                pending_name = None;
            }
            b'1' | b'2' => {
                inspector.count_entry()?;
                if !safe_entry_name(header_name(header, pending_name.as_deref()))
                    || !safe_link_target(&header[157..257])
                {
                    return Err(ArchiveError::UnsafePath);
                }
                pending_name = None;
            }
            b'x' | b'g' => {
                if size > MAX_TAR_EXTENSION_BYTES {
                    return Err(ArchiveError::EntrySize);
                }
                if let Some(name) = pax_path(data) {
                    if !safe_entry_name(&name) {
                        return Err(ArchiveError::UnsafePath);
                    }
                    pending_name = Some(name);
                }
            }
            b'L' => {
                if size > MAX_TAR_EXTENSION_BYTES {
                    return Err(ArchiveError::EntrySize);
                }
                let name = trim_trailing_nul(data).to_vec();
                if !safe_entry_name(&name) {
                    return Err(ArchiveError::UnsafePath);
                }
                pending_name = Some(name);
            }
            b'K' => {}
            _ => return Err(ArchiveError::Unsupported("tar special member")),
        }
        offset = next;
    }
    Ok(None)
}

fn safe_link_target(target: &[u8]) -> bool {
    let trimmed = trim_trailing_nul(target);
    if trimmed.is_empty() || trimmed.starts_with(b"/") || trimmed.contains(&0) {
        return false;
    }
    trimmed
        .split(|byte| *byte == b'/')
        .all(|component| component != b"..")
}

fn header_name<'a>(header: &'a [u8], pending: Option<&'a [u8]>) -> &'a [u8] {
    if let Some(pending) = pending {
        return pending;
    }
    let raw = &header[..100];
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    &raw[..end]
}

fn trim_trailing_nul(value: &[u8]) -> &[u8] {
    let end = value.iter().position(|byte| *byte == 0).unwrap_or(value.len());
    &value[..end]
}

fn pax_path(data: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0usize;
    while offset < data.len() {
        let space = data[offset..].iter().position(|byte| *byte == b' ')? + offset;
        let length: usize = std::str::from_utf8(&data[offset..space]).ok()?.parse().ok()?;
        if length == 0 || offset + length > data.len() {
            return None;
        }
        let record = &data[space + 1..offset + length];
        let record = record.strip_suffix(b"\n").unwrap_or(record);
        if let Some(path) = record.strip_prefix(b"path=") {
            return Some(path.to_vec());
        }
        offset += length;
    }
    None
}

fn parse_size(field: &[u8]) -> Result<u64, ArchiveError> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(ArchiveError::Unsupported("tar base-256 size"));
    }
    let text = std::str::from_utf8(field).map_err(|_| ArchiveError::Malformed("tar size utf8"))?;
    let text = text.trim_matches(|character| character == '\0' || character == ' ');
    if text.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(text, 8).map_err(|_| ArchiveError::Malformed("tar size octal"))
}

fn verify_checksum(header: &[u8]) -> Result<(), ArchiveError> {
    let stored = parse_size(&header[148..156])?;
    let mut sum = 0u64;
    for (index, byte) in header.iter().enumerate() {
        sum += if (148..156).contains(&index) {
            u64::from(b' ')
        } else {
            u64::from(*byte)
        };
    }
    if sum != stored {
        return Err(ArchiveError::Malformed("tar checksum"));
    }
    Ok(())
}

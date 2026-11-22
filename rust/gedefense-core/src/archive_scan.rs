//! M1.2 (6.2.0): bounded recursive archive inspection for the malware scanner.
//!
//! The pre-existing `archive_violation` check in `malware.rs` only inspected the
//! ZIP central directory and the GZIP trailer of the *outer* file for expansion
//! bombs. An attacker could therefore smuggle a payload inside a nested archive
//! (ZIP -> GZIP -> TAR), because nothing ever decompressed a member. This module
//! owns the recursive inspection state and orchestrates the three format
//! readers ([`crate::archive_zip`], [`crate::archive_gzip`],
//! [`crate::archive_tar`]): every decoded member is re-scanned for the EICAR
//! signature and the configured SHA-256 signature database, and a member that is
//! itself a supported archive is recursed into.
//!
//! Hard bounds make a decompression bomb a bounded rejection, not an OOM:
//! `MAX_DEPTH` (8), `MAX_ENTRY_BYTES` (16 MiB), `MAX_TOTAL_EXPANDED` (64 MiB),
//! `MAX_ENTRIES` (10 000) and `MAX_RATIO` (200:1). Unsafe member paths
//! (absolute, `..` traversal, backslashes, drive prefixes) and unsafe link
//! targets are rejected as suspicious. Unsupported nested containers (encrypted
//! ZIP entries, ZIP64, BZIP2/XZ/7z/RAR/ZSTD members, TAR special files) are
//! fail-closed suspicious: an archive we cannot look inside is never reported
//! clean. A malformed *outer* archive is likewise suspicious; that is deliberate
//! (a corrupt archive that other extractors accept must not become a bypass).
//!
//! The module is pure with respect to policy: it returns `Finding`s and never
//! deletes, moves or blocks anything. `malware.rs` maps them to a
//! `ScanVerdict` (state `malicious` for signature hits, `suspicious` for every
//! bounded/unsafe structure) and keeps the on-access/on-write action separate.

use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
};

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Nested-archive recursion depth (documented budget of M1.2).
pub(crate) const MAX_DEPTH: u8 = 8;
/// Maximum decoded size of one archive member.
pub(crate) const MAX_ENTRY_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum decoded size across one inspection (all depths).
pub(crate) const MAX_TOTAL_EXPANDED: u64 = 64 * 1024 * 1024;
/// Maximum number of members across one inspection (all depths).
pub(crate) const MAX_ENTRIES: u64 = 10_000;
/// Expansion ratio ceiling of a single member (kept from the pre-existing
/// `ARCHIVE_RATIO_LIMIT` contract in `malware.rs`).
pub(crate) const MAX_RATIO: u64 = 200;
const ZIP_LOCAL_MAGIC: &[u8; 4] = b"PK\x03\x04";
const GZIP_MAGIC: &[u8; 2] = b"\x1f\x8b";
const TAR_MAGIC_OFFSET: usize = 257;
const TAR_MAGIC: &[u8; 5] = b"ustar";

/// One scanner finding: `malicious` findings carry a signature identifier and
/// are the only ones the on-write sensor may quarantine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Finding {
    pub(crate) malicious: bool,
    pub(crate) reason: String,
}

/// Bounded structural rejection; every variant becomes a suspicious finding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArchiveError {
    Depth,
    EntryLimit,
    EntrySize,
    ExpandedLimit,
    Ratio,
    UnsafePath,
    Unsupported(&'static str),
    Malformed(&'static str),
}

impl ArchiveError {
    fn reason(self) -> String {
        match self {
            ArchiveError::Depth => "nested-archive-depth",
            ArchiveError::EntryLimit => "nested-archive-entry-limit",
            ArchiveError::EntrySize => "nested-archive-entry-size",
            ArchiveError::ExpandedLimit => "nested-archive-expanded-limit",
            ArchiveError::Ratio => "nested-archive-ratio",
            ArchiveError::UnsafePath => "nested-archive-unsafe-path",
            // One stable reason keeps the control-plane alert taxonomy small;
            // the specific structural detail is in the stderr diagnostics.
            ArchiveError::Unsupported(_) => "nested-archive-uninspectable",
            ArchiveError::Malformed(_) => "archive-malformed",
        }
        .to_owned()
    }
}

/// Inspection state shared across the recursion: signature database, EICAR
/// pattern, hard budgets and the current depth.
pub(crate) struct Inspector<'a> {
    eicar: &'a [u8],
    signature: &'a dyn Fn(&[u8; 32]) -> Option<String>,
    entries: u64,
    expanded: u64,
    depth: u8,
}

/// Inspects one archive file. `Ok(None)` means the file is not a supported
/// archive (nothing claimed to inspect); `Ok(Some(finding))` is a result;
/// `Err` only for I/O failures of the scan itself.
pub(crate) fn inspect(
    file: &mut File,
    size: u64,
    eicar: &[u8],
    signature: &dyn Fn(&[u8; 32]) -> Option<String>,
) -> Result<Option<Finding>, BoxError> {
    if eicar.is_empty() || size < 16 {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(0))?;
    let mut header = [0u8; 1024];
    let read = read_up_to(file, &mut header)?;
    file.seek(SeekFrom::Start(0))?;
    let mut inspector = Inspector {
        eicar,
        signature,
        entries: 0,
        expanded: 0,
        depth: 0,
    };
    let result = if header.starts_with(ZIP_LOCAL_MAGIC) {
        crate::archive_zip::inspect(&mut inspector, file, size)
    } else if header.starts_with(GZIP_MAGIC) {
        crate::archive_gzip::inspect(&mut inspector, file)
    } else if read >= TAR_MAGIC_OFFSET + TAR_MAGIC.len()
        && &header[TAR_MAGIC_OFFSET..TAR_MAGIC_OFFSET + TAR_MAGIC.len()] == TAR_MAGIC
    {
        crate::archive_tar::inspect_file(&mut inspector, file, size)
    } else {
        return Ok(None);
    };
    Ok(match result {
        Ok(finding) => finding,
        Err(error) => {
            if let ArchiveError::Unsupported(detail) | ArchiveError::Malformed(detail) = error {
                eprintln!("GeDefense archive inspection rejected: {detail}");
            }
            Some(Finding {
                malicious: false,
                reason: error.reason(),
            })
        }
    })
}

impl<'a> Inspector<'a> {
    /// Counts one member against the global entry budget.
    pub(crate) fn count_entry(&mut self) -> Result<(), ArchiveError> {
        self.entries = self.entries.saturating_add(1);
        if self.entries > MAX_ENTRIES {
            return Err(ArchiveError::EntryLimit);
        }
        Ok(())
    }

    /// Charges one decoded member against the total expansion budget.
    pub(crate) fn charge_expanded(&mut self, bytes: usize) -> Result<(), ArchiveError> {
        self.expanded = self.expanded.saturating_add(bytes as u64);
        if self.expanded > MAX_TOTAL_EXPANDED {
            return Err(ArchiveError::ExpandedLimit);
        }
        Ok(())
    }

    /// Re-scans one decoded member: signature first, then EICAR, then a nested
    /// archive recursion. Returns the first finding.
    pub(crate) fn scan_member(&mut self, bytes: &[u8]) -> Result<Option<Finding>, ArchiveError> {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        if let Some(identifier) = (self.signature)(&digest) {
            return Ok(Some(Finding {
                malicious: true,
                reason: identifier,
            }));
        }
        if bytes
            .windows(self.eicar.len())
            .any(|window| window == self.eicar)
        {
            return Ok(Some(Finding {
                malicious: true,
                reason: "nested-eicar-signature".to_owned(),
            }));
        }
        match archive_kind(bytes) {
            Some(Kind::Zip) => {
                self.descend()?;
                let mut cursor = std::io::Cursor::new(bytes);
                let size = bytes.len() as u64;
                let result = crate::archive_zip::inspect(self, &mut cursor, size);
                self.depth -= 1;
                result
            }
            Some(Kind::Gzip) => {
                self.descend()?;
                let mut cursor = std::io::Cursor::new(bytes);
                let result = crate::archive_gzip::inspect(self, &mut cursor);
                self.depth -= 1;
                result
            }
            Some(Kind::Tar) => {
                self.descend()?;
                let result = crate::archive_tar::inspect_bytes(self, bytes);
                self.depth -= 1;
                result
            }
            Some(Kind::Unsupported(detail)) => Err(ArchiveError::Unsupported(detail)),
            None => Ok(None),
        }
    }

    fn descend(&mut self) -> Result<(), ArchiveError> {
        if self.depth >= MAX_DEPTH {
            return Err(ArchiveError::Depth);
        }
        self.depth += 1;
        Ok(())
    }
}

/// Archive format sniffing of one decoded member.
enum Kind {
    Zip,
    Gzip,
    Tar,
    Unsupported(&'static str),
}

fn archive_kind(bytes: &[u8]) -> Option<Kind> {
    if bytes.starts_with(ZIP_LOCAL_MAGIC) {
        return Some(Kind::Zip);
    }
    if bytes.starts_with(GZIP_MAGIC) {
        return Some(Kind::Gzip);
    }
    if bytes.len() >= TAR_MAGIC_OFFSET + TAR_MAGIC.len()
        && &bytes[TAR_MAGIC_OFFSET..TAR_MAGIC_OFFSET + TAR_MAGIC.len()] == TAR_MAGIC
    {
        return Some(Kind::Tar);
    }
    for (magic, label) in [
        (&b"BZh"[..], "bzip2 member"),
        (&b"\xfd7zXZ\x00"[..], "xz member"),
        (&b"7z\xbc\xaf\x27\x1c"[..], "7z member"),
        (&b"Rar!"[..], "rar member"),
        (&b"\x28\xb5\x2f\xfd"[..], "zstd member"),
    ] {
        if bytes.starts_with(magic) {
            return Some(Kind::Unsupported(label));
        }
    }
    None
}

/// Rejects absolute paths, `..`/`.` components, backslashes, NUL bytes and drive
/// prefixes. ZIP and TAR names share this check (Linux extraction must never be
/// able to escape the destination directory).
pub(crate) fn safe_entry_name(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > 4096 || name.contains(&0) {
        return false;
    }
    let trimmed = name.strip_suffix(b"/").unwrap_or(name);
    if trimmed.is_empty() || trimmed.starts_with(b"/") || trimmed.contains(&b'\\') {
        return false;
    }
    if trimmed.len() >= 2 && trimmed[1] == b':' {
        return false;
    }
    trimmed
        .split(|byte| *byte == b'/')
        .all(|component| !component.is_empty() && component != b".." && component != b".")
}

fn read_up_to<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<usize, BoxError> {
    let mut total = 0;
    while total < buffer.len() {
        let count = reader.read(&mut buffer[total..])?;
        if count == 0 {
            break;
        }
        total += count;
    }
    Ok(total)
}

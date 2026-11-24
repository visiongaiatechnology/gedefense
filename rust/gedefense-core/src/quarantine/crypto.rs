use super::*;

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::{
    ffi::{CStr, CString},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, RawFd},
        unix::fs::OpenOptionsExt,
    },
};

type HmacSha256 = Hmac<Sha256>;

const MAGIC: &[u8; 8] = b"VGTQV1\0\0";
pub(super) const HEADER_BYTES: usize = 92;
pub(super) const CHUNK_BYTES: usize = 1024 * 1024;

impl QuarantineBroker {
    pub(super) fn encrypt_staged(
        &self,
        parent_fd: RawFd,
        staging_name: &CStr,
        object_id: &str,
        expected: &FileIdentity,
    ) -> Result<(), BoxError> {
        let source_fd = open_regular_at(parent_fd, staging_name)?;
        let mut source = File::from(source_fd);
        self.encrypt_open_source(&mut source, object_id, expected)
    }

    pub(super) fn encrypt_open_source(
        &self,
        source: &mut File,
        object_id: &str,
        expected: &FileIdentity,
    ) -> Result<(), BoxError> {
        source.seek(SeekFrom::Start(0))?;
        let temporary_path = self.object_dir.join(format!(".{object_id}.tmp"));
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temporary_path)?;
        let result = (|| {
            let nonce_prefix = random_nonce_prefix()?;
            let header = encode_header(expected, nonce_prefix);
            output.write_all(&header)?;
            let mut key = self.object_key(object_id)?;
            let encryption_result = (|| {
                let cipher = Aes256Gcm::new_from_slice(&key)
                    .map_err(|_| "quarantine cipher initialization failed")?;
                let mut remaining = expected.size;
                let mut index = 0u32;
                let mut digest = Sha256::new();
                loop {
                    let length = usize::try_from(remaining.min(CHUNK_BYTES as u64))?;
                    let mut chunk = vec![0u8; length];
                    if length > 0 {
                        source.read_exact(&mut chunk)?;
                        digest.update(&chunk);
                    }
                    let aad = chunk_aad(&header, index, length as u32);
                    let nonce_bytes = chunk_nonce(nonce_prefix, index);
                    let tag = cipher
                        .encrypt_in_place_detached(
                            Nonce::from_slice(&nonce_bytes),
                            &aad,
                            &mut chunk,
                        )
                        .map_err(|_| "quarantine chunk encryption failed")?;
                    output.write_all(&(length as u32).to_le_bytes())?;
                    output.write_all(&chunk)?;
                    output.write_all(tag.as_slice())?;
                    remaining = remaining.saturating_sub(length as u64);
                    index = index
                        .checked_add(1)
                        .ok_or("quarantine chunk counter exhausted")?;
                    if remaining == 0 {
                        break;
                    }
                }
                if digest.finalize().as_slice() != expected.sha256 {
                    return Err("quarantine source changed during encryption".into());
                }
                let mut extra = [0u8; 1];
                if source.read(&mut extra)? != 0 {
                    return Err("quarantine source grew during encryption".into());
                }
                Ok::<(), BoxError>(())
            })();
            key.fill(0);
            encryption_result?;
            output.sync_all()?;
            drop(output);
            let directory = File::open(&self.object_dir)?;
            let temporary_name = CString::new(format!(".{object_id}.tmp"))?;
            let object_name = CString::new(format!("{object_id}.qv"))?;
            rename_noreplace(
                directory.as_raw_fd(),
                &temporary_name,
                directory.as_raw_fd(),
                &object_name,
            )?;
            sync_directory(&self.object_dir)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result
    }

    pub(super) fn decrypt_object<W: Write>(
        &self,
        object_id: &str,
        expected: &FileIdentity,
        output: &mut W,
    ) -> Result<u64, BoxError> {
        let path = self.object_path(object_id)?;
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("quarantine object must be a regular non-symlink file".into());
        }
        if metadata.len() > MAX_FILE_BYTES + (MAX_FILE_BYTES / CHUNK_BYTES as u64 + 1) * 24 + 4096 {
            return Err("quarantine object exceeds encrypted size boundary".into());
        }
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)?;
        let mut header = [0u8; HEADER_BYTES];
        input.read_exact(&mut header)?;
        let (stored, nonce_prefix) = decode_header(&header)?;
        if expected != &stored {
            return Err("quarantine object header binding mismatch".into());
        }
        let mut key = self.object_key(object_id)?;
        let decryption_result = (|| {
            let cipher = Aes256Gcm::new_from_slice(&key)
                .map_err(|_| "quarantine cipher initialization failed")?;
            let mut remaining = stored.size;
            let mut index = 0u32;
            let mut digest = Sha256::new();
            loop {
                let mut length_bytes = [0u8; 4];
                input.read_exact(&mut length_bytes)?;
                let length = u32::from_le_bytes(length_bytes) as usize;
                let expected_length = usize::try_from(remaining.min(CHUNK_BYTES as u64))?;
                if length != expected_length {
                    return Err("quarantine chunk length mismatch".into());
                }
                let mut chunk = vec![0u8; length];
                input.read_exact(&mut chunk)?;
                let mut tag = [0u8; 16];
                input.read_exact(&mut tag)?;
                let aad = chunk_aad(&header, index, length as u32);
                let nonce_bytes = chunk_nonce(nonce_prefix, index);
                cipher
                    .decrypt_in_place_detached(
                        Nonce::from_slice(&nonce_bytes),
                        &aad,
                        &mut chunk,
                        aes_gcm::Tag::from_slice(&tag),
                    )
                    .map_err(|_| "quarantine chunk authentication failed")?;
                output.write_all(&chunk)?;
                digest.update(&chunk);
                remaining = remaining.saturating_sub(length as u64);
                index = index
                    .checked_add(1)
                    .ok_or("quarantine chunk counter exhausted")?;
                if remaining == 0 {
                    break;
                }
            }
            let mut trailing = [0u8; 1];
            if input.read(&mut trailing)? != 0 || digest.finalize().as_slice() != expected.sha256 {
                return Err("quarantine object digest or trailing-data verification failed".into());
            }
            Ok::<(), BoxError>(())
        })();
        key.fill(0);
        decryption_result?;
        Ok(stored.size)
    }

    fn object_key(&self, object_id: &str) -> Result<[u8; 32], BoxError> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.storage_key)?;
        mac.update(b"VGT-GEDEFENSE-QUARANTINE-OBJECT-KEY-V1\0");
        mac.update(object_id.as_bytes());
        let bytes = mac.finalize().into_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    }
}

fn random_nonce_prefix() -> Result<[u8; 8], BoxError> {
    let mut random = File::open("/dev/urandom")?;
    let mut prefix = [0u8; 8];
    random.read_exact(&mut prefix)?;
    Ok(prefix)
}

fn encode_header(identity: &FileIdentity, nonce_prefix: [u8; 8]) -> [u8; HEADER_BYTES] {
    let mut header = [0u8; HEADER_BYTES];
    header[0..8].copy_from_slice(MAGIC);
    header[8..16].copy_from_slice(&identity.size.to_le_bytes());
    header[16..20].copy_from_slice(&identity.mode.to_le_bytes());
    header[20..24].copy_from_slice(&identity.uid.to_le_bytes());
    header[24..28].copy_from_slice(&identity.gid.to_le_bytes());
    header[28..36].copy_from_slice(&identity.device.to_le_bytes());
    header[36..44].copy_from_slice(&identity.inode.to_le_bytes());
    header[44..52].copy_from_slice(&identity.modified_nanos.to_le_bytes());
    header[52..60].copy_from_slice(&nonce_prefix);
    header[60..92].copy_from_slice(&identity.sha256);
    header
}

pub(super) fn decode_header(header: &[u8; HEADER_BYTES]) -> Result<(FileIdentity, [u8; 8]), BoxError> {
    if &header[0..8] != MAGIC {
        return Err("quarantine object magic is invalid".into());
    }
    let size = u64::from_le_bytes(header[8..16].try_into()?);
    let mode = u32::from_le_bytes(header[16..20].try_into()?);
    let uid = u32::from_le_bytes(header[20..24].try_into()?);
    let gid = u32::from_le_bytes(header[24..28].try_into()?);
    let device = u64::from_le_bytes(header[28..36].try_into()?);
    let inode = u64::from_le_bytes(header[36..44].try_into()?);
    let modified_nanos = i64::from_le_bytes(header[44..52].try_into()?);
    if size > MAX_FILE_BYTES || mode > 0o7777 {
        return Err("quarantine object header exceeds typed bounds".into());
    }
    let mut nonce_prefix = [0u8; 8];
    nonce_prefix.copy_from_slice(&header[52..60]);
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&header[60..92]);
    Ok((
        FileIdentity {
            size,
            mode,
            uid,
            gid,
            device,
            inode,
            modified_nanos,
            sha256,
        },
        nonce_prefix,
    ))
}

pub(super) fn chunk_nonce(prefix: [u8; 8], index: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&prefix);
    nonce[8..12].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn chunk_aad(header: &[u8; HEADER_BYTES], index: u32, length: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_BYTES + 48);
    aad.extend_from_slice(b"VGT-GEDEFENSE-QUARANTINE-CHUNK-V1\0");
    aad.extend_from_slice(header);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&length.to_be_bytes());
    aad
}

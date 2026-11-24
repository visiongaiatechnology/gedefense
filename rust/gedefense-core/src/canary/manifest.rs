use super::*;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::OpenOptionsExt,
        },
    },
};

impl CanaryBroker {
    // -------------------------------------------------------------- manifest

    fn manifest_path(&self) -> Option<PathBuf> {
        self.roots.first().map(|root| root.join(MANIFEST_NAME))
    }

    pub(super) fn load_manifest(&self) {
        let Some(path) = self.manifest_path() else {
            return;
        };
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            return;
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() == 0
            || metadata.len() > MAX_MANIFEST_BYTES
        {
            eprintln!("GeDefense canary manifest rejected by type or size");
            return;
        }
        let Ok(file) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
        else {
            eprintln!("GeDefense canary manifest could not be opened");
            return;
        };
        let mut text = String::new();
        if file
            .take(MAX_MANIFEST_BYTES)
            .read_to_string(&mut text)
            .is_err()
        {
            eprintln!("GeDefense canary manifest is not valid UTF-8");
            return;
        }
        let mut loaded = 0usize;
        for line in text.lines() {
            if loaded >= MAX_REGISTERED_CANARIES {
                break;
            }
            let Some((digest_hex, rest)) = line.split_once(' ') else {
                continue;
            };
            let Some((mode_text, rest)) = rest.split_once(' ') else {
                continue;
            };
            let Some((canary_type, path_token)) = rest.split_once(' ') else {
                continue;
            };
            if !VALID_TYPES.contains(&canary_type) {
                continue;
            }
            let Ok(mode) = u32::from_str_radix(mode_text, 8) else {
                continue;
            };
            if !VALID_MODES.contains(&mode) {
                continue;
            }
            let Ok(digest_raw) = hex::decode(digest_hex) else {
                continue;
            };
            let Ok(digest) = <[u8; 32]>::try_from(digest_raw) else {
                continue;
            };
            let Ok(path) = decode_path_token(path_token) else {
                continue;
            };
            let Ok((root, relative)) = self.resolve_in_roots(&path) else {
                continue;
            };
            let Ok((parent_components, basename)) = split_relative(&relative) else {
                continue;
            };
            let Ok(parent) = open_canary_parent(&root, &parent_components, false) else {
                continue;
            };
            let Ok(name) = CString::new(basename.as_bytes()) else {
                continue;
            };
            let Ok(mut file) = open_regular_at(parent.as_raw_fd(), &name) else {
                continue;
            };
            let Ok(metadata) = file.metadata() else {
                continue;
            };
            if (metadata.mode() & 0o7777) != mode {
                continue;
            }
            let mut digest_now = Sha256::new();
            if std::io::copy(&mut file, &mut digest_now).is_err() {
                continue;
            }
            if digest_now.finalize().as_slice() != digest {
                continue;
            }
            if let Ok(mut records) = self.records.lock() {
                records.insert(
                    path.clone(),
                    CanaryRecord {
                        path,
                        canary_type: canary_type.to_owned(),
                        mode,
                        sha256: digest,
                    },
                );
                loaded += 1;
            }
        }
        if loaded > 0 {
            eprintln!("GeDefense canary broker recovered {loaded} registered decoy(s)");
        }
    }

    pub(super) fn persist_manifest(&self) -> Result<(), BoxError> {
        let Some(directory) = self.roots.first().cloned() else {
            return Ok(());
        };
        let records = {
            let records = self
                .records
                .lock()
                .map_err(|_| "canary registry integrity failure")?;
            records.values().cloned().collect::<Vec<_>>()
        };
        let mut text = String::new();
        for record in records {
            let path_token = URL_SAFE_NO_PAD.encode(record.path.as_os_str().as_bytes());
            text.push_str(&format!(
                "{} {:o} {} {}\n",
                hex::encode(record.sha256),
                record.mode,
                record.canary_type,
                path_token
            ));
        }
        let staging_name = format!(".canary-manifest.{}.tmp", random_hex(8)?);
        let staging_path = directory.join(&staging_name);
        let final_path = directory.join(MANIFEST_NAME);
        let write = (|| -> Result<(), BoxError> {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&staging_path)?;
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
            drop(file);
            fs::rename(&staging_path, &final_path)?;
            if let Ok(directory_file) = File::open(&directory) {
                let _ = directory_file.sync_all();
            }
            Ok(())
        })();
        if write.is_err() {
            let _ = fs::remove_file(&staging_path);
        }
        write
    }
}

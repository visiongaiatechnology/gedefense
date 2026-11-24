use super::*;

impl ExecInodeCore {
    /// `MALWARE_INODE_LOCK <dev> <ino> <ttl_seconds>`.
    pub(crate) fn lock_malware_inode(
        &mut self,
        dev: &str,
        ino: &str,
        ttl: &str,
    ) -> Result<String, BoxError> {
        let dev = parse_dev_token(dev)?;
        let ino = parse_ino_token(ino)?;
        let ttl = parse_ttl_token(ttl)?;
        let key = exec_inode_key(dev, ino);
        if self.ttl_locks.contains_key(&key) {
            return Err("inode is already TTL-locked".into());
        }
        if self.ttl_locks.len() >= EXEC_INODE_MAX_TTL_LOCKS {
            return Err("exec-inode TTL lock capacity exhausted".into());
        }
        // Insert the kernel-side carrier first; the in-memory deadline only
        // starts once the map accepted the lock.
        self.ttl.insert(&key, ttl, 0)?;
        self.ttl_locks
            .insert(key, Instant::now() + Duration::from_secs(u64::from(ttl)));
        Ok("locked".to_owned())
    }
}

impl ExecInodeCore {
    /// `MALWARE_INODE_UNLOCK <dev> <ino>`.
    pub(crate) fn unlock_malware_inode(
        &mut self,
        dev: &str,
        ino: &str,
    ) -> Result<String, BoxError> {
        let dev = parse_dev_token(dev)?;
        let ino = parse_ino_token(ino)?;
        let key = exec_inode_key(dev, ino);
        if self.ttl_locks.remove(&key).is_none() {
            return Err("inode is not TTL-locked".into());
        }
        match self.ttl.remove(&key) {
            Ok(()) | Err(aya::maps::MapError::KeyNotFound) => Ok("unlocked".to_owned()),
            Err(error) => Err(error.into()),
        }
    }
}

impl ExecInodeCore {
    /// `MALWARE_INODE_STATUS` -> bounded lock counters.
    pub(crate) fn malware_lock_status(&self) -> String {
        format!(
            "locks={}:expired={}",
            self.ttl_locks.len(),
            self.expired_locks
        )
    }
}

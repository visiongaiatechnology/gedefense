//! Wave 3a extraction: the network command surface (`ADD`/`DEL`/`ALLOW_*`,
//! `INGRESS_*`/`EGRESS_*`, `STYX_*` and blocklist lifecycle) formerly inline in
//! `main.rs`.

use crate::*;

impl KernelCore {
    pub(crate) fn add(&mut self, target: &str) -> Result<(), BoxError> {
        let target = parse_target(target)?;
        match target {
            Target::V4(ip, prefix) => {
                self.v4
                    .insert(&Key::new(prefix, ip.octets()), ACTION_DROP, 0)?;
            }
            Target::V6(ip, prefix) => {
                self.v6
                    .insert(&Key::new(prefix, ip.octets()), ACTION_DROP, 0)?;
            }
        }
        self.blocked.insert(target);
        Ok(())
    }

    pub(crate) fn del(&mut self, target: &str) -> Result<(), BoxError> {
        let target = parse_target(target)?;
        match target {
            Target::V4(ip, prefix) => self.v4.remove(&Key::new(prefix, ip.octets()))?,
            Target::V6(ip, prefix) => self.v6.remove(&Key::new(prefix, ip.octets()))?,
        }
        self.blocked.remove(&target);
        Ok(())
    }

    pub(crate) fn clear_blocklist(&mut self) -> Result<(), BoxError> {
        let targets: Vec<Target> = self.blocked.iter().copied().collect();
        let mut failures = 0usize;
        for target in targets {
            let result = match target {
                Target::V4(ip, prefix) => self.v4.remove(&Key::new(prefix, ip.octets())),
                Target::V6(ip, prefix) => self.v6.remove(&Key::new(prefix, ip.octets())),
            };
            match result {
                Ok(()) => {
                    self.blocked.remove(&target);
                }
                Err(error) => {
                    failures += 1;
                    eprintln!("kernel blocklist clear failed for {target:?}: {error}");
                }
            }
        }
        if failures == 0 {
            Ok(())
        } else {
            Err(format!("kernel blocklist clear retained {failures} entries").into())
        }
    }

    pub(crate) fn allow_add(&mut self, target: &str) -> Result<(), BoxError> {
        match parse_target(target)? {
            Target::V4(ip, prefix) => {
                self.allow_v4.insert(&Key::new(prefix, ip.octets()), 1, 0)?;
            }
            Target::V6(ip, prefix) => {
                self.allow_v6.insert(&Key::new(prefix, ip.octets()), 1, 0)?;
            }
        }
        Ok(())
    }

    pub(crate) fn allow_del(&mut self, target: &str) -> Result<(), BoxError> {
        match parse_target(target)? {
            Target::V4(ip, prefix) => self.allow_v4.remove(&Key::new(prefix, ip.octets()))?,
            Target::V6(ip, prefix) => self.allow_v6.remove(&Key::new(prefix, ip.octets()))?,
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Point 3 (Phase 1) STYX command surface (§5/§7).
    //
    // Every method parses and validates the complete argument list first and
    // only then performs its single map operation, so a rejected command can
    // never leave a partial policy change behind. Deletes are idempotent.
    // ------------------------------------------------------------------

    pub(crate) fn styx_version(&self) -> Result<String, BoxError> {
        Ok(styx_flow::STYX_WIRE_VERSION.to_owned())
    }

    pub(crate) fn styx_epoch(&self) -> Result<String, BoxError> {
        Ok(self.styx_epoch_hex.clone())
    }

    pub(crate) fn styx_set_global(&mut self, args: &[&str]) -> Result<String, BoxError> {
        let request = styx_flow::parse_global_request(args)?;
        // The epoch is fixed for the process lifetime, so a global update only
        // rewrites mode/flags and keeps the kernel cache epoch valid.
        let word =
            styx_flow::encode_styx_global(self.styx_epoch as u32, request.mode, request.flags);
        self.styx_global.set(0, word, 0)?;
        Ok("applied".to_owned())
    }

    pub(crate) fn styx_mode_set(&mut self, args: &[&str]) -> Result<String, BoxError> {
        let (cgroup_id, mode, flags) = styx_flow::parse_mode_set_request(args)?;
        self.styx_mode.insert(cgroup_id, mode | flags, 0)?;
        Ok("applied".to_owned())
    }

    pub(crate) fn styx_mode_delete(&mut self, args: &[&str]) -> Result<String, BoxError> {
        let cgroup_id = styx_flow::parse_mode_del_request(args)?;
        styx_map_result(self.styx_mode.remove(&cgroup_id), false)
    }

    pub(crate) fn styx_allow(&mut self, args: &[&str], add: bool) -> Result<String, BoxError> {
        let key = styx_flow::parse_allow_request(args)?.allow_key()?;
        let result = match key {
            styx_flow::StyxAllowKey::CellV4(key, prefix) => {
                if add {
                    self.styx_cell_allow_v4.insert(&Key::new(prefix, key), 1, 0)
                } else {
                    self.styx_cell_allow_v4.remove(&Key::new(prefix, key))
                }
            }
            styx_flow::StyxAllowKey::CellV6(key, prefix) => {
                if add {
                    self.styx_cell_allow_v6.insert(&Key::new(prefix, key), 1, 0)
                } else {
                    self.styx_cell_allow_v6.remove(&Key::new(prefix, key))
                }
            }
            styx_flow::StyxAllowKey::GlobalV4(key, prefix) => {
                if add {
                    self.styx_allow_global_v4.insert(&Key::new(prefix, key), 1, 0)
                } else {
                    self.styx_allow_global_v4.remove(&Key::new(prefix, key))
                }
            }
            styx_flow::StyxAllowKey::GlobalV6(key, prefix) => {
                if add {
                    self.styx_allow_global_v6.insert(&Key::new(prefix, key), 1, 0)
                } else {
                    self.styx_allow_global_v6.remove(&Key::new(prefix, key))
                }
            }
        };
        styx_map_result(result, add)
    }

    pub(crate) fn styx_block(&mut self, args: &[&str], add: bool) -> Result<String, BoxError> {
        self.styx_prefix_change(args, add, false)
    }

    pub(crate) fn styx_resolver(&mut self, args: &[&str], add: bool) -> Result<String, BoxError> {
        self.styx_prefix_change(args, add, true)
    }

    pub(crate) fn styx_prefix_change(
        &mut self,
        args: &[&str],
        add: bool,
        resolver: bool,
    ) -> Result<String, BoxError> {
        let key = styx_flow::parse_prefix_request(args)?.prefix_key()?;
        let result = match (resolver, key) {
            (false, styx_flow::StyxPrefixKey::V4(key, prefix)) => {
                if add {
                    self.styx_block_v4.insert(&Key::new(prefix, key), 1, 0)
                } else {
                    self.styx_block_v4.remove(&Key::new(prefix, key))
                }
            }
            (false, styx_flow::StyxPrefixKey::V6(key, prefix)) => {
                if add {
                    self.styx_block_v6.insert(&Key::new(prefix, key), 1, 0)
                } else {
                    self.styx_block_v6.remove(&Key::new(prefix, key))
                }
            }
            (true, styx_flow::StyxPrefixKey::V4(key, prefix)) => {
                if add {
                    self.styx_resolver_v4.insert(&Key::new(prefix, key), 1, 0)
                } else {
                    self.styx_resolver_v4.remove(&Key::new(prefix, key))
                }
            }
            (true, styx_flow::StyxPrefixKey::V6(key, prefix)) => {
                if add {
                    self.styx_resolver_v6.insert(&Key::new(prefix, key), 1, 0)
                } else {
                    self.styx_resolver_v6.remove(&Key::new(prefix, key))
                }
            }
        };
        styx_map_result(result, add)
    }
}

/// Maps one STYX map write to the §5 `added`/`deleted` payload. A missing key on
/// DELETE is a success: the delete commands are idempotent by contract.
pub(crate) fn styx_map_result(result: Result<(), MapError>, add: bool) -> Result<String, BoxError> {
    match result {
        Ok(()) => Ok(if add { "added" } else { "deleted" }.to_owned()),
        Err(MapError::KeyNotFound) if !add => Ok("deleted".to_owned()),
        Err(error) => Err(error.into()),
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Target {
    V4(Ipv4Addr, u32),
    V6(Ipv6Addr, u32),
}

pub(crate) fn parse_target(value: &str) -> Result<Target, BoxError> {
    let (ip, prefix) = match value.split_once('/') {
        Some((address, raw_prefix)) => (address, Some(raw_prefix.parse::<u32>()?)),
        None => (value, None),
    };
    match ip.parse::<IpAddr>()? {
        IpAddr::V4(address) => {
            let prefix = prefix.unwrap_or(32);
            if prefix > 32 {
                return Err("invalid IPv4 prefix".into());
            }
            let bits = u32::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let network = Ipv4Addr::from(bits & mask);
            if network.is_unspecified() {
                return Err("unspecified IPv4 network is forbidden".into());
            }
            Ok(Target::V4(network, prefix))
        }
        IpAddr::V6(address) => {
            let prefix = prefix.unwrap_or(128);
            if prefix > 128 {
                return Err("invalid IPv6 prefix".into());
            }
            let bits = u128::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            let network = Ipv6Addr::from(bits & mask);
            if network.is_unspecified() {
                return Err("unspecified IPv6 network is forbidden".into());
            }
            Ok(Target::V6(network, prefix))
        }
    }
}

pub(crate) fn dispatch(
    core: &mut KernelCore,
    parts: &[&str],
) -> Result<Option<String>, BoxError> {
    let result = match parts {
        ["EGRESS_EVENTS"] => core.take_egress_events(),
        ["INGRESS_EVENTS"] => core.take_ingress_events(),
        ["INGRESS_HEALTH"] => core.ingress_health(),
        ["STYX_VERSION"] => core.styx_version(),
        ["STYX_EPOCH"] => core.styx_epoch(),
        ["STYX_GLOBAL", args @ ..] => core.styx_set_global(args),
        ["STYX_MODE_SET", args @ ..] => core.styx_mode_set(args),
        ["STYX_MODE_DEL", args @ ..] => core.styx_mode_delete(args),
        ["STYX_ALLOW_ADD", args @ ..] => core.styx_allow(args, true),
        ["STYX_ALLOW_DEL", args @ ..] => core.styx_allow(args, false),
        ["STYX_BLOCK_ADD", args @ ..] => core.styx_block(args, true),
        ["STYX_BLOCK_DEL", args @ ..] => core.styx_block(args, false),
        ["STYX_RESOLVER_ADD", args @ ..] => core.styx_resolver(args, true),
        ["STYX_RESOLVER_DEL", args @ ..] => core.styx_resolver(args, false),
        ["STYX_FLOW_EVENTS"] => core.styx_take_flow_events(),
        ["STYX_FLOW_HEALTH"] => core.styx_flow_health(),
        ["CLEAR_BLOCKLIST"] => core.clear_blocklist().map(|_| "cleared".into()),
        ["VERIFY_EMPTY"] if core.blocked.is_empty() => Ok("empty".into()),
        ["VERIFY_EMPTY"] => Err("blocklist is not empty".into()),
        ["ADD", target] => core.add(target).map(|_| "added".into()),
        ["DEL", target] => core.del(target).map(|_| "deleted".into()),
        ["ALLOW_ADD", target] => core.allow_add(target).map(|_| "allowlisted".into()),
        ["ALLOW_DEL", target] => core
            .allow_del(target)
            .map(|_| "allowlist entry deleted".into()),
        _ => return Ok(None),
    };
    Ok(Some(result?))
}

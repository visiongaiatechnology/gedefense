# GeDefense Linux 6.3.0 — Troubleshooting & Diagnostics

---

## 1. Quick Service & Kernel Health Check

```bash
systemctl status gedefense-bpffs gedefense-core gedefense-control gedefense-access gedefense-capture-helper --no-pager
journalctl -u gedefense-core -u gedefense-control --since=-15min --no-pager
curl --fail http://127.0.0.1:9844/livez && curl --fail http://127.0.0.1:9844/readyz
cat /sys/kernel/security/lsm
```

---

## 2. Common Operational States & Fixes

### BPF-LSM Guards Report `inactive` (`Titan Exec Gate` / `CredentialGuard` / `BPF_GUARD`)
- **Symptom:** `/api/v1/antispyware/status` or Web UI shows BPF-LSM hooks `inactive`.
- **Cause:** The running Linux kernel does not have `bpf` enabled in `/sys/kernel/security/lsm`.
- **Fix:** Add `bpf` to your kernel boot `lsm=` parameter (preserving `lockdown,capability,landlock,yama,apparmor,bpf`) in GRUB/systemd-boot and reboot. GeDefense never fakes enforcement when `bpf` LSM is absent.

### Posture Shows `DEGRADED` After Updating Binaries
- **Symptom:** FIM reports tampered hashes or `xdr degraded` after manual file replacement.
- **Fix:** Always deploy via immutable versioned releases (`OneClick.run` or `install-beta.sh`), update `/etc/vgt/gedefense/xdr-baseline.json` digests if modifying local binaries cleanly, and seal the release baseline via `POST /api/v1/fim/baseline` (`"scope": "release"`, `"confirm": "REBASELINE RELEASE"`).

### Cannot Promote `Canary → Enforce`
- **Symptom:** Promotion endpoint refuses transition with empty allowlist error.
- **Fix:** Add at least one verified operator management IP/CIDR (`[defense] allowlist` or Settings UI), restart/reconcile so XDP shows `Allowlist SYNC`, then retry promotion.

### `systemd 255+` Fails Pinning eBPF Maps Under `/sys/fs/bpf/gedefense`
- **Symptom:** Core reports read-only `/sys/fs/bpf` inside systemd sandbox.
- **Fix:** Ensure `gedefense-bpffs.service` is active (pre-creates `/sys/fs/bpf/gedefense`) and `gedefense-core.service` includes `-/sys/fs/bpf/gedefense` in `ReadWritePaths`. Run `bash scripts/validate-systemd.sh` to verify.

### `EMERGENCY_STOP` Triggered (`/readyz` Returns Error, `/livez` OK)
- **Check:** Verify whether `/var/lib/vgt/gedefense/EMERGENCY_STOP` exists and inspect `GET /api/v1/release`.
- **Recovery:** Review signed forensics, verify no active compromise, clear via `POST /api/v1/release/emergency-stop/clear`, inspect kernel maps, and re-promote cautiously from `observe`.

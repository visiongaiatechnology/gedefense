# Migration Notes — GeDefense RC/Beta 4 to 1.0.0-beta.5

The one-click installer preserves structurally valid password records, TLS material, dashboard token, IPC key, policy state, incidents, behavior profiles and runtime settings.

During the first successful Beta 5 startup:

- a new storage master key is created under `/etc/vgt/gedefense/secrets/storage-master.key`;
- supported plaintext operational state is authenticated, encrypted with AES-256-GCM and atomically replaced;
- a valid legacy PBKDF2 password record remains usable and is migrated to Argon2id after the next successful login;
- existing TLS, public policy key and service identity material remain permission-protected and are not needlessly regenerated.

The new release is installed under:

```text
/opt/vgt/gedefense/releases/1.0.0-beta.5
```

The previous release and service definitions are retained until the new Rust core, target-kernel XDP path, control plane and HTTPS gateway pass activation checks. Any failure triggers rollback, including restoration of pre-migration state and secret files from the installer transaction backup.

The old `/opt/vgt/gedefense-observe` tree is not deleted automatically.

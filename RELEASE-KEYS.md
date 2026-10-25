# Release signing keys

This repository publishes the Ed25519 public key used to sign GeDefense release
artifacts. Private keys are never stored in the repository or CI; the release
private key remains offline.

## 5.0.0-beta.2 (2026-10-25) and later

- Signer: `ed25519:e011a96c7c6ab4f6`
- Public key (32 raw bytes, hex):
  `e011a96c7c6ab4f6b0d8c80edcb414c0593d675c2fb65494cffe7f53ac621b6e`
- SHA-256 of the public key:
  `23d8adf811ddef1b678146569b540c694daf3c4fea7272be2e57c974b93178b3`
- Public key file:
  [`release/gedefense-release-2026-10-25.ed25519.pub`](release/gedefense-release-2026-10-25.ed25519.pub)

The installer embeds this public key and verifies the signed release index,
SBOM and build provenance before it executes any privileged step.

**Rotation note:** the previous release-signing private key was not available
for this public beta build. This release therefore introduces a new release
key. The old key must not be used to verify 5.0.0-beta.2 artifacts, and this key
applies from 5.0.0-beta.2 onward.

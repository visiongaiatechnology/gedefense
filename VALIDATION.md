# Validation — GeDefense 1.0.0-beta.5

## Scope

Beta 5 validates the branded multilingual interface, Argon2id gateway authentication, AES-256-GCM operational storage, browser/backend hardening and the retained full-stack Rust/XDP activation path.

## Automated validation

The release pipeline runs:

- Go control-plane tests and `go vet`;
- HTTPS gateway tests and `go vet`;
- race-detector suites for control plane and gateway;
- native fuzz-smoke runs for IPC, policy, encrypted-envelope and `/proc` parsers;
- locked Rust userspace tests and no_std eBPF target compilation;
- JavaScript syntax checks for every browser module;
- static security regression audit;
- CGO-disabled static control-plane build;
- CGO-enabled gateway build and `libargon2.so.1` dependency resolution;
- source-manifest generation;
- deterministic source ZIP and self-extracting RUN packaging;
- embedded payload and binary digest verification;
- XDP source guard against attacker-controlled length-derived packet pointers.

## Security cases covered

- login CSRF missing and token mismatch;
- explicit cross-site and mismatched-origin login rejection;
- exact-origin requirement for authenticated mutating requests and logout;
- forged and expired session rejection;
- Host-header allowlist;
- browser Authorization/cookie/origin/referer/forwarding-header stripping;
- backend bearer requirement and foreign-Origin rejection;
- asset allowlist and encoded traversal rejection;
- strict security-header presence;
- Argon2id record generation, verification and private-file policy;
- AES-GCM tamper, purpose, path and sequence binding;
- absence of operational plaintext in protected stores;
- HTTPS-only feed URL policy and local/private-network SSRF refusal;
- absence of unsafe DOM HTML sinks and runtime command execution primitives across Go, Rust and eBPF source.
- authenticated and response-bounded privileged-core IPC;
- authoritative blocklist clearing plus independent empty-state verification;
- startup Observe verification and fail-closed Emergency Stop behavior;
- revision-conflict and Observe/Degraded mutation gates for modular rule settings;
- alert-score/response-score separation for operator-defined RE2 rules.

## Target-host gate

This build environment cannot substitute for the destination kernel, driver or BPF verifier. The RUN installer compiles Rust/eBPF on the destination and refuses activation unless:

1. the eBPF verifier accepts the program;
2. native or generic XDP attaches to the selected interface;
3. the Rust socket is created with the expected identity;
4. authenticated VGT3 IPC succeeds;
5. `core_connected=true` is reported by the control plane;
6. the public TLS gateway passes authenticated backend and liveness checks.

Failure at any stage triggers the installation transaction rollback.

## Honest boundary

Static and integration testing materially reduce known XSS, CSRF, auth bypass, SSRF, RCE and storage-tampering risks; they do not constitute a formal proof or independent penetration test. Host-root compromise remains outside the confidentiality boundary of locally available unattended-start keys.

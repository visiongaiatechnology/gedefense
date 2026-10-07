# GeDefense 4.1 Kinetic Defense – L7/TLS Integration Contract

## Purpose

The native TLS security engine analyzes bounded metadata from a complete TLS ClientHello: SNI, JA3 components, ALPN/GREASE structure and short-window handshake behavior. It never retains the submitted TLS payload after parsing and it performs no external reputation lookup.

## Producer boundary

The control/L7 service does **not** claim to passively reconstruct arbitrary TCP streams from the network. A trusted local producer positioned before TLS termination must submit a **complete, reassembled ClientHello TLS record** to the Unix-socket endpoint:

`POST /v1/tls/clienthello`

The endpoint is available only when L7 and TLS inspection are enabled. Production deployments should keep `require_peer_credentials=true` and authorize only the local reverse-proxy/sensor UID or GID. The request envelope is bounded by `l7.tls_max_client_hello_bytes` and unknown JSON fields are rejected.

If no trusted producer is installed, disable TLS telemetry or keep GeDefense in a non-enforcing release state. The dashboard must not interpret `tls_enabled=true` as proof that TLS traffic is actually inspected.

## Coverage truth

The L7 service distinguishes engine health from traffic coverage:

- `HEALTHY_AWAITING_TRAFFIC`: engine is alive but no verified inspection traffic has traversed it yet.
- `NO_TRAFFIC_WARNING`: L7 has been enabled for more than five minutes without HTTP/TLS inspection traffic.
- `TLS_NOT_IN_PATH`: HTTP inspection is active while TLS telemetry is enabled but no ClientHello has reached the TLS sensor.
- `TRAFFIC_ACTIVE`: at least one real HTTP or TLS inspection has traversed the configured path.
- `OFFLINE` / `INLINE_DEGRADED`: service or inline path failure.

When L7 is enabled, `l7_application` is a required coverage sensor. Enforce promotion is rejected while required coverage is degraded/offline.

## Fingerprint policy

JA3 signature/profile files are local, versioned JSON policy. GeDefense rejects:

- symlinks/non-regular files,
- empty or oversized files,
- group/world-writable policy files,
- files that change between validation and open,
- unknown JSON fields,
- duplicate JA3 signatures/profiles,
- invalid JA3 hashes or severities.

JA3 MD5 is used only because the JA3 format defines it. It is a fingerprint, never an evidence-integrity digest.

## Response boundary

TLS/L7 findings may contribute to **network containment** through Kinetic Defense. They never independently authorize host process termination. Management allowlists and the normal Kinetic release/response gates remain authoritative.

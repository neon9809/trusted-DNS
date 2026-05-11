# Trusted-DNS Architecture Document

## Overview

Trusted-DNS is a dual-component DNS system designed to bypass local DNS pollution. It consists of a **Docker Node** (data plane) and a **Cloudflare Worker** (control plane + relay), connected by a compact binary protocol over HTTPS.

In the current v1 scope, one Worker deployment is paired with one Docker node. The Worker derives a single active `client_id` from its configured `ROOT_SEED` and manages one generation namespace. Multi-client multiplexing inside one Worker deployment is reserved for a future version.

## System Components

### Docker Node (Go)

The Docker node runs on the local network and serves as a drop-in DNS resolver on `53/UDP`. It intercepts standard DNS queries from LAN clients, encrypts them using the Trusted-DNS binary protocol, and sends them to the Worker over HTTPS.

| Module | Responsibility |
|---|---|
| `listener` | Accepts DNS queries on 53/UDP, dispatches to handler goroutines |
| `session` | Manages KeyBundle lifecycle, ticket selection, sequence tracking |
| `transport` | Builds binary protocol messages, handles HTTPS communication |
| `probe` | TCP/ICMP reachability probes for A/AAAA records |
| `rewriter` | Reorders DNS response records based on probe results |
| `protocol` | Shared binary encoding/decoding and cryptographic primitives |

### Cloudflare Worker (TypeScript)

The Worker runs on Cloudflare's edge network and serves as the trusted relay. It validates client credentials, manages generation state via Durable Objects, and forwards DNS queries to DoH upstreams.

| Module | Responsibility |
|---|---|
| `handlers` | Routes and processes Bootstrap, Query, and Refresh requests |
| `protocol` | Binary protocol definitions and serialization |
| `crypto` | HKDF key derivation, AES-256-GCM AEAD, HMAC ticket auth |
| `tickets` | KeyBundle issuance and session/refresh ticket verification |
| `resolver` | DoH upstream forwarding with race + fallback strategy |
| `replay` | Short-window anti-replay cache per Worker isolate |
| `generation-store` | Durable Object for per-client generation state |

## Data Flow

### Bootstrap Flow

```text
Docker                          Worker
  │                               │
  │  BootstrapReq                 │
  │  (boot_nonce + timestamp +    │
  │   bootstrap_proof)            │
  │──────────────────────────────>│
  │                               │  Verify proof
  │                               │  Advance generation (DO)
  │                               │  Issue KeyBundle
  │  BootstrapResp                │
  │  (encrypted KeyBundle)        │
  │<──────────────────────────────│
  │                               │
  │  Install bundle               │
  │  Derive query keys            │
```

### Query Flow (Hot Path)

```text
Docker                          Worker                      DoH Upstream
  │                               │                            │
  │  QueryReq                     │                            │
  │  (ticket_blob + encrypted     │                            │
  │   DNS query + padding)        │                            │
  │──────────────────────────────>│                            │
  │                               │  Verify ticket             │
  │                               │  Anti-replay check         │
  │                               │  Decrypt DNS query         │
  │                               │  Forward via DoH           │
  │                               │───────────────────────────>│
  │                               │<───────────────────────────│
  │                               │  Encrypt DNS response      │
  │  QueryResp                    │                            │
  │  (encrypted DNS response)     │                            │
  │<──────────────────────────────│                            │
  │                               │                            │
  │  Decrypt response             │                            │
  │  Probe + Reorder (optional)   │                            │
  │  Return to LAN client         │                            │
```

### Refresh Flow

```text
Docker                          Worker
  │                               │
  │  RefreshReq                   │
  │  (refresh_ticket + proof +    │
  │   spent counts)               │
  │──────────────────────────────>│
  │                               │  Verify refresh ticket
  │                               │  Parse forward-compatible
  │                               │  refresh attestation fields
  │                               │  Advance generation (DO)
  │                               │  Issue new KeyBundle
  │  RefreshResp                  │
  │  (encrypted new KeyBundle)    │
  │<──────────────────────────────│
  │                               │
  │  Install new bundle           │
  │  Old generation invalidated   │
```

## Key Design Decisions

### Ticket-Based Session Management

Instead of maintaining per-session state on the Worker, Trusted-DNS uses **self-contained tickets** signed with HMAC. The Worker only needs to verify the ticket tag and check the generation number against a single Durable Object entry per client. This minimizes Worker-side state to `O(1)` per client.

### Generation Rotation

Each Bootstrap or Refresh advances the generation counter. The Worker stores only the latest generation per client. Any ticket from an older generation is rejected, providing forward security without complex revocation lists.

### Forward-Compatible Refresh Attestation

The Refresh request already carries `spent_bundle_gen`, `spent_query_count`, and `refresh_proof`. These fields are intentionally kept in the wire format for a future **multi-client Worker** mode where refresh requests will carry stronger attestation about the client's spent state.

In v1, the refresh ticket remains the authoritative refresh credential. The Worker parses the attestation fields for protocol compatibility, but does not yet treat them as an independently enforced acceptance boundary.

### DoH Upstream Strategy

The Worker uses a "Primary + Secondary Race, Tertiary Fallback" strategy:

1. Send the DNS query to the primary and secondary upstreams concurrently
2. Return whichever responds first with a valid DNS response
3. If both fail, try the tertiary upstream as a fallback

This provides both low latency (via racing) and high availability (via fallback).

### Resilient Transport & DPI Evasion (v1.1)

To circumvent Deep Packet Inspection (DPI) and traffic shaping algorithms commonly deployed by ISPs:
1. **Dynamic Payload Padding**: The Docker node injects 64-319 bytes of cryptographically secure random padding to the end of the `QueryReq` payload, preventing fixed-length packet fingerprinting.
2. **HTTP Header Masquerading**: The transport injects standard `User-Agent` and `Accept` headers to blend in with regular web traffic.
3. **Strict Timeout Handling**: Explicit timeouts (e.g., 5-second `ResponseHeaderTimeout` and 30-second handshake contexts) prevent the Docker node from deadlocking on silent DPI packet drops (half-open connections).

## Deployment Model

The system is designed for **single-user or small-network deployment**:

- One Docker node per network (e.g., home router, VPS, or NAS)
- One Worker deployment per Docker node in v1
- Multiple DoH upstreams for redundancy

To deploy multiple nodes today, run multiple Worker deployments and assign each one its own `ROOT_SEED`. Supporting multiple clients behind a single Worker deployment is a planned future capability rather than a current v1 feature.

The Docker image supports **amd64 and arm64** architectures, enabling deployment on x86 servers, Raspberry Pi, and ARM-based NAS devices.

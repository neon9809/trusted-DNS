# Trusted-DNS Architecture Document

## Overview

Trusted-DNS is a dual-component DNS system designed to bypass local DNS pollution. It consists of a **Docker Node** (data plane) and a **Cloudflare Worker** (control plane + relay), connected by a compact binary protocol over HTTPS.

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
  │   DNS query)                  │                            │
  │──────────────────────────────>│                            │
  │                               │  Verify ticket             │
  │                               │  Anti-replay check         │
  │                               │  Decrypt DNS query         │
  │                               │  Forward via DoH           │
  │                               │────────────────────────────>│
  │                               │<────────────────────────────│
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

### DoH Upstream Strategy

The Worker uses a "Primary + Secondary Race, Tertiary Fallback" strategy:

1. Send the DNS query to the primary and secondary upstreams concurrently
2. Return whichever responds first with a valid DNS response
3. If both fail, try the tertiary upstream as a fallback

This provides both low latency (via racing) and high availability (via fallback).

### Probe Engine

The Docker node optionally probes A/AAAA record addresses via TCP connection tests. Results are used to reorder DNS response records so that the most reachable address appears first. This improves connection quality without fabricating DNS answers.

## Deployment Model

The system is designed for **single-user or small-network deployment**:

- One Docker node per network (e.g., home router, VPS, or NAS)
- One Worker per user (shared ROOT_SEED)
- Multiple DoH upstreams for redundancy

The Docker image supports **amd64 and arm64** architectures, enabling deployment on x86 servers, Raspberry Pi, and ARM-based NAS devices.

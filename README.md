# Trusted-DNS

[English](README.md) | [简体中文](README.zh-CN.md)

**Trusted-DNS** is an open-source DNS system designed for polluted network environments. It mitigates local ISP DNS pollution by routing DNS queries through a secure, encrypted private protocol between a local Docker node and a Cloudflare Worker, which then forwards standard DNS queries to trusted DoH (DNS over HTTPS) upstream resolvers.

## Architecture

Trusted-DNS adopts a **Cloudflare Worker + Local Docker Node** dual-side architecture. The Docker node takes over the local `53/UDP` port, encrypts DNS queries using a compact binary protocol, and sends them to the Worker over HTTPS. The Worker validates tickets, manages generation state, and forwards standard DNS wire-format queries to DoH upstreams per [RFC 8484](https://datatracker.ietf.org/doc/html/rfc8484).

```text
┌──────────────────────────────┐
│      LAN / Host Clients      │
│   Phones, Browsers, Stubs    │
└──────────────┬───────────────┘
               │ Standard DNS (53/UDP)
               ▼
┌──────────────────────────────┐
│      Trusted-DNS Docker      │
│  DNS Listener                │
│  Session Manager             │
│  Secure Transport            │
│  Probe Engine                │
│  Response Rewriter           │
└──────────────┬───────────────┘
               │ HTTPS + Binary Ciphertext
               ▼
┌──────────────────────────────┐
│     Trusted-DNS Worker       │
│  Bootstrap / Query / Refresh │
│  Ticket Verifier             │
│  Generation State Store      │
└──────────────┬───────────────┘
               │ DoH (HTTP POST)
               ▼
┌──────────────────────────────┐
│     DoH Upstream Resolvers   │
│   Google / Cloudflare / etc  │
└──────────────────────────────┘
```

## Current Scope (v2.0)

Trusted-DNS v2.0 now focuses on a **Cloudflare Worker multi-client deployment** model:

- One Cloudflare Worker deployment can serve multiple Docker clients
- Requests are routed by `client_id_prefix` through `CLIENT_REGISTRY`
- Generation state is isolated per client while keeping the persistent state model minimal
- If `CLIENT_REGISTRY` is omitted, the Worker falls back to the original single-client `ROOT_SEED` mode

The repository also now reserves `platform/deno/` and `platform/fastly/` as v2.1 landing areas. Those runtimes are not production-ready yet; they are intentionally kept as skeletons until the Deno and Fastly PoC work starts.

## Features

**Security & Privacy**

- **DPI Evasion (v1.1)**: Random payload padding and HTTP header masquerading to bypass Deep Packet Inspection and traffic shaping.
- Encrypted Docker-to-Worker communication using AES-256-GCM with HKDF-derived purpose-specific keys
- Ticket-based session management with generation rotation (no persistent session tables)
- Short-window anti-replay protection with sequence number validation
- Zero DNS query history: no QNAME, QTYPE, or answer content is ever persisted
- Minimal state: only `client_id → latest_bundle_gen` is stored per client
- Multi-client isolation on the Worker side through static `CLIENT_REGISTRY` routing
- Resilient Transport: Explicit context timeouts and strict connection constraints to prevent half-open drops.

**Performance**

- Hot-path queries use lightweight ticket verification (no full handshake per query)
- "Primary + Secondary Race, Tertiary Fallback" upstream strategy for optimal latency
- Optional A/AAAA record probing and reordering for improved connection quality
- Compact binary protocol (no JSON on hot path)

**v2.0 Architecture & Operations**

- `Bootstrap`, `Query`, and `Refresh` are split into independent service handlers instead of staying in one monolithic Worker file
- Service logic now uses dependency injection, so runtime-specific Cloudflare wiring is separated from protocol flow
- Static multi-client registry is configured entirely through environment variables, without introducing a control plane or external database
- End-to-end smoke scripts cover bootstrap, query, refresh, registry verification, and single-Worker multi-client validation
- The repository now uses `platform/cloudflare_worker` as the active Cloudflare runtime root, with `platform/deno` and `platform/fastly` reserved for v2.1 PoC work
- Shared protocol and service-core logic is now placed under `platform/src`, so platform directories stay focused on entrypoints and adapters

**Deployment**

- Docker image supports **multi-architecture** builds (amd64 / arm64)
- Single `docker-compose.yml` deployment with minimal configuration
- Worker deploys to Cloudflare Workers with Durable Objects for state management

## Verification

The following end-to-end test was performed with a live Docker node connected to a deployed Worker instance. Bootstrap succeeded on the first attempt, and all encrypted query/response round-trips completed without errors.

```text
$ docker run -d --name trusted-dns \
  -p 53:53/udp \
  -e WORKER_URL="https://your-worker.example.com" \
  -e ROOT_SEED="$(openssl rand -hex 32)" \
  ghcr.io/neon9809/trusted-dns-docker:latest

$ docker logs trusted-dns
[main] Trusted-DNS Docker node starting...
[main] client_id_prefix: 4a545d971cb4372e
[transport] starting bootstrap...
[transport] bootstrap success: gen=1, tickets=5
[session] installed bundle gen=1 with 5 tickets, budget=1000
[listener] DNS listener started on 0.0.0.0:53
[main] Trusted-DNS Docker node ready
```

```text
$ dig @127.0.0.1 google.com A +short
142.251.140.238

$ dig @127.0.0.1 cloudflare.com A +short
104.16.132.229
104.16.133.229

$ dig @127.0.0.1 github.com A +short
140.82.121.3

$ dig @127.0.0.1 baidu.com A +short
110.242.74.102
124.237.177.164
111.63.65.247
111.63.65.103

$ dig @127.0.0.1 google.com AAAA +short
2a00:1450:4003:818::200e

$ dig @127.0.0.1 gmail.com MX +short
5 gmail-smtp-in.l.google.com.
10 alt1.gmail-smtp-in.l.google.com.
20 alt2.gmail-smtp-in.l.google.com.
30 alt3.gmail-smtp-in.l.google.com.
40 alt4.gmail-smtp-in.l.google.com.
```

All record types (A, AAAA, MX) resolved correctly. The response rewriter also reordered multi-record answers for improved connection quality.

## Log Interpretation

The Docker node does not print one `rewriter` log per DNS query. The line
`[rewriter] reordered N records` is emitted only when a single DNS response
contains multiple A/AAAA answers and the rewriter finishes probing and
reordering them. It does **not** mean "N queries were processed", and it is
not a counter for when session refresh will happen.

| Query / response shape | Consumes one query budget / ticket sequence? | Prints `[rewriter] reordered N records`? | Notes |
|---|---|---|---|
| A or AAAA response with only one IP | Yes | No | The request still goes through the Worker and uses one query sequence, but there is nothing to reorder. |
| A or AAAA response with multiple IPs | Yes | Usually yes | The probe engine ranks the returned addresses and the rewriter logs one line for that response, where `N` is the number of reordered answer records. |
| MX / CNAME / TXT / other non-A/AAAA answers | Yes | No | These requests still consume query budget, but the rewriter only handles A/AAAA address ordering. |
| DNS response with no answers | Yes | No | An empty response still consumes a query sequence if it was sent through the Worker. |
| Refresh triggered by `totalQueries >= threshold` | No new query is consumed by the log itself | No | Refresh uses a separate refresh request. The trigger is based on the internal `totalQueries` counter, not the visible number of `rewriter` log lines. |
| Refresh triggered by `approaching expiration` | No new query is consumed by the log itself | No | Refresh can happen even if you saw only a few `rewriter` lines, because bundle expiry time is checked independently from query count. |

In short, `docker logs` will usually undercount real DNS traffic if you only
look at `rewriter` lines. Many successful queries never print a rewriter log,
but they still consume ticket/query budget and can still lead to a refresh.

## Quick Start

### Prerequisites

- A Cloudflare account with Workers and Durable Objects enabled
- Docker and Docker Compose on your local machine or gateway
- A shared secret (ROOT_SEED): generate with `openssl rand -hex 32`

### 1. Deploy the Worker

**Option A: One-Click Deploy (Recommended)**

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/neon9809/trusted-DNS/tree/main/platform/cloudflare_worker)

*Note: The one-click deploy template now pre-fills `DOH_UPSTREAMS` and a sample `CLIENT_REGISTRY`. Replace the sample `root_seed` values with your own 64-character hex seeds, or remove `CLIENT_REGISTRY` if you want single-client mode. Generate each seed using `openssl rand -hex 32`.*

**Option B: Manual Deploy**

```bash
cd platform/cloudflare_worker
cp ../../examples/worker.env.example .env

# Edit wrangler.toml with your ROOT_SEED, DOH upstreams, and optional CLIENT_REGISTRY
pnpm install
pnpm deploy
```

Configure the following variables in `wrangler.toml` or as Worker secrets:

```toml
[vars]
ROOT_SEED = "your-64-char-hex-seed"
DOH_UPSTREAMS = '["https://dns.google/dns-query","https://cloudflare-dns.com/dns-query","https://1.1.1.1/dns-query"]'
CLIENT_REGISTRY = '[{"root_seed":"seed-a","enabled":true},{"root_seed":"seed-b","enabled":true}]'
```

If `CLIENT_REGISTRY` is set, the Worker uses multi-client routing and looks up each client by `client_id_prefix`. If `CLIENT_REGISTRY` is omitted, the Worker falls back to single-client mode and uses `ROOT_SEED`.

### 2. Deploy the Docker Node

```bash
cp examples/docker-compose.example.yml docker-compose.yml

# Edit docker-compose.yml with your Worker URL and ROOT_SEED
docker compose up -d
```

Or pull directly from GitHub Container Registry:

```bash
docker pull ghcr.io/neon9809/trusted-dns-docker:latest
```

### 3. Configure Your Devices

Point your devices' DNS settings to the Docker node's IP address. For example, if the Docker node runs on `192.168.1.100`:

- **Router**: Set primary DNS to `192.168.1.100`
- **Individual devices**: Set DNS server to `192.168.1.100`

## Configuration

### Docker Node Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `WORKER_URL` | Yes | — | Cloudflare Worker endpoint URL |
| `ROOT_SEED` | Yes | — | Shared 64-character hex secret |
| `PROBE_MODE` | No | `tcp443` | Probe mode: `none`, `tcp443`, `icmp`, `icmp,tcp443` |
| `LISTEN_ADDR` | No | `0.0.0.0:53` | DNS listener address |
| `PROTOCOL_PATH` | No | `/dns-query` | Custom protocol endpoint path (must match Worker) |

### Worker Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `ROOT_SEED` | Yes | — | Shared 64-character hex secret (must match Docker) |
| `DOH_UPSTREAMS` | Yes | Google + Cloudflare + `1.1.1.1` | JSON array of default DoH upstream URLs. Used directly in single-client mode, and as the fallback upstream set for registry entries that do not override it. |
| `DOH_TIMEOUT_MS` | No | `5000` | Per-upstream timeout in milliseconds |
| `PROTOCOL_PATH` | No | `/dns-query` | Custom protocol endpoint path (must match Docker) |
| `CLIENT_REGISTRY` | No | — | JSON array string for multi-client routing. Each entry must include a `root_seed`, and may optionally override `doh_upstreams` and `doh_timeout_ms`. Omit it to keep single-client mode with `ROOT_SEED`. |

## Deployment Scope And Multi-Node Notes

**Trusted-DNS v2.0 supports one Cloudflare Worker deployment serving multiple Docker nodes**, as long as the Worker is configured with `CLIENT_REGISTRY` and each Docker node uses its own matching `ROOT_SEED`.

Supported topology:

```text
Docker Node A  <->  Worker Deployment A  (CLIENT_REGISTRY contains ROOT_SEED_A)
Docker Node B  <->  Worker Deployment A  (CLIENT_REGISTRY contains ROOT_SEED_B)
Docker Node C  <->  Worker Deployment A  (CLIENT_REGISTRY contains ROOT_SEED_C)
```

The following combinations matter:

| Scenario | Outcome |
|---|---|
| **Multiple Docker nodes use different `ROOT_SEED`s against the same Worker, and `CLIENT_REGISTRY` contains all of them** | Supported v2.0 model. Each client gets its own routed context and generation state. |
| **Multiple Docker nodes use different `ROOT_SEED`s against the same Worker, but `CLIENT_REGISTRY` is missing one of them** | Requests for the missing client fail because the Worker cannot resolve that `client_id_prefix`. |
| **Two Docker nodes share the same `ROOT_SEED` against the same Worker** | Not recommended. Both nodes derive the same `client_id` and collide on bootstrap, query sequence space, and refresh generation state. |
| **`CLIENT_REGISTRY` is omitted and only `ROOT_SEED` is configured** | Single-client fallback mode. This preserves the original v1 deployment behavior. |

If you want to run multiple nodes today, generate a different seed for each node and include every seed in `CLIENT_REGISTRY`:

```bash
# Node A
ROOT_SEED_A=$(openssl rand -hex 32)

# Node B
ROOT_SEED_B=$(openssl rand -hex 32)

# Node C
ROOT_SEED_C=$(openssl rand -hex 32)
```

At the moment, multi-client production support is implemented only for Cloudflare Workers. `platform/deno/` and `platform/fastly/` are reserved for v2.1 PoC work.

## Protocol Overview

Trusted-DNS uses a three-phase protocol model:

| Phase | Purpose | Frequency |
|---|---|---|
| **Bootstrap** | Initial authentication and first KeyBundle issuance | Low |
| **Query** | Encrypted DNS query using session tickets | High |
| **Refresh** | Obtain next-generation KeyBundle | Medium-Low |

Each `KeyBundle` contains **5 session tickets** (200 queries each) and **1 refresh ticket**, providing a total budget of **1000 queries per generation**. This design avoids full handshakes on the hot path while maintaining clear security semantics.

In the current v2.0 implementation, the Refresh request still carries `spent_bundle_gen`, `spent_query_count`, and `refresh_proof` as forward-compatible fields. They remain reserved for a future refresh-semantics upgrade and are not yet enforced as standalone refresh acceptance criteria.

For detailed protocol specification, see [docs/protocol.md](docs/protocol.md).

## Security Model

Trusted-DNS is designed to **reduce the most direct and realistic pollution and tampering risks**, not to achieve absolute unobservability. Key security properties include:

- **Anti-pollution**: DNS queries bypass local plaintext DNS paths
- **Link confidentiality**: Docker-to-Worker traffic is encrypted
- **Link integrity**: AEAD authentication prevents silent tampering
- **Session ephemerality**: Tickets and keys reside only in memory
- **Generation invalidation**: New bootstrap/refresh invalidates old generations
- **Basic anti-replay**: Sequence numbers and short-window deduplication

The current production security boundary assumes **Cloudflare Workers as the active multi-client runtime**. Client isolation inside one Worker deployment is implemented through `CLIENT_REGISTRY` routing plus per-client generation state. Deno and Fastly remain future PoC targets and are not part of the released production boundary yet.

For the complete threat model, see [docs/threat-model.md](docs/threat-model.md).

## Project Structure

```text
Trusted-DNS/
├── README.md
├── docs/
│   ├── architecture.md
│   ├── protocol.md
│   └── threat-model.md
├── platform/
│   ├── README.md
│   ├── src/                    # Shared protocol and service-core
│   ├── deno/
│   │   ├── main.ts               # Deno PoC entry skeleton
│   │   ├── kv-store.ts           # Deno KV adapter skeleton
│   │   └── config/
│   ├── fastly/
│   │   ├── index.ts              # Fastly PoC entry skeleton
│   │   ├── store.ts              # Fastly adapter skeleton
│   │   └── config/
│   └── cloudflare_worker/
│       ├── src/
│       │   ├── index.ts          # Cloudflare Worker entry point
│       │   ├── adapters/         # Cloudflare runtime wiring
│       │   └── generation-store.ts # Durable Object for gen state
│       ├── wrangler.toml
│       └── package.json
├── docker/
│   ├── cmd/trusted-dns/
│   │   └── main.go           # Docker node entry point
│   ├── internal/
│   │   ├── protocol/         # Binary protocol + crypto (Go)
│   │   ├── listener/         # DNS UDP listener
│   │   ├── session/          # KeyBundle & ticket management
│   │   ├── transport/        # Secure HTTPS transport
│   │   ├── probe/            # Reachability probe engine
│   │   └── rewriter/         # DNS response rewriter
│   ├── Dockerfile
│   └── docker-compose.yml
├── examples/
│   ├── docker-compose.example.yml
│   └── worker.env.example
└── .github/
    └── workflows/
        └── docker-publish.yml
```

## Roadmap

| Milestone | Goal |
|---|---|
| **M1** | MVP: Docker ↔ Worker ↔ DoH core path |
| **M2** | Complete KeyBundle rotation and anti-replay |
| **M3** | Enhanced A/AAAA probing and reordering |
| **M4** | Upstream strategy optimization and observability |
| **M5** | Multi-client Worker mode, refresh attestation enforcement, and extension capabilities |

## License

This project is licensed under the [MIT License](LICENSE).

## Credit

The initial direction, functional constraints, and security boundaries of this project originate from **neon9809**'s continuous exploration and iteration around the following questions: how to counter local ISP DNS pollution; how to split the system into a Worker side and a Docker side; and how to converge the goals into a truly deployable open-source project within Cloudflare Worker's platform constraints. The project documentation, protocol specification, architecture design, and implementation were systematically developed by **Manus AI** based on these requirements.

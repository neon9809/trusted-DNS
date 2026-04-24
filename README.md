# Trusted-DNS

[English](README.md) | [简体中文](README.zh-CN.md)

**Trusted-DNS** is an open-source DNS system designed for polluted network environments. It mitigates local ISP DNS pollution by routing DNS queries through a secure, encrypted private protocol between a local Docker node and a Cloudflare Worker, which then forwards standard DNS queries to trusted DoH (DNS over HTTPS) upstream resolvers.

## Architecture

Trusted-DNS adopts a **Cloudflare Worker + Local Docker Node** dual-side architecture. The Docker node takes over the local `53/UDP` port, encrypts DNS queries using a compact binary protocol, and sends them to the Worker over HTTPS. The Worker validates tickets, manages generation state, and forwards standard DNS wire-format queries to DoH upstreams per [RFC 8484](https://datatracker.ietf.org/doc/html/rfc8484).

```text
┌─────────────────────────────┐
│        LAN / Host Clients    │
│   Phones, Browsers, Stubs    │
└──────────────┬──────────────┘
               │ Standard DNS (53/UDP)
               ▼
┌─────────────────────────────┐
│      Trusted-DNS Docker      │
│  DNS Listener                │
│  Session Manager             │
│  Secure Transport            │
│  Probe Engine                │
│  Response Rewriter           │
└──────────────┬──────────────┘
               │ HTTPS + Binary Ciphertext
               ▼
┌─────────────────────────────┐
│     Trusted-DNS Worker       │
│  Bootstrap / Query / Refresh │
│  Ticket Verifier             │
│  Generation State Store      │
└──────────────┬──────────────┘
               │ DoH (HTTP POST)
               ▼
┌─────────────────────────────┐
│      DoH Upstream Resolvers  │
│   Google / Cloudflare / etc  │
└─────────────────────────────┘
```

## Features

**Security and Privacy**

- Encrypted Docker-to-Worker communication using AES-256-GCM with HKDF-derived purpose-specific keys
- Ticket-based session management with generation rotation (no persistent session tables)
- Short-window anti-replay protection with sequence number validation
- Zero DNS query history: no QNAME, QTYPE, or answer content is ever persisted
- Minimal state: only `client_id → latest_bundle_gen` is stored per client

**Performance**

- Hot-path queries use lightweight ticket verification (no full handshake per query)
- "Primary + Secondary Race, Tertiary Fallback" upstream strategy for optimal latency
- Optional A/AAAA record probing and reordering for improved connection quality
- Compact binary protocol (no JSON on hot path)

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

## Quick Start

### Prerequisites

- A Cloudflare account with Workers and Durable Objects enabled
- Docker and Docker Compose on your local machine or gateway
- A shared secret (ROOT_SEED): generate with `openssl rand -hex 32`

### 1. Deploy the Worker

**Option A: One-Click Deploy (Recommended)**

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/neon9809/trusted-DNS/tree/main/worker)

*Note: You will be prompted to enter a `ROOT_SEED` during deployment. Generate one using `openssl rand -hex 32`.*

**Option B: Manual Deploy**

```bash
cd worker
cp ../examples/worker.env.example .env

# Edit wrangler.toml with your ROOT_SEED and DoH upstreams
pnpm install
pnpm deploy
```

Configure the following variables in `wrangler.toml` or as Worker secrets:

```toml
[vars]
ROOT_SEED = "your-64-char-hex-seed"
DOH_UPSTREAMS = '["https://dns.google/dns-query","https://cloudflare-dns.com/dns-query","https://1.1.1.1/dns-query"]'
```

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
| `DOH_UPSTREAMS` | Yes | — | JSON array of DoH upstream URLs |
| `DOH_TIMEOUT_MS` | No | `5000` | Per-upstream timeout in milliseconds |
| `PROTOCOL_PATH` | No | `/dns-query` | Custom protocol endpoint path (must match Docker) |

## Multi-Node Deployment

**Each Docker node must use a unique `ROOT_SEED`.** The `client_id` is deterministically derived from `ROOT_SEED` via HKDF, meaning two nodes sharing the same seed will produce the same `client_id` and map to the same Durable Object instance on the Worker. This causes the following failure cascade:

| Stage | What happens |
|---|---|
| **Bootstrap** | Both nodes advance the same generation counter. The node that bootstraps second immediately invalidates the first node's KeyBundle (`ERR_OLD_GENERATION`). |
| **Query** | Both nodes hold identical tickets derived from the same `client_id` and generation. Overlapping sequence numbers trigger the anti-replay check (`ERR_REPLAY_SUSPECTED`). |
| **Refresh** | Both nodes race to refresh the same generation, continuously invalidating each other's bundles. |

The correct approach for multi-node deployments is to generate a separate `ROOT_SEED` for each node:

```bash
# Node A
ROOT_SEED=$(openssl rand -hex 32)

# Node B
ROOT_SEED=$(openssl rand -hex 32)
```

Each node then has an independent `client_id`, an independent Durable Object instance, and an independent ticket lifecycle — with no interference between nodes. The Worker supports an unlimited number of independent nodes simultaneously.

## Protocol Overview

Trusted-DNS uses a three-phase protocol model:

| Phase | Purpose | Frequency |
|---|---|---|
| **Bootstrap** | Initial authentication and first KeyBundle issuance | Low |
| **Query** | Encrypted DNS query using session tickets | High |
| **Refresh** | Obtain next-generation KeyBundle | Medium-Low |

Each `KeyBundle` contains **5 session tickets** (200 queries each) and **1 refresh ticket**, providing a total budget of **1000 queries per generation**. This design avoids full handshakes on the hot path while maintaining clear security semantics.

For detailed protocol specification, see [docs/protocol.md](docs/protocol.md).

## Security Model

Trusted-DNS is designed to **reduce the most direct and realistic pollution and tampering risks**, not to achieve absolute unobservability. Key security properties include:

- **Anti-pollution**: DNS queries bypass local plaintext DNS paths
- **Link confidentiality**: Docker-to-Worker traffic is encrypted
- **Link integrity**: AEAD authentication prevents silent tampering
- **Session ephemerality**: Tickets and keys reside only in memory
- **Generation invalidation**: New bootstrap/refresh invalidates old generations
- **Basic anti-replay**: Sequence numbers and short-window deduplication

For the complete threat model, see [docs/threat-model.md](docs/threat-model.md).

## Project Structure

```text
Trusted-DNS/
├── README.md
├── docs/
│   ├── architecture.md
│   ├── protocol.md
│   └── threat-model.md
├── worker/
│   ├── src/
│   │   ├── index.ts          # Worker entry point
│   │   ├── handlers.ts       # Bootstrap/Query/Refresh handlers
│   │   ├── protocol.ts       # Binary protocol definitions
│   │   ├── crypto.ts         # HKDF, AEAD, HMAC utilities
│   │   ├── tickets.ts        # Ticket issuance and verification
│   │   ├── resolver.ts       # DoH upstream resolver
│   │   ├── replay.ts         # Anti-replay cache
│   │   └── generation-store.ts # Durable Object for gen state
│   ├── wrangler.toml
│   └── package.json
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
| **M5** | Evaluate DoT, relay, and extension capabilities |

## License

This project is licensed under the [MIT License](LICENSE).

## Credit

The initial direction, functional constraints, and security boundaries of this project originate from **neon9809**'s continuous exploration and iteration around the following questions: how to counter local ISP DNS pollution; how to split the system into a Worker side and a Docker side; and how to converge the goals into a truly deployable open-source project within Cloudflare Worker's platform constraints. The project documentation, protocol specification, architecture design, and implementation were systematically developed by **Manus AI** based on these requirements.

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

### Worker Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `ROOT_SEED` | Yes | — | Shared 64-character hex secret (must match Docker) |
| `DOH_UPSTREAMS` | Yes | — | JSON array of DoH upstream URLs |
| `DOH_TIMEOUT_MS` | No | `5000` | Per-upstream timeout in milliseconds |

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

# Deno Platform PoC

This directory hosts the Trusted-DNS v2.1 Deno PoC entrypoint and Deno-specific state wiring.

## Deploy Button

Use the Deno Deploy button below to clone only the `platform/deno` subtree into a new Deno Deploy project:

[![Deploy on Deno](https://deno.com/button)](https://console.deno.com/new?clone=https://github.com/neon9809/trusted-DNS&path=platform/deno)

## Files

- `main.ts`: Deno HTTP entrypoint wired to shared `platform/src` service-core
- `kv-store.ts`: Deno KV-backed `GenerationStore` adapter
- `deno.json`: minimal Deno task and lint configuration
- `config/`: Deno runtime config notes or helpers

## Environment Variables

- `ROOT_SEED`: optional single-client seed for fallback mode
- `CLIENT_REGISTRY`: optional multi-client registry JSON string
- `DOH_UPSTREAMS`: DoH upstream JSON array string
- `DOH_TIMEOUT_MS`: per-upstream timeout in milliseconds
- `PROTOCOL_PATH`: protocol endpoint path, default `/dns-query`

## Local Run

```bash
cd platform/deno
deno task dev
```

## Deploy

```bash
cd platform/deno
deno deploy --project=trusted-dns-deno main.ts
```

## Scope

The goal is to validate Bootstrap, Query, and Refresh on Deno without creating a second heavyweight implementation.
The PoC keeps runtime-specific logic local and reuses shared protocol and service code from `platform/src`.

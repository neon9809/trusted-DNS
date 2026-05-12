# Deno Platform PoC

This directory hosts the Trusted-DNS v2.1 Deno PoC entrypoint and Deno-specific state wiring.

## Intended Files

- `main.ts`: Deno HTTP entrypoint wired to shared `platform/src` service-core
- `kv-store.ts`: Deno KV-backed `GenerationStore` adapter
- `config/`: Deno runtime config notes or helpers

## Scope

The goal is to validate Bootstrap, Query, and Refresh on Deno without creating a second heavyweight implementation.
The PoC keeps runtime-specific logic local and reuses shared protocol and service code from `platform/src`.

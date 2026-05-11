# Deno Platform Skeleton

This directory is reserved for the Trusted-DNS v2.1 Deno PoC.

## Intended Files

- `main.ts`: Deno HTTP entrypoint
- `kv-store.ts`: Deno KV-backed state adapter
- `config/`: Deno runtime config notes or helpers

## Scope

The first goal is to validate Bootstrap, Query, and Refresh using the existing service-core split,
not to build a second production platform immediately.

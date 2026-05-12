# Fastly Platform PoC

This directory hosts the Trusted-DNS v2.1 Fastly PoC entrypoint and Fastly-specific adapter notes.

## Intended Files

- `index.ts`: Fastly entrypoint wired to shared `platform/src` service-core
- `store.ts`: Fastly-oriented `GenerationStore` adapter shape
- `config/`: Fastly runtime config notes or helpers

## Scope

The goal is to validate runtime feasibility and adapter boundaries without expanding the state model.
The PoC keeps platform-specific logic minimal and reuses the shared core from `platform/src`.

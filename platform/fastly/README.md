# Fastly Platform PoC

This directory hosts the Trusted-DNS v2.1 Fastly PoC entrypoint and Fastly-specific adapter notes.

## Cloud Deploy

Fastly provides a Cloud Deploy button for public template repositories:

[![Deploy to Fastly](https://deploy.edgecompute.app/button)](https://deploy.edgecompute.app/deploy)

In this monorepo, the button is best treated as the target shape for a future standalone Fastly template repo.
The local deployment scaffold in this directory is prepared so that `platform/fastly` can be split out later with minimal changes.

## Files

- `index.ts`: Fastly entrypoint wired to shared `platform/src` service-core
- `store.ts`: Fastly-oriented `GenerationStore` adapter shape
- `fastly.toml`: Cloud Deploy and Fastly CLI scaffold
- `package.json`: build helper for bundling the TypeScript entrypoint
- `config/`: Fastly runtime config notes or helpers

## Environment Variables

- `ROOT_SEED`: optional single-client seed for fallback mode
- `CLIENT_REGISTRY`: optional multi-client registry JSON string
- `DOH_UPSTREAMS`: DoH upstream JSON array string
- `DOH_TIMEOUT_MS`: per-upstream timeout in milliseconds
- `PROTOCOL_PATH`: protocol endpoint path, default `/dns-query`

## Local Build

```bash
cd platform/fastly
pnpm install
pnpm build
```

## Scope

The goal is to validate runtime feasibility and adapter boundaries without expanding the state model.
The PoC keeps platform-specific logic minimal and reuses the shared core from `platform/src`.

## Current Limitation

This PoC has passed adapter-level smoke tests, but it has not yet been verified inside the native Fastly JavaScript runtime.
Treat `fastly.toml` and the Cloud Deploy button as deployment scaffolding, not as a production-ready Fastly release.

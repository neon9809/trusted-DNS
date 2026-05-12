# Platform Layout

This directory groups runtime-specific implementations for Trusted-DNS.

## Current Status

- `src/`: shared protocol, service-core, and runtime-agnostic helpers
- `cloudflare_worker/`: active Cloudflare Workers implementation and baseline runtime
- `deno/`: v2.1 Deno PoC entrypoint and adapter landing area
- `fastly/`: v2.1 Fastly PoC entrypoint and adapter landing area

## Goal

Keep platform-specific entrypoints, config wiring, and state adapters under `platform/`,
while moving reusable logic into `platform/src` so all runtimes stay lightweight and as stateless as possible.

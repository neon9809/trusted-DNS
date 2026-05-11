# Platform Layout

This directory groups runtime-specific implementations for Trusted-DNS.

## Current Status

- `worker/`: active Cloudflare Workers implementation used by v2.0
- `deno/`: v2.1 Deno PoC skeleton and landing area
- `fastly/`: v2.1 Fastly PoC skeleton and landing area

## Goal

Keep platform-specific entrypoints, config wiring, and state adapters under `platform/`,
while preserving reusable service logic inside each runtime's core/adapters layout.

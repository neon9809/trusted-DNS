# Deno Config Notes

Configuration helpers, environment loading notes, and local run instructions for the Deno PoC belong here.

## Suggested Variables

- `ROOT_SEED`
- `CLIENT_REGISTRY`
- `DOH_UPSTREAMS`
- `DOH_TIMEOUT_MS`
- `PROTOCOL_PATH`

## Notes

- Prefer `CLIENT_REGISTRY` for multi-client validation; omit it to fall back to single-client mode.
- Deno Deploy can import this subtree through the Deploy Button in `../README.md`.
- If you switch from the in-memory backend to `Deno.openKv()`, keep the state model limited to generation metadata only.

# Fastly Config Notes

Configuration helpers, deployment notes, and backend wiring details for the Fastly PoC belong here.

## Suggested Variables

- `ROOT_SEED`
- `CLIENT_REGISTRY`
- `DOH_UPSTREAMS`
- `DOH_TIMEOUT_MS`
- `PROTOCOL_PATH`

## Notes

- Fastly Cloud Deploy is oriented around a public GitHub template repository plus a valid `fastly.toml`.
- The current monorepo layout is suitable for local PoC work, but the cleanest Cloud Deploy path is to split `platform/fastly` into its own template repository later.
- The current PoC has passed adapter-level smoke tests only; native Fastly runtime validation is still a follow-up task.

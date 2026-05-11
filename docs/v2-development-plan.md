# Trusted-DNS v2 Development Plan

## 1. Document Purpose

This document defines the formal development plan for Trusted-DNS v2.

The v2 scope is intentionally limited to three platform tracks:

1. **Cloudflare Workers v2 multi-client support**
2. **Deno Deploy proof of concept**
3. **Fastly Compute proof of concept**

This plan explicitly keeps the v1 design philosophy:

- **lightweight deployment**
- **stateless hot path**
- **minimal persistent state**
- **no DNS history retention**

This document is a planning artifact only. It does not imply that all v2 work
must be delivered in a single release.

## 2. v1 Baseline

Trusted-DNS v1 is built around a strict **single Docker node <-> single Worker
deployment** model.

Current properties:

- one Worker deployment derives exactly one active `client_id`
- one Docker node uses one `ROOT_SEED`
- one Worker manages one generation namespace
- the Worker stores only minimal generation state per client
- the query hot path uses a compact binary protocol with no JSON overhead
- the Worker does not maintain session tables

v1 already includes protocol fields reserved for future multi-client upgrade:

- `spent_bundle_gen`
- `spent_query_count`
- `refresh_proof`

These fields must be reused in v2 rather than replaced with a new heavy control
plane.

## 3. v2 Goals

### 3.1 Primary Goal

Enable **one Cloudflare Worker deployment to serve multiple Docker clients**
without violating the v1 lightweight and stateless principles.

### 3.2 Secondary Goals

Build a platform-neutral Worker core that can be validated on:

- **Deno Deploy**
- **Fastly Compute**

These two platforms are proof-of-concept targets in v2, not production parity
targets on day one.

### 3.3 Non-Goals

The following are explicitly out of scope for v2:

- multi-platform production support delivered all at once
- per-query persistent logs or DNS query storage
- Worker-side session tables
- replacing the binary protocol with JSON
- introducing a Docker-side database or control-plane service
- AWS CloudFront Functions support
- Vercel Edge Functions support
- Netlify Edge Functions support

## 4. v2 Design Principles

### 4.1 Lightweight First

The Docker deployment model must remain simple:

- one container
- one environment-based configuration model
- no mandatory external database on the Docker side
- no long bootstrap sequence beyond what is already required by protocol safety

### 4.2 Stateless Worker Hot Path

The Worker query path must remain stateless in the same sense as v1:

- no persistent session table
- no query-by-query write amplification
- ticket verification remains self-contained
- only minimal client generation state is persisted

### 4.3 O(1) Persistent State Per Client

Persistent state growth must remain bounded by client count, not by ticket count
or query count.

Allowed persistent state examples:

- `client_id -> latest_bundle_gen`
- optional minimal client registry metadata
- optional minimal replay-related state only if strictly necessary

Disallowed persistent state examples:

- per-query logs
- per-ticket lifecycle logs
- per-client DNS traffic history

### 4.4 Protocol Stability

v2 should preserve as much of the existing wire format as possible.

Preferred approach:

- reuse reserved fields already present in refresh flow
- evolve semantics before expanding payload shapes
- isolate platform differences outside protocol-core

### 4.5 Platform Isolation

Cloudflare, Deno, and Fastly specific code must not be mixed into the protocol
or service logic.

The implementation should separate:

- protocol logic
- request lifecycle logic
- state interfaces
- runtime adapters

## 5. Target v2 Architecture

v2 should refactor the Worker into three logical layers.

### 5.1 Protocol Core

Responsibilities:

- header encode/decode
- ticket encode/decode
- bootstrap proof verification
- refresh proof verification
- AEAD encryption/decryption
- HKDF key derivation
- error response construction

Requirements:

- no Cloudflare-specific imports
- no Durable Object assumptions
- portable across all target platforms

### 5.2 Service Core

Responsibilities:

- bootstrap flow
- query flow
- refresh flow
- client lookup orchestration
- generation transition orchestration
- resolver orchestration

Dependencies must be abstract interfaces:

- `ClientRegistry`
- `GenerationStore`
- `ReplayGuard`
- `Resolver`
- `Clock`
- `Logger`

### 5.3 Runtime Adapter Layer

Responsibilities:

- HTTP request entrypoint
- environment and config binding
- state backend wiring
- platform-specific fetch/storage behavior
- deployment descriptors

Expected adapters:

- `cloudflare`
- `deno`
- `fastly`

## 6. Multi-Client Model

### 6.1 Core Decision

v2 should **not** reuse one shared `ROOT_SEED` for multiple Docker clients.

Instead:

- each Docker client retains its own independent seed material
- the Worker holds a lightweight registry of known clients
- request handling begins by resolving the client identity from
  `client_id_prefix`

### 6.2 Why This Model

This preserves the v1 security and isolation model:

- each Docker node gets an independent `client_id`
- each client gets an independent generation namespace
- ticket and refresh validation remain client-scoped
- client collisions are removed by design

### 6.3 Client Registry Requirements

The registry must remain minimal.

Required data:

- `client_id`
- `client_id_prefix`
- seed material or equivalent derivation source
- enabled/disabled status

Optional data:

- display name
- creation time
- notes for operator use

The registry must not store:

- query history
- ticket issue history
- DNS answers

### 6.4 Generation State Model

The v1 generation model remains valid and should be preserved:

- one minimal generation record per client
- only newest generation is authoritative
- older generations are rejected

This is a major v1 strength and should not be replaced with a heavier model.

### 6.5 Replay Model

Replay handling should remain lightweight, but v2 must document platform
semantics clearly:

- isolate-local replay detection is acceptable as a baseline
- stronger replay guarantees may be added only if they do not break the
  lightweight state model
- cross-platform semantics must be documented explicitly

## 7. Platform Strategy

## 7.1 Cloudflare Workers v2

Role:

- primary production platform
- first delivery target
- reference implementation for multi-client support

Why:

- current production architecture already exists here
- Durable Objects match the current minimal generation-state design well
- migration risk is lowest

Expected v2 outcome:

- one Worker deployment serves multiple Docker clients
- Cloudflare remains the first fully supported production platform

## 7.2 Deno Deploy PoC

Role:

- first portability validation target

Why:

- strong runtime capabilities
- standard Deno runtime
- built-in `Deno KV`
- good fit for a platform-neutral service-core validation

PoC objective:

- prove that bootstrap/query/refresh can run on Deno Deploy without changing
  the Docker protocol

PoC does not require:

- production hardening
- feature parity with Cloudflare operations
- final performance tuning

## 7.3 Fastly Compute PoC

Role:

- second portability validation target

Why:

- strong edge execution model
- explicit support for compute-oriented edge services
- support for fetch and edge data storage primitives

PoC objective:

- prove that the Worker core can operate in a Wasm-oriented edge environment
- validate storage, fetch, and binary request/response viability

PoC does not require:

- full operational parity
- broad deployment tooling parity
- final production SLA positioning

## 8. Workstreams

v2 should be split into parallel but dependency-aware workstreams.

### W1. Architecture Refactor

Scope:

- separate protocol-core from runtime logic
- define platform-neutral interfaces
- reduce Cloudflare-specific coupling

Deliverables:

- core module boundaries
- interface definitions
- updated directory structure

### W2. Multi-Client Cloudflare Support

Scope:

- introduce client registry
- route requests by `client_id_prefix`
- isolate generation state by client
- enforce stronger refresh semantics

Deliverables:

- Cloudflare multi-client Worker implementation
- registry configuration model
- migration documentation

### W3. Refresh Attestation Enforcement

Scope:

- move refresh reserved fields from parse-only to policy-enforced state
- define exact verification rules
- ensure compatibility with existing Docker transport behavior

Deliverables:

- formal refresh validation rules
- tests for valid/invalid refresh paths
- updated protocol documentation

### W4. State Adapter Abstraction

Scope:

- abstract generation store
- define registry backend interface
- define platform-specific adapters

Deliverables:

- Cloudflare state adapter
- Deno state adapter
- Fastly state adapter

### W5. Deno Deploy PoC

Scope:

- create Deno adapter
- wire Deno KV
- validate bootstrap/query/refresh

Deliverables:

- runnable Deno PoC
- deployment instructions
- known limitations list

### W6. Fastly Compute PoC

Scope:

- create Fastly adapter
- validate request parsing, DoH fetch, and state persistence
- confirm feasibility of current crypto and protocol assumptions

Deliverables:

- runnable Fastly PoC
- platform notes
- known limitations list

### W7. Documentation and Migration

Scope:

- update architecture docs
- document multi-client operations
- document platform matrix

Deliverables:

- v2 architecture document
- platform capability matrix
- migration guide

## 9. Milestones

## M0. Planning Freeze

Goal:

- agree on architecture boundaries and v2 scope

Entry criteria:

- this development plan approved

Exit criteria:

- interface plan accepted
- multi-client model accepted
- supported platform list frozen for v2

## M1. Core Refactor

Goal:

- create protocol-core and service-core boundaries

Tasks:

- move crypto/protocol/ticket logic into portable core
- define state and runtime interfaces
- keep existing Cloudflare behavior unchanged during refactor

Exit criteria:

- Cloudflare single-client mode still works
- no regression in current protocol behavior
- platform adapters are technically possible without major rewrites

## M2. Cloudflare Workers v2 Multi-Client

Goal:

- deliver one Worker serving multiple Docker clients

Tasks:

- add client registry
- replace single `env.ROOT_SEED` assumption in request flows
- route each request to a client context
- isolate generation state by client
- add operator configuration for multiple clients

Exit criteria:

- one Worker can serve at least three independent Docker clients
- one client cannot consume another client's generation namespace
- bootstrap/query/refresh are all client-isolated

## M3. Refresh Attestation Hardening

Goal:

- enforce stronger refresh acceptance rules

Tasks:

- validate `spent_bundle_gen`
- validate `spent_query_count`
- validate `refresh_proof`
- define failure semantics and error codes

Exit criteria:

- reserved refresh fields become active security inputs
- invalid refresh claims are rejected deterministically

## M4. Deno Deploy PoC

Goal:

- prove platform portability on Deno Deploy

Tasks:

- implement Deno runtime adapter
- implement Deno KV-backed state adapter
- deploy and test bootstrap/query/refresh

Exit criteria:

- end-to-end encrypted query flow works on Deno Deploy
- limitations are documented

## M5. Fastly Compute PoC

Goal:

- prove platform portability on Fastly Compute

Tasks:

- implement Fastly runtime adapter
- implement Fastly-compatible state adapter
- validate binary request/response handling and DoH relay flow

Exit criteria:

- end-to-end encrypted query flow works on Fastly Compute
- limitations are documented

## M6. Documentation Completion

Goal:

- complete all v2 planning and operator docs

Tasks:

- update architecture docs
- publish migration notes
- publish capability matrix
- publish operator guidance

Exit criteria:

- docs are sufficient for implementation and evaluation

## 10. Proposed Directory Evolution

One possible target structure:

```text
worker/
  core/
    protocol/
    crypto/
    tickets/
    service/
    interfaces/
  adapters/
    cloudflare/
    deno/
    fastly/
  platforms/
    cloudflare/
      entry.ts
      generation-store.ts
      config/
    deno/
      main.ts
      kv-store.ts
      config/
    fastly/
      index.ts
      store.ts
      config/
docs/
  v2-development-plan.md
  v2-architecture.md
  platform-matrix.md
  migration-v1-to-v2.md
```

This structure is illustrative. Exact naming can change during implementation.

## 11. Testing Strategy

### 11.1 Core Tests

Must cover:

- protocol encode/decode round trips
- ticket verification
- bootstrap proof verification
- refresh proof verification
- bundle serialization compatibility

### 11.2 Cloudflare Multi-Client Tests

Must cover:

- multiple registered clients
- correct routing by `client_id_prefix`
- cross-client ticket rejection
- generation isolation
- refresh isolation

### 11.3 Platform Smoke Tests

For Deno and Fastly PoCs:

- bootstrap success
- encrypted query success
- refresh success
- failure mode reporting

### 11.4 Regression Tests

Must ensure:

- Docker protocol remains compatible
- no DNS content is persisted
- hot path remains binary and lightweight

## 12. Acceptance Criteria

v2 planning and implementation should be considered successful only if all of
the following hold:

- Cloudflare Workers supports multiple Docker clients within one deployment
- Worker-side state remains minimal and client-scoped
- no persistent session table is introduced
- no DNS query history is persisted
- Docker deployment stays lightweight
- Deno Deploy PoC completes bootstrap/query/refresh end-to-end
- Fastly Compute PoC completes bootstrap/query/refresh end-to-end
- platform differences are isolated behind adapters

## 13. Key Risks

### R1. Cross-Client Isolation Bugs

Risk:

- a request may be routed to the wrong client context

Mitigation:

- strict client lookup path
- cross-client rejection tests
- generation-store isolation tests

### R2. Refresh Semantics Drift

Risk:

- Docker and Worker may disagree once refresh attestation becomes enforced

Mitigation:

- formal refresh rules before coding
- compatibility tests against existing Docker transport

### R3. Platform State Semantics Differ

Risk:

- Cloudflare DO, Deno KV, and Fastly storage differ in consistency and latency

Mitigation:

- keep state contract minimal
- document guarantees per platform
- avoid overfitting logic to strong consistency assumptions

### R4. Portability Refactor Becomes Too Large

Risk:

- abstraction work may destabilize the Cloudflare path

Mitigation:

- refactor in phases
- keep Cloudflare as the first reference target
- do not start both PoCs before M2 is stable

### R5. Over-Engineering

Risk:

- platform abstraction may introduce too much framework code

Mitigation:

- keep interfaces narrow
- avoid speculative abstractions
- only support the three approved platform tracks

## 14. Delivery Order Recommendation

Recommended execution order:

1. planning freeze
2. core refactor
3. Cloudflare Workers v2 multi-client
4. refresh attestation hardening
5. Deno Deploy PoC
6. Fastly Compute PoC
7. final documentation pass

This order keeps the primary product goal ahead of portability experiments.

## 15. Release Strategy Recommendation

Recommended release labeling:

- **v2.0**: Cloudflare Workers multi-client support
- **v2.1**: Deno Deploy PoC or experimental adapter
- **v2.2**: Fastly Compute PoC or experimental adapter

Reason:

- the main business value is multi-client support on the existing production
  platform
- PoCs should not block the primary release

## 16. Immediate Next Steps

The next planning artifacts recommended after this document are:

1. `docs/v2-architecture.md`
2. `docs/platform-matrix.md`
3. `docs/migration-v1-to-v2.md`
4. implementation task breakdown by milestone

## 17. Final Position

Trusted-DNS v2 should be built as a **multi-client evolution of the existing
stateless protocol architecture**, not as a heavy redesign.

The correct v2 path is:

- **first** make Cloudflare Workers support multiple clients cleanly
- **then** validate portability through Deno Deploy and Fastly Compute PoCs
- **always** preserve lightweight deployment and minimal persistent state

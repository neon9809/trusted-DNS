# Trusted-DNS Threat Model

## Scope

Trusted-DNS is designed to **reduce the most direct and realistic DNS pollution and tampering risks** in environments where the local ISP performs active DNS injection or modification. It is **not** designed to achieve absolute unobservability or resist nation-state-level traffic analysis.

## Threat Categories

### T1: Local DNS Pollution (Primary Threat)

**Description**: The local ISP injects forged DNS responses or modifies legitimate responses in transit.

**Mitigation**: All DNS queries bypass the local plaintext DNS path entirely. Queries are encrypted with AES-256-GCM and sent to the Worker over HTTPS. The ISP cannot see or modify the DNS query content.

**Residual Risk**: The ISP can observe that HTTPS traffic is being sent to a Cloudflare Worker endpoint, but cannot determine the DNS query content.

### T2: Man-in-the-Middle on Docker-Worker Link

**Description**: An attacker intercepts and modifies traffic between the Docker node and the Worker.

**Mitigation**: The transport uses HTTPS (TLS) for the outer layer and AES-256-GCM AEAD for the inner protocol layer. Both layers must be compromised simultaneously to tamper with DNS queries.

**Residual Risk**: If the attacker compromises the TLS certificate chain (e.g., via a rogue CA), the inner AEAD layer still protects query integrity and confidentiality.

### T3: Replay Attacks

**Description**: An attacker captures and replays a valid query request to trigger duplicate upstream queries or observe timing patterns.

**Mitigation**: Each query uses a unique `(ticket_id, seq)` pair. The Worker maintains a short-window anti-replay cache that rejects duplicate pairs within the TTL window. Sequence numbers must fall within the ticket's `[counter_base, counter_base + query_budget)` range.

**Residual Risk**: The anti-replay cache is per-Worker-isolate and may not be globally consistent across Cloudflare's edge network. A sophisticated attacker could potentially replay a request to a different isolate within the deduplication window.

### T4: Ticket Forgery

**Description**: An attacker attempts to forge session tickets to make unauthorized queries.

**Mitigation**: Session tickets are authenticated with HMAC-SHA256 using a key derived from the shared `root_seed`. Without knowledge of the root seed, an attacker cannot produce valid ticket tags.

**Residual Risk**: If the `root_seed` is compromised, all security properties are lost. The root seed must be kept confidential.

### T5: Generation Rollback

**Description**: An attacker attempts to use tickets from an older generation after a new generation has been issued.

**Mitigation**: The Worker stores the latest generation number per client in a Durable Object. Any ticket with a generation older than the stored value is rejected.

**Residual Risk**: Durable Object consistency is eventually consistent within Cloudflare's network. There may be a brief window during generation transitions where old-generation tickets are still accepted.

### T6: DoH Upstream Compromise

**Description**: A DoH upstream resolver returns poisoned responses.

**Mitigation**: The system uses multiple upstreams with a race strategy. If one upstream is compromised, the other may return a correct response first. However, the system does not perform DNSSEC validation.

**Residual Risk**: If all configured upstreams are compromised or return identical poisoned responses, the Docker node will relay the poisoned response to clients.

### T7: Traffic Analysis

**Description**: An observer analyzes traffic patterns (timing, size, frequency) to infer DNS query behavior.

**Mitigation**: Limited. The binary protocol has relatively fixed overhead, but query timing and response sizes can still leak information about the queried domains.

**Residual Risk**: Traffic analysis is explicitly out of scope for this version. Future versions may consider padding or traffic shaping.

### T8: Root Seed Compromise

**Description**: The shared `root_seed` is leaked or stolen.

**Impact**: Complete compromise of all security properties. The attacker can:

- Forge tickets and make unauthorized queries
- Decrypt intercepted query/response traffic
- Impersonate the Docker node

**Mitigation**: The root seed should be generated with a cryptographically secure random number generator (`openssl rand -hex 32`) and stored securely. It should not be committed to version control or transmitted over insecure channels.

## Trust Boundaries

| Boundary | Trust Level |
|---|---|
| LAN clients → Docker node | Trusted (same network) |
| Docker node → Cloudflare Worker | Encrypted (HTTPS + AEAD) |
| Worker → DoH upstreams | Trusted (HTTPS to reputable providers) |
| Cloudflare platform | Trusted (Worker execution environment) |

## Explicit Non-Goals

The following are explicitly **not** goals of Trusted-DNS v1:

- **DNSSEC validation**: The system relays DNS responses as-is from upstreams
- **Traffic analysis resistance**: No padding or traffic shaping is implemented
- **Multi-user support**: The system is designed for single-user or single-household deployment
- **Anonymity**: The Worker operator can observe all DNS queries
- **Censorship circumvention**: The system does not attempt to bypass IP-level blocking

## Recommendations

1. **Rotate root_seed periodically** (e.g., monthly) by redeploying both Worker and Docker
2. **Use multiple diverse DoH upstreams** (e.g., Google + Cloudflare + Quad9)
3. **Monitor Docker node logs** for unusual error patterns that may indicate attacks
4. **Keep the Docker image updated** to receive security patches
5. **Do not expose the Worker endpoint** beyond what is necessary (consider Cloudflare Access)

# Trusted-DNS Protocol Specification

**Version**: 1 (0x01)

## Overview

The Trusted-DNS protocol is a compact binary protocol designed for encrypted DNS query relay between a Docker node and a Cloudflare Worker. It operates over HTTPS (POST) with `Content-Type: application/octet-stream`.

All multi-byte integers are encoded in **big-endian** (network byte order).

## Message Structure

Every message consists of a **32-byte fixed header** followed by a **variable-length payload**.

```text
┌──────────────────────────────────────────────────┐
│                   Header (32 bytes)              │
├──────────────────────────────────────────────────┤
│                   Payload (variable)             │
└──────────────────────────────────────────────────┘
```

### Header Format

| Offset | Size | Field | Description |
|---|---|---|---|
| 0 | 1 | `ver` | Protocol version (0x01) |
| 1 | 1 | `msg_type` | Message type identifier |
| 2 | 2 | `flags` | Reserved flags |
| 4 | 8 | `client_id_prefix` | First 8 bytes of client_id |
| 12 | 8 | `bundle_gen` | KeyBundle generation number |
| 20 | 2 | `ticket_id` | Session ticket identifier |
| 22 | 4 | `seq` | Sequence number |
| 26 | 4 | `payload_len` | Payload length in bytes |
| 30 | 2 | `header_mac` | Header integrity check (reserved) |

### Message Types

| Code | Name | Direction |
|---|---|---|
| 0x01 | `BOOTSTRAP_REQ` | Docker → Worker |
| 0x02 | `BOOTSTRAP_RESP` | Worker → Docker |
| 0x03 | `QUERY_REQ` | Docker → Worker |
| 0x04 | `QUERY_RESP` | Worker → Docker |
| 0x05 | `REFRESH_REQ` | Docker → Worker |
| 0x06 | `REFRESH_RESP` | Worker → Docker |
| 0x7F | `ERROR_RESP` | Worker → Docker |

### Error Codes

| Code | Name | Description |
|---|---|---|
| 0x01 | `BAD_VERSION` | Unsupported protocol version |
| 0x02 | `BAD_TYPE` | Unknown message type |
| 0x03 | `BAD_TICKET` | Ticket verification failed |
| 0x04 | `EXPIRED` | Ticket or timestamp expired |
| 0x05 | `OLD_GENERATION` | Ticket from superseded generation |
| 0x06 | `REPLAY_SUSPECTED` | Replay or seq window violation |
| 0x07 | `DECRYPT_FAILED` | AEAD decryption failure |
| 0x08 | `UPSTREAM_FAILURE` | All DoH upstreams failed |
| 0x09 | `RATE_LIMITED` | Rate limit exceeded |
| 0x0A | `INTERNAL` | Internal server error |

## Cryptographic Primitives

### Key Derivation (HKDF-SHA256)

All keys are derived from a shared `root_seed` (32 bytes) using HKDF-SHA256 with a fixed zero salt and purpose-specific info strings:

| Key | Info String | Size |
|---|---|---|
| `bootstrap_key` | `trusted-dns/bootstrap` | 32 bytes |
| `ticket_auth_key` | `trusted-dns/ticket-mac` | 32 bytes |
| `refresh_auth_key` | `trusted-dns/refresh-mac` | 32 bytes |
| `bundle_wrap_key` | `trusted-dns/bundle-wrap` | 32 bytes |
| `client_id` | `trusted-dns/client-id` | 32 bytes |
| `req_key` | `trusted-dns/query/req` | 32 bytes (from resume_seed) |
| `resp_key` | `trusted-dns/query/resp` | 32 bytes (from resume_seed) |

### AEAD Encryption (AES-256-GCM)

- **Key size**: 256 bits (32 bytes)
- **Nonce size**: 96 bits (12 bytes), randomly generated
- **Tag size**: 128 bits (16 bytes), appended to ciphertext
- **AAD**: Protocol header bytes (varies by context)

### Ticket Authentication (HMAC-SHA256)

Ticket tags are computed as the first 16 bytes of HMAC-SHA256 over the ticket data (excluding the tag field itself).

## Session Ticket Structure (114 bytes)

| Offset | Size | Field | Description |
|---|---|---|---|
| 0 | 2 | `ticket_id` | Unique ticket identifier (1-based) |
| 2 | 1 | `slot` | Ticket slot index (0-based) |
| 3 | 1 | `reserved` | Reserved (0x00) |
| 4 | 32 | `client_id` | Full 32-byte client identifier |
| 36 | 8 | `bundle_gen` | Generation number |
| 44 | 8 | `not_before_ms` | Validity start (Unix ms) |
| 52 | 8 | `not_after_ms` | Validity end (Unix ms) |
| 60 | 2 | `query_budget` | Max queries for this ticket |
| 62 | 4 | `counter_base` | Starting sequence number |
| 66 | 32 | `resume_seed` | Seed for deriving query keys |
| 98 | 16 | `ticket_tag` | HMAC-SHA256 truncated tag |

## Refresh Ticket Structure (122 bytes)

| Offset | Size | Field | Description |
|---|---|---|---|
| 0 | 32 | `client_id` | Full 32-byte client identifier |
| 32 | 8 | `bundle_gen` | Generation number |
| 40 | 8 | `not_before_ms` | Validity start (Unix ms) |
| 48 | 8 | `not_after_ms` | Validity end (Unix ms) |
| 56 | 2 | `rotate_after_queries` | Trigger refresh after N queries |
| 58 | 16 | `refresh_nonce` | Random nonce for refresh |
| 74 | 32 | `refresh_seed` | Seed for refresh proof |
| 106 | 16 | `refresh_tag` | HMAC-SHA256 truncated tag |

## KeyBundle Structure

A KeyBundle is issued during Bootstrap or Refresh and contains:

| Field | Description |
|---|---|
| `bundle_gen` | Generation number (monotonically increasing) |
| `issued_at_ms` | Issuance timestamp (Unix ms) |
| `expire_at_ms` | Expiration timestamp (Unix ms) |
| `worker_kid` | Worker key identifier |
| `policy` | Session policy parameters |
| `session_tickets[5]` | Array of 5 session tickets |
| `refresh_ticket` | Single refresh ticket |

### Default Policy

| Parameter | Default | Description |
|---|---|---|
| `tickets_per_bundle` | 5 | Session tickets per bundle |
| `queries_per_ticket` | 200 | Max queries per ticket |
| `queries_per_bundle` | 1000 | Total queries per bundle |
| `max_clock_skew_ms` | 300000 | Allowed clock skew (5 min) |
| `anti_replay_window` | 64 | Replay detection window |
| `ticket_lifetime_ms` | 3600000 | Ticket validity (1 hour) |

## Phase Details

### Bootstrap Phase

**Request payload** (44 bytes):

| Offset | Size | Field |
|---|---|---|
| 0 | 16 | `boot_nonce` (random) |
| 16 | 8 | `timestamp_ms` (Unix ms) |
| 24 | 16 | `bootstrap_proof` (HMAC) |
| 40 | 4 | `capabilities` (bitmask) |

**Response payload** (variable):

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | `server_time_ms` |
| 8 | 8 | `bundle_gen` |
| 16 | 12 | `nonce` (AEAD) |
| 28 | var | `ciphertext` (encrypted KeyBundle) |

### Query Phase

**Request payload** (variable):

| Offset | Size | Field |
|---|---|---|
| 0 | 114 | `ticket_blob` (SessionTicket) |
| 114 | 12 | `nonce` (AEAD) |
| 126 | var | `ciphertext` (encrypted DNS query) |

**Response payload** (variable):

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `resolver_id` |
| 1 | 1 | `transport_flags` |
| 2 | 2 | `upstream_rtt_ms` |
| 4 | 12 | `nonce` (AEAD) |
| 16 | var | `ciphertext` (encrypted DNS response) |

### Refresh Phase

**Request payload** (variable):

| Offset | Size | Field |
|---|---|---|
| 0 | 122 | `refresh_ticket_blob` |
| 122 | 8 | `spent_bundle_gen` |
| 130 | 4 | `spent_query_count` |
| 134 | 32 | `refresh_proof` |
| 166 | 1 | `requested_reason` |

**Response payload**: Same format as Bootstrap response.

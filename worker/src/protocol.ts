/**
 * Trusted-DNS Protocol Constants and Types
 *
 * Defines the binary protocol structures, message types, error codes,
 * and key derivation utilities shared across Worker modules.
 */

// ─── Protocol Version ───────────────────────────────────────────────
export const PROTOCOL_VERSION = 0x01;

// ─── Message Types ──────────────────────────────────────────────────
export const MSG_BOOTSTRAP_REQ  = 0x01;
export const MSG_BOOTSTRAP_RESP = 0x02;
export const MSG_QUERY_REQ      = 0x03;
export const MSG_QUERY_RESP     = 0x04;
export const MSG_REFRESH_REQ    = 0x05;
export const MSG_REFRESH_RESP   = 0x06;
export const MSG_ERROR_RESP     = 0x7f;

// ─── Error Codes ────────────────────────────────────────────────────
export const ERR_BAD_VERSION      = 0x01;
export const ERR_BAD_TYPE         = 0x02;
export const ERR_BAD_TICKET       = 0x03;
export const ERR_EXPIRED          = 0x04;
export const ERR_OLD_GENERATION   = 0x05;
export const ERR_REPLAY_SUSPECTED = 0x06;
export const ERR_DECRYPT_FAILED   = 0x07;
export const ERR_UPSTREAM_FAILURE = 0x08;
export const ERR_RATE_LIMITED     = 0x09;
export const ERR_INTERNAL         = 0x0a;

// ─── Fixed Sizes ────────────────────────────────────────────────────
export const HEADER_SIZE        = 32;
export const CLIENT_ID_SIZE     = 32;
export const CLIENT_ID_PREFIX   = 8;
export const NONCE_SIZE         = 12;
export const TAG_SIZE           = 16;
export const TICKET_TAG_SIZE    = 16;
export const RESUME_SEED_SIZE   = 32;
export const REFRESH_SEED_SIZE  = 32;
export const REFRESH_NONCE_SIZE = 16;
export const BOOT_NONCE_SIZE    = 16;

// ─── Default Policy Values ──────────────────────────────────────────
export const DEFAULT_TICKETS_PER_BUNDLE  = 5;
export const DEFAULT_QUERIES_PER_TICKET  = 200;
export const DEFAULT_QUERIES_PER_BUNDLE  = 1000;
export const DEFAULT_MAX_CLOCK_SKEW_MS   = 300_000;
export const DEFAULT_ANTI_REPLAY_WINDOW  = 64;
export const DEFAULT_TICKET_LIFETIME_MS  = 3_600_000; // 1 hour

// ─── Interfaces ─────────────────────────────────────────────────────

/** 32-byte fixed protocol header (big-endian) */
export interface ProtocolHeader {
  ver: number;             // 1 byte
  msgType: number;         // 1 byte
  flags: number;           // 2 bytes
  clientIdPrefix: Uint8Array; // 8 bytes
  bundleGen: bigint;       // 8 bytes (u64)
  ticketId: number;        // 2 bytes
  seq: number;             // 4 bytes
  payloadLen: number;      // 4 bytes
  headerMac: number;       // 2 bytes
}

export interface Policy {
  ticketsPerBundle: number;
  queriesPerTicket: number;
  queriesPerBundle: number;
  maxClockSkewMs: number;
  antiReplayWindow: number;
  ticketLifetimeMs: number;
}

export interface SessionTicket {
  ticketId: number;        // u16
  slot: number;            // u8
  reserved: number;        // u8
  clientId: Uint8Array;    // 32 bytes
  bundleGen: bigint;       // u64
  notBeforeMs: bigint;     // u64
  notAfterMs: bigint;      // u64
  queryBudget: number;     // u16
  counterBase: number;     // u32
  resumeSeed: Uint8Array;  // 32 bytes
  ticketTag: Uint8Array;   // 16 bytes
}

export interface RefreshTicket {
  clientId: Uint8Array;    // 32 bytes
  bundleGen: bigint;       // u64
  notBeforeMs: bigint;     // u64
  notAfterMs: bigint;      // u64
  rotateAfterQueries: number; // u16
  refreshNonce: Uint8Array;   // 16 bytes
  refreshSeed: Uint8Array;    // 32 bytes
  refreshTag: Uint8Array;     // 16 bytes
}

export interface KeyBundle {
  bundleGen: bigint;
  issuedAtMs: bigint;
  expireAtMs: bigint;
  workerKid: number;
  policy: Policy;
  sessionTickets: SessionTicket[];
  refreshTicket: RefreshTicket;
}

// ─── Header Encoding / Decoding ─────────────────────────────────────

export function encodeHeader(h: ProtocolHeader): Uint8Array {
  const buf = new ArrayBuffer(HEADER_SIZE);
  const dv = new DataView(buf);
  const u8 = new Uint8Array(buf);

  dv.setUint8(0, h.ver);
  dv.setUint8(1, h.msgType);
  dv.setUint16(2, h.flags, false);
  u8.set(h.clientIdPrefix.subarray(0, 8), 4);
  dv.setBigUint64(12, h.bundleGen, false);
  dv.setUint16(20, h.ticketId, false);
  dv.setUint32(22, h.seq, false);
  dv.setUint32(26, h.payloadLen, false);
  dv.setUint16(30, h.headerMac, false);

  return u8;
}

export function decodeHeader(data: Uint8Array): ProtocolHeader {
  if (data.length < HEADER_SIZE) {
    throw new Error(`Header too short: ${data.length} < ${HEADER_SIZE}`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);

  return {
    ver: dv.getUint8(0),
    msgType: dv.getUint8(1),
    flags: dv.getUint16(2, false),
    clientIdPrefix: data.slice(4, 12),
    bundleGen: dv.getBigUint64(12, false),
    ticketId: dv.getUint16(20, false),
    seq: dv.getUint32(22, false),
    payloadLen: dv.getUint32(26, false),
    headerMac: dv.getUint16(30, false),
  };
}

// ─── Session Ticket Serialization ───────────────────────────────────

export const SESSION_TICKET_SIZE = 2 + 1 + 1 + 32 + 8 + 8 + 8 + 2 + 4 + 32 + 16; // = 114

export function encodeSessionTicket(t: SessionTicket): Uint8Array {
  const buf = new ArrayBuffer(SESSION_TICKET_SIZE);
  const dv = new DataView(buf);
  const u8 = new Uint8Array(buf);
  let off = 0;

  dv.setUint16(off, t.ticketId, false); off += 2;
  dv.setUint8(off, t.slot); off += 1;
  dv.setUint8(off, t.reserved); off += 1;
  u8.set(t.clientId.subarray(0, 32), off); off += 32;
  dv.setBigUint64(off, t.bundleGen, false); off += 8;
  dv.setBigUint64(off, t.notBeforeMs, false); off += 8;
  dv.setBigUint64(off, t.notAfterMs, false); off += 8;
  dv.setUint16(off, t.queryBudget, false); off += 2;
  dv.setUint32(off, t.counterBase, false); off += 4;
  u8.set(t.resumeSeed.subarray(0, 32), off); off += 32;
  u8.set(t.ticketTag.subarray(0, 16), off);

  return u8;
}

export function decodeSessionTicket(data: Uint8Array): SessionTicket {
  if (data.length < SESSION_TICKET_SIZE) {
    throw new Error(`SessionTicket too short: ${data.length}`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let off = 0;

  const ticketId = dv.getUint16(off, false); off += 2;
  const slot = dv.getUint8(off); off += 1;
  const reserved = dv.getUint8(off); off += 1;
  const clientId = data.slice(off, off + 32); off += 32;
  const bundleGen = dv.getBigUint64(off, false); off += 8;
  const notBeforeMs = dv.getBigUint64(off, false); off += 8;
  const notAfterMs = dv.getBigUint64(off, false); off += 8;
  const queryBudget = dv.getUint16(off, false); off += 2;
  const counterBase = dv.getUint32(off, false); off += 4;
  const resumeSeed = data.slice(off, off + 32); off += 32;
  const ticketTag = data.slice(off, off + 16);

  return {
    ticketId, slot, reserved, clientId, bundleGen,
    notBeforeMs, notAfterMs, queryBudget, counterBase,
    resumeSeed, ticketTag,
  };
}

// ─── Refresh Ticket Serialization ───────────────────────────────────

export const REFRESH_TICKET_SIZE = 32 + 8 + 8 + 8 + 2 + 16 + 32 + 16; // = 122

export function encodeRefreshTicket(t: RefreshTicket): Uint8Array {
  const buf = new ArrayBuffer(REFRESH_TICKET_SIZE);
  const dv = new DataView(buf);
  const u8 = new Uint8Array(buf);
  let off = 0;

  u8.set(t.clientId.subarray(0, 32), off); off += 32;
  dv.setBigUint64(off, t.bundleGen, false); off += 8;
  dv.setBigUint64(off, t.notBeforeMs, false); off += 8;
  dv.setBigUint64(off, t.notAfterMs, false); off += 8;
  dv.setUint16(off, t.rotateAfterQueries, false); off += 2;
  u8.set(t.refreshNonce.subarray(0, 16), off); off += 16;
  u8.set(t.refreshSeed.subarray(0, 32), off); off += 32;
  u8.set(t.refreshTag.subarray(0, 16), off);

  return u8;
}

export function decodeRefreshTicket(data: Uint8Array): RefreshTicket {
  if (data.length < REFRESH_TICKET_SIZE) {
    throw new Error(`RefreshTicket too short: ${data.length}`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let off = 0;

  const clientId = data.slice(off, off + 32); off += 32;
  const bundleGen = dv.getBigUint64(off, false); off += 8;
  const notBeforeMs = dv.getBigUint64(off, false); off += 8;
  const notAfterMs = dv.getBigUint64(off, false); off += 8;
  const rotateAfterQueries = dv.getUint16(off, false); off += 2;
  const refreshNonce = data.slice(off, off + 16); off += 16;
  const refreshSeed = data.slice(off, off + 32); off += 32;
  const refreshTag = data.slice(off, off + 16);

  return {
    clientId, bundleGen, notBeforeMs, notAfterMs,
    rotateAfterQueries, refreshNonce, refreshSeed, refreshTag,
  };
}

// ─── Error Response Builder ─────────────────────────────────────────

export function buildErrorResponse(
  clientIdPrefix: Uint8Array,
  bundleGen: bigint,
  errorCode: number,
  detail?: string,
): Uint8Array {
  const detailBytes = detail
    ? new TextEncoder().encode(detail.substring(0, 128))
    : new Uint8Array(0);
  const payloadLen = 1 + detailBytes.length;

  const header = encodeHeader({
    ver: PROTOCOL_VERSION,
    msgType: MSG_ERROR_RESP,
    flags: 0,
    clientIdPrefix,
    bundleGen,
    ticketId: 0,
    seq: 0,
    payloadLen,
    headerMac: 0,
  });

  const result = new Uint8Array(HEADER_SIZE + payloadLen);
  result.set(header, 0);
  result[HEADER_SIZE] = errorCode;
  if (detailBytes.length > 0) {
    result.set(detailBytes, HEADER_SIZE + 1);
  }
  return result;
}

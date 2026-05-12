/**
 * Trusted-DNS Ticket Issuance and Verification
 *
 * Handles the creation and validation of SessionTickets, RefreshTickets,
 * and KeyBundles. The Worker uses these to issue credentials during
 * Bootstrap/Refresh and to verify them during Query.
 */

import {
  SessionTicket,
  RefreshTicket,
  KeyBundle,
  Policy,
  DEFAULT_TICKETS_PER_BUNDLE,
  DEFAULT_QUERIES_PER_TICKET,
  DEFAULT_QUERIES_PER_BUNDLE,
  DEFAULT_MAX_CLOCK_SKEW_MS,
  DEFAULT_ANTI_REPLAY_WINDOW,
  DEFAULT_TICKET_LIFETIME_MS,
  encodeSessionTicket,
  encodeRefreshTicket,
  decodeSessionTicket,
  decodeRefreshTicket,
  SESSION_TICKET_SIZE,
  REFRESH_TICKET_SIZE,
} from './protocol';

import {
  computeTicketTag,
  verifyTicketTag,
  randomBytes,
  hkdfDerive,
} from './crypto';

// ─── Default Policy ─────────────────────────────────────────────────

export function defaultPolicy(): Policy {
  return {
    ticketsPerBundle: DEFAULT_TICKETS_PER_BUNDLE,
    queriesPerTicket: DEFAULT_QUERIES_PER_TICKET,
    queriesPerBundle: DEFAULT_QUERIES_PER_BUNDLE,
    maxClockSkewMs: DEFAULT_MAX_CLOCK_SKEW_MS,
    antiReplayWindow: DEFAULT_ANTI_REPLAY_WINDOW,
    ticketLifetimeMs: DEFAULT_TICKET_LIFETIME_MS,
  };
}

// ─── Issue KeyBundle ────────────────────────────────────────────────

/**
 * Issue a new KeyBundle for a client.
 *
 * @param clientId - 32-byte client identifier
 * @param bundleGen - The generation number for this bundle
 * @param ticketAuthKey - Key for computing session ticket tags
 * @param refreshAuthKey - Key for computing refresh ticket tags
 * @param policy - Policy parameters
 */
export async function issueKeyBundle(
  clientId: Uint8Array,
  bundleGen: bigint,
  ticketAuthKey: Uint8Array,
  refreshAuthKey: Uint8Array,
  policy: Policy = defaultPolicy(),
): Promise<KeyBundle> {
  const now = BigInt(Date.now());
  const lifetime = BigInt(policy.ticketLifetimeMs);
  const issuedAtMs = now;
  const expireAtMs = now + lifetime;

  // Issue session tickets
  const sessionTickets: SessionTicket[] = [];
  for (let slot = 0; slot < policy.ticketsPerBundle; slot++) {
    const ticketId = slot + 1; // 1-based
    const resumeSeed = randomBytes(32);
    const counterBase = slot * policy.queriesPerTicket;

    // Build ticket without tag first, then compute tag
    const ticket: SessionTicket = {
      ticketId,
      slot,
      reserved: 0,
      clientId: clientId.slice(),
      bundleGen,
      notBeforeMs: issuedAtMs,
      notAfterMs: expireAtMs,
      queryBudget: policy.queriesPerTicket,
      counterBase,
      resumeSeed,
      ticketTag: new Uint8Array(16), // placeholder
    };

    // Compute tag over ticket data (excluding the tag field itself)
    const ticketBytes = encodeSessionTicket(ticket);
    const dataForTag = ticketBytes.slice(0, SESSION_TICKET_SIZE - 16);
    ticket.ticketTag = await computeTicketTag(ticketAuthKey, dataForTag);

    sessionTickets.push(ticket);
  }

  // Issue refresh ticket
  const refreshNonce = randomBytes(16);
  const refreshSeed = randomBytes(32);

  const refreshTicket: RefreshTicket = {
    clientId: clientId.slice(),
    bundleGen,
    notBeforeMs: issuedAtMs,
    notAfterMs: expireAtMs,
    rotateAfterQueries: policy.queriesPerBundle,
    refreshNonce,
    refreshSeed,
    refreshTag: new Uint8Array(16), // placeholder
  };

  const refreshBytes = encodeRefreshTicket(refreshTicket);
  const refreshDataForTag = refreshBytes.slice(0, REFRESH_TICKET_SIZE - 16);
  refreshTicket.refreshTag = await computeTicketTag(refreshAuthKey, refreshDataForTag);

  return {
    bundleGen,
    issuedAtMs,
    expireAtMs,
    workerKid: 1,
    policy,
    sessionTickets,
    refreshTicket,
  };
}

// ─── Verify Session Ticket ──────────────────────────────────────────

/**
 * Verify a session ticket's authenticity and validity.
 *
 * @returns null if valid, or an error string describing the failure
 */
export async function verifySessionTicket(
  ticket: SessionTicket,
  ticketAuthKey: Uint8Array,
  expectedClientIdPrefix: Uint8Array,
  expectedBundleGen: bigint,
  nowMs: bigint,
  maxClockSkewMs: number = DEFAULT_MAX_CLOCK_SKEW_MS,
): Promise<string | null> {
  // 1. Verify tag
  const ticketBytes = encodeSessionTicket(ticket);
  const dataForTag = ticketBytes.slice(0, SESSION_TICKET_SIZE - 16);
  const tagValid = await verifyTicketTag(ticketAuthKey, dataForTag, ticket.ticketTag);
  if (!tagValid) {
    return 'ticket tag verification failed';
  }

  // 2. Verify client_id prefix matches
  const ticketPrefix = ticket.clientId.slice(0, 8);
  let prefixMatch = true;
  for (let i = 0; i < 8; i++) {
    if (ticketPrefix[i] !== expectedClientIdPrefix[i]) {
      prefixMatch = false;
      break;
    }
  }
  if (!prefixMatch) {
    return 'client_id prefix mismatch';
  }

  // 3. Verify generation
  if (ticket.bundleGen !== expectedBundleGen) {
    return 'bundle generation mismatch';
  }

  // 4. Verify time window
  const skew = BigInt(maxClockSkewMs);
  if (nowMs < ticket.notBeforeMs - skew) {
    return 'ticket not yet valid';
  }
  if (nowMs > ticket.notAfterMs + skew) {
    return 'ticket expired';
  }

  return null; // valid
}

// ─── Verify Refresh Ticket ──────────────────────────────────────────

export async function verifyRefreshTicket(
  ticket: RefreshTicket,
  refreshAuthKey: Uint8Array,
  expectedClientIdPrefix: Uint8Array,
  expectedBundleGen: bigint,
  nowMs: bigint,
  maxClockSkewMs: number = DEFAULT_MAX_CLOCK_SKEW_MS,
): Promise<string | null> {
  // 1. Verify tag
  const ticketBytes = encodeRefreshTicket(ticket);
  const dataForTag = ticketBytes.slice(0, REFRESH_TICKET_SIZE - 16);
  const tagValid = await verifyTicketTag(refreshAuthKey, dataForTag, ticket.refreshTag);
  if (!tagValid) {
    return 'refresh ticket tag verification failed';
  }

  // 2. Verify client_id prefix
  const ticketPrefix = ticket.clientId.slice(0, 8);
  let prefixMatch = true;
  for (let i = 0; i < 8; i++) {
    if (ticketPrefix[i] !== expectedClientIdPrefix[i]) {
      prefixMatch = false;
      break;
    }
  }
  if (!prefixMatch) {
    return 'client_id prefix mismatch';
  }

  // 3. Verify generation
  if (ticket.bundleGen !== expectedBundleGen) {
    return 'bundle generation mismatch';
  }

  // 4. Verify time window
  const skew = BigInt(maxClockSkewMs);
  if (nowMs < ticket.notBeforeMs - skew) {
    return 'refresh ticket not yet valid';
  }
  if (nowMs > ticket.notAfterMs + skew) {
    return 'refresh ticket expired';
  }

  return null;
}

// ─── Serialize KeyBundle for encrypted transmission ─────────────────

export function serializeKeyBundle(bundle: KeyBundle): Uint8Array {
  // Layout: bundleGen(8) + issuedAtMs(8) + expireAtMs(8) + workerKid(2)
  //       + policy(20) + 5*SessionTicket + RefreshTicket
  const policySize = 2 + 2 + 2 + 4 + 2 + 8; // = 20
  const totalSize = 8 + 8 + 8 + 2 + policySize
    + bundle.sessionTickets.length * SESSION_TICKET_SIZE
    + REFRESH_TICKET_SIZE;

  const buf = new ArrayBuffer(totalSize);
  const dv = new DataView(buf);
  const u8 = new Uint8Array(buf);
  let off = 0;

  dv.setBigUint64(off, bundle.bundleGen, false); off += 8;
  dv.setBigUint64(off, bundle.issuedAtMs, false); off += 8;
  dv.setBigUint64(off, bundle.expireAtMs, false); off += 8;
  dv.setUint16(off, bundle.workerKid, false); off += 2;

  // Policy
  const p = bundle.policy;
  dv.setUint8(off, p.ticketsPerBundle); off += 1;
  dv.setUint8(off, 0); off += 1; // padding
  dv.setUint16(off, p.queriesPerTicket, false); off += 2;
  dv.setUint16(off, p.queriesPerBundle, false); off += 2;
  dv.setUint32(off, p.maxClockSkewMs, false); off += 4;
  dv.setUint16(off, p.antiReplayWindow, false); off += 2;
  dv.setBigUint64(off, BigInt(p.ticketLifetimeMs), false); off += 8;

  // Session tickets
  for (const t of bundle.sessionTickets) {
    u8.set(encodeSessionTicket(t), off);
    off += SESSION_TICKET_SIZE;
  }

  // Refresh ticket
  u8.set(encodeRefreshTicket(bundle.refreshTicket), off);

  return u8;
}

export function deserializeKeyBundle(data: Uint8Array): KeyBundle {
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let off = 0;

  const bundleGen = dv.getBigUint64(off, false); off += 8;
  const issuedAtMs = dv.getBigUint64(off, false); off += 8;
  const expireAtMs = dv.getBigUint64(off, false); off += 8;
  const workerKid = dv.getUint16(off, false); off += 2;

  // Policy
  const ticketsPerBundle = dv.getUint8(off); off += 1;
  off += 1; // padding
  const queriesPerTicket = dv.getUint16(off, false); off += 2;
  const queriesPerBundle = dv.getUint16(off, false); off += 2;
  const maxClockSkewMs = dv.getUint32(off, false); off += 4;
  const antiReplayWindow = dv.getUint16(off, false); off += 2;
  const ticketLifetimeMs = Number(dv.getBigUint64(off, false)); off += 8;

  const policy: Policy = {
    ticketsPerBundle, queriesPerTicket, queriesPerBundle,
    maxClockSkewMs, antiReplayWindow, ticketLifetimeMs,
  };

  // Session tickets
  const sessionTickets: SessionTicket[] = [];
  for (let i = 0; i < ticketsPerBundle; i++) {
    const ticketData = data.slice(off, off + SESSION_TICKET_SIZE);
    sessionTickets.push(decodeSessionTicket(ticketData));
    off += SESSION_TICKET_SIZE;
  }

  // Refresh ticket
  const refreshTicket = decodeRefreshTicket(data.slice(off, off + REFRESH_TICKET_SIZE));

  return {
    bundleGen, issuedAtMs, expireAtMs, workerKid,
    policy, sessionTickets, refreshTicket,
  };
}

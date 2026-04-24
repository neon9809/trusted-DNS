/**
 * Trusted-DNS Worker API Handlers
 *
 * Implements Bootstrap, Query, and Refresh request handlers.
 * Each handler parses the binary protocol, performs verification,
 * and returns the appropriate response.
 */

import {
  ProtocolHeader,
  decodeHeader,
  encodeHeader,
  decodeSessionTicket,
  decodeRefreshTicket,
  HEADER_SIZE,
  PROTOCOL_VERSION,
  MSG_BOOTSTRAP_REQ,
  MSG_BOOTSTRAP_RESP,
  MSG_QUERY_REQ,
  MSG_QUERY_RESP,
  MSG_REFRESH_REQ,
  MSG_REFRESH_RESP,
  MSG_ERROR_RESP,
  ERR_BAD_VERSION,
  ERR_BAD_TYPE,
  ERR_BAD_TICKET,
  ERR_EXPIRED,
  ERR_OLD_GENERATION,
  ERR_REPLAY_SUSPECTED,
  ERR_DECRYPT_FAILED,
  ERR_UPSTREAM_FAILURE,
  ERR_INTERNAL,
  SESSION_TICKET_SIZE,
  REFRESH_TICKET_SIZE,
  NONCE_SIZE,
  TAG_SIZE,
  BOOT_NONCE_SIZE,
  buildErrorResponse,
} from './protocol';

import {
  deriveAllKeys,
  deriveQueryKeys,
  deriveClientId,
  aeadEncrypt,
  aeadDecrypt,
  verifyBootstrapProof,
  hexToBytes,
  bytesToHex,
} from './crypto';

import {
  issueKeyBundle,
  verifySessionTicket,
  verifyRefreshTicket,
  serializeKeyBundle,
  defaultPolicy,
} from './tickets';

import { resolve, parseUpstreams, ResolverConfig } from './resolver';
import { AntiReplayCache } from './replay';

// ─── Types ──────────────────────────────────────────────────────────

export interface Env {
  ROOT_SEED: string;
  DOH_UPSTREAMS: string;
  GENERATION_STORE: DurableObjectNamespace;
  DOH_TIMEOUT_MS?: string;
  DEBUG_MODE?: string;
}

// Global anti-replay cache (per Worker isolate)
const replayCache = new AntiReplayCache(8192, 120_000);

// ─── Main Request Router ────────────────────────────────────────────

export async function handleRequest(
  request: Request,
  env: Env,
): Promise<Response> {
  // Only accept POST with binary body
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  const body = await request.arrayBuffer();
  const data = new Uint8Array(body);

  if (data.length < HEADER_SIZE) {
    return binaryResponse(
      buildErrorResponse(new Uint8Array(8), 0n, ERR_BAD_TYPE),
    );
  }

  const header = decodeHeader(data);

  // Version check
  if (header.ver !== PROTOCOL_VERSION) {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_BAD_VERSION),
    );
  }

  const payload = data.slice(HEADER_SIZE, HEADER_SIZE + header.payloadLen);

  try {
    switch (header.msgType) {
      case MSG_BOOTSTRAP_REQ:
        return await handleBootstrap(header, payload, env);
      case MSG_QUERY_REQ:
        return await handleQuery(header, payload, env);
      case MSG_REFRESH_REQ:
        return await handleRefresh(header, payload, env);
      default:
        return binaryResponse(
          buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_BAD_TYPE),
        );
    }
  } catch (err: any) {
    console.error('Handler error:', err.message);
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_INTERNAL),
    );
  }
}

// ─── Bootstrap Handler ──────────────────────────────────────────────

async function handleBootstrap(
  header: ProtocolHeader,
  payload: Uint8Array,
  env: Env,
): Promise<Response> {
  const rootSeed = hexToBytes(env.ROOT_SEED);
  const keys = await deriveAllKeys(rootSeed);
  const clientId = await deriveClientId(rootSeed);

  // Parse bootstrap payload:
  // boot_nonce(16) + timestamp_ms(8) + bootstrap_proof(16) + capabilities(4)
  if (payload.length < 44) {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_BAD_TICKET),
    );
  }

  const bootNonce = payload.slice(0, 16);
  const dv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const timestampMs = dv.getBigUint64(16, false);
  const bootstrapProof = payload.slice(24, 40);
  // capabilities at offset 40, 4 bytes (reserved for future use)

  // Verify bootstrap proof
  const proofValid = await verifyBootstrapProof(
    keys.bootstrapKey, bootNonce, timestampMs, bootstrapProof,
  );
  if (!proofValid) {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_BAD_TICKET),
    );
  }

  // Check timestamp within acceptable window
  const now = BigInt(Date.now());
  const skew = BigInt(300_000);
  if (now < timestampMs - skew || now > timestampMs + skew) {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_EXPIRED),
    );
  }

  // Get current generation from Durable Object
  const doId = env.GENERATION_STORE.idFromName(bytesToHex(clientId));
  const doStub = env.GENERATION_STORE.get(doId);
  const genResp = await doStub.fetch(new Request('https://do/get'));
  const genState = await genResp.json() as { latestBundleGen: number };

  const newGen = BigInt(genState.latestBundleGen + 1);

  // Advance generation
  await doStub.fetch(new Request('https://do/advance', {
    method: 'POST',
    body: JSON.stringify({ newGen: Number(newGen) }),
    headers: { 'Content-Type': 'application/json' },
  }));

  // Issue KeyBundle
  const bundle = await issueKeyBundle(
    clientId, newGen, keys.ticketAuthKey, keys.refreshAuthKey,
  );

  // Serialize and encrypt KeyBundle
  const bundleBytes = serializeKeyBundle(bundle);
  const aad = encodeHeader({
    ...header,
    msgType: MSG_BOOTSTRAP_RESP,
    bundleGen: newGen,
    payloadLen: 0, // will be set later
  });

  const { nonce, ciphertext } = await aeadEncrypt(keys.bundleWrapKey, bundleBytes, aad);

  // Build response payload: server_time_ms(8) + bundle_gen(8) + nonce(12) + ciphertext
  const respPayloadLen = 8 + 8 + NONCE_SIZE + ciphertext.length;
  const respPayload = new Uint8Array(respPayloadLen);
  const rpDv = new DataView(respPayload.buffer);
  rpDv.setBigUint64(0, now, false);
  rpDv.setBigUint64(8, newGen, false);
  respPayload.set(nonce, 16);
  respPayload.set(ciphertext, 16 + NONCE_SIZE);

  // Build response header
  const respHeader = encodeHeader({
    ver: PROTOCOL_VERSION,
    msgType: MSG_BOOTSTRAP_RESP,
    flags: 0,
    clientIdPrefix: clientId.slice(0, 8),
    bundleGen: newGen,
    ticketId: 0,
    seq: 0,
    payloadLen: respPayloadLen,
    headerMac: 0,
  });

  const response = new Uint8Array(HEADER_SIZE + respPayloadLen);
  response.set(respHeader, 0);
  response.set(respPayload, HEADER_SIZE);

  return binaryResponse(response);
}

// ─── Query Handler ──────────────────────────────────────────────────

async function handleQuery(
  header: ProtocolHeader,
  payload: Uint8Array,
  env: Env,
): Promise<Response> {
  const rootSeed = hexToBytes(env.ROOT_SEED);
  const keys = await deriveAllKeys(rootSeed);
  const clientId = await deriveClientId(rootSeed);

  // Parse query payload: ticket_blob(114) + nonce(12) + ciphertext(var)
  if (payload.length < SESSION_TICKET_SIZE + NONCE_SIZE + 1) {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_BAD_TICKET),
    );
  }

  const ticketBlob = payload.slice(0, SESSION_TICKET_SIZE);
  const nonce = payload.slice(SESSION_TICKET_SIZE, SESSION_TICKET_SIZE + NONCE_SIZE);
  const ciphertext = payload.slice(SESSION_TICKET_SIZE + NONCE_SIZE);

  // Decode and verify ticket
  const ticket = decodeSessionTicket(ticketBlob);
  const nowMs = BigInt(Date.now());

  // Check generation against Durable Object
  const doId = env.GENERATION_STORE.idFromName(bytesToHex(clientId));
  const doStub = env.GENERATION_STORE.get(doId);
  const genResp = await doStub.fetch(new Request('https://do/get'));
  const genState = await genResp.json() as { latestBundleGen: number };

  if (Number(ticket.bundleGen) < genState.latestBundleGen) {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_OLD_GENERATION),
    );
  }

  // Verify ticket
  const ticketError = await verifySessionTicket(
    ticket, keys.ticketAuthKey, header.clientIdPrefix,
    BigInt(genState.latestBundleGen), nowMs,
  );
  if (ticketError) {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_BAD_TICKET),
    );
  }

  // Anti-replay check
  if (replayCache.check(ticket.ticketId, header.seq, header.bundleGen)) {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_REPLAY_SUSPECTED),
    );
  }

  // Check seq window
  if (!replayCache.checkSeqWindow(header.seq, ticket.counterBase, ticket.queryBudget)) {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_REPLAY_SUSPECTED),
    );
  }

  // Mark generation as used
  await doStub.fetch(new Request('https://do/mark-used', {
    method: 'POST',
    body: JSON.stringify({ gen: Number(ticket.bundleGen) }),
    headers: { 'Content-Type': 'application/json' },
  }));

  // Derive query keys from resume_seed
  const queryKeys = await deriveQueryKeys(ticket.resumeSeed);

  // Build AAD from header fields
  // Docker encrypts before setting payloadLen, so AAD uses payloadLen=0 and headerMac=0
  const aad = encodeHeader({
    ...header,
    payloadLen: 0,
    headerMac: 0,
  });

  // Decrypt DNS query
  let dnsQuery: Uint8Array;
  try {
    dnsQuery = await aeadDecrypt(queryKeys.reqKey, nonce, ciphertext, aad);
  } catch {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_DECRYPT_FAILED),
    );
  }

  // Forward to DoH upstream
  const upstreams = parseUpstreams(env.DOH_UPSTREAMS);
  const resolverConfig: ResolverConfig = {
    upstreams,
    timeoutMs: parseInt(env.DOH_TIMEOUT_MS || '5000', 10),
  };

  let resolverResult;
  try {
    resolverResult = await resolve(dnsQuery, resolverConfig);
  } catch {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_UPSTREAM_FAILURE),
    );
  }

  // Encrypt DNS response
  const respAad = encodeHeader({
    ver: PROTOCOL_VERSION,
    msgType: MSG_QUERY_RESP,
    flags: 0,
    clientIdPrefix: clientId.slice(0, 8),
    bundleGen: header.bundleGen,
    ticketId: header.ticketId,
    seq: header.seq,
    payloadLen: 0,
    headerMac: 0,
  });

  const encResp = await aeadEncrypt(queryKeys.respKey, resolverResult.dnsResponse, respAad);

  // Build response payload:
  // resolver_id(1) + transport_flags(1) + upstream_rtt_ms(2) + nonce(12) + ciphertext
  const respPayloadLen = 1 + 1 + 2 + NONCE_SIZE + encResp.ciphertext.length;
  const respPayload = new Uint8Array(respPayloadLen);
  const rpDv = new DataView(respPayload.buffer);
  respPayload[0] = resolverResult.resolverId;
  respPayload[1] = resolverResult.fallback ? 0x01 : 0x00;
  rpDv.setUint16(2, Math.min(resolverResult.rttMs, 65535), false);
  respPayload.set(encResp.nonce, 4);
  respPayload.set(encResp.ciphertext, 4 + NONCE_SIZE);

  // Build response header
  const respHeader = encodeHeader({
    ver: PROTOCOL_VERSION,
    msgType: MSG_QUERY_RESP,
    flags: 0,
    clientIdPrefix: clientId.slice(0, 8),
    bundleGen: header.bundleGen,
    ticketId: header.ticketId,
    seq: header.seq,
    payloadLen: respPayloadLen,
    headerMac: 0,
  });

  const response = new Uint8Array(HEADER_SIZE + respPayloadLen);
  response.set(respHeader, 0);
  response.set(respPayload, HEADER_SIZE);

  return binaryResponse(response);
}

// ─── Refresh Handler ────────────────────────────────────────────────

async function handleRefresh(
  header: ProtocolHeader,
  payload: Uint8Array,
  env: Env,
): Promise<Response> {
  const rootSeed = hexToBytes(env.ROOT_SEED);
  const keys = await deriveAllKeys(rootSeed);
  const clientId = await deriveClientId(rootSeed);

  // Parse refresh payload:
  // refresh_ticket_blob(122) + spent_bundle_gen(8) + spent_query_count(4) +
  // refresh_proof(32) + requested_reason(1)
  const minPayloadLen = REFRESH_TICKET_SIZE + 8 + 4 + 32 + 1;
  if (payload.length < minPayloadLen) {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_BAD_TICKET),
    );
  }

  let off = 0;
  const refreshTicketBlob = payload.slice(off, off + REFRESH_TICKET_SIZE); off += REFRESH_TICKET_SIZE;
  const dv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const spentBundleGen = dv.getBigUint64(off, false); off += 8;
  const spentQueryCount = dv.getUint32(off, false); off += 4;
  const refreshProof = payload.slice(off, off + 32); off += 32;
  const requestedReason = payload[off];

  // Decode and verify refresh ticket
  const refreshTicket = decodeRefreshTicket(refreshTicketBlob);
  const nowMs = BigInt(Date.now());

  // Check generation
  const doId = env.GENERATION_STORE.idFromName(bytesToHex(clientId));
  const doStub = env.GENERATION_STORE.get(doId);
  const genResp = await doStub.fetch(new Request('https://do/get'));
  const genState = await genResp.json() as { latestBundleGen: number };

  // CRITICAL: Verify ticket BEFORE advancing generation
  // The ticket was created with the current generation, so we must verify
  // against the current latestBundleGen, not after it's incremented.
  const currentGen = BigInt(genState.latestBundleGen);
  const ticketError = await verifyRefreshTicket(
    refreshTicket, keys.refreshAuthKey, header.clientIdPrefix,
    currentGen, nowMs,
  );
  if (ticketError) {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_BAD_TICKET),
    );
  }

  // Only advance generation AFTER successful verification
  const newGen = currentGen + 1n;
  await doStub.fetch(new Request('https://do/advance', {
    method: 'POST',
    body: JSON.stringify({ newGen: Number(newGen) }),
    headers: { 'Content-Type': 'application/json' },
  }));

  // Issue new KeyBundle
  const bundle = await issueKeyBundle(
    clientId, newGen, keys.ticketAuthKey, keys.refreshAuthKey,
  );

  // Serialize and encrypt
  const bundleBytes = serializeKeyBundle(bundle);
  const aad = encodeHeader({
    ver: PROTOCOL_VERSION,
    msgType: MSG_REFRESH_RESP,
    flags: 0,
    clientIdPrefix: clientId.slice(0, 8),
    bundleGen: newGen,
    ticketId: 0,
    seq: 0,
    payloadLen: 0,
    headerMac: 0,
  });

  const { nonce, ciphertext } = await aeadEncrypt(keys.bundleWrapKey, bundleBytes, aad);

  // Build response payload: server_time_ms(8) + bundle_gen(8) + nonce(12) + ciphertext
  const respPayloadLen = 8 + 8 + NONCE_SIZE + ciphertext.length;
  const respPayload = new Uint8Array(respPayloadLen);
  const rpDv = new DataView(respPayload.buffer);
  rpDv.setBigUint64(0, nowMs, false);
  rpDv.setBigUint64(8, newGen, false);
  respPayload.set(nonce, 16);
  respPayload.set(ciphertext, 16 + NONCE_SIZE);

  // Build response header
  const respHeader = encodeHeader({
    ver: PROTOCOL_VERSION,
    msgType: MSG_REFRESH_RESP,
    flags: 0,
    clientIdPrefix: clientId.slice(0, 8),
    bundleGen: newGen,
    ticketId: 0,
    seq: 0,
    payloadLen: respPayloadLen,
    headerMac: 0,
  });

  const response = new Uint8Array(HEADER_SIZE + respPayloadLen);
  response.set(respHeader, 0);
  response.set(respPayload, HEADER_SIZE);

  return binaryResponse(response);
}

// ─── Helpers ────────────────────────────────────────────────────────

function binaryResponse(data: Uint8Array): Response {
  return new Response(data, {
    status: 200,
    headers: {
      'Content-Type': 'application/octet-stream',
      'Cache-Control': 'no-store',
    },
  });
}

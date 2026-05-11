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
  decodeRefreshTicket,
  HEADER_SIZE,
  PROTOCOL_VERSION,
  MSG_BOOTSTRAP_REQ,
  MSG_BOOTSTRAP_RESP,
  MSG_QUERY_REQ,
  MSG_REFRESH_REQ,
  MSG_REFRESH_RESP,
  MSG_ERROR_RESP,
  ERR_BAD_VERSION,
  ERR_BAD_TYPE,
  ERR_BAD_TICKET,
  ERR_EXPIRED,
  ERR_INTERNAL,
  REFRESH_TICKET_SIZE,
  NONCE_SIZE,
  buildErrorResponse,
} from './protocol';

import {
  deriveAllKeys,
  deriveClientId,
  aeadEncrypt,
  hexToBytes,
} from './crypto';

import {
  issueKeyBundle,
  verifyRefreshTicket,
  serializeKeyBundle,
  defaultPolicy,
} from './tickets';

import type { CloudflareEnv } from './adapters/cloudflare/env';
import {
  advanceGenerationState,
  getGenerationState,
} from './adapters/cloudflare/generation-store';
import { binaryResponse } from './core/binary-response';
import { handleBootstrap } from './core/services/bootstrap';
import { handleQuery } from './core/services/query';

// ─── Types ──────────────────────────────────────────────────────────

export type Env = CloudflareEnv;

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
  const genState = await getGenerationState(env, clientId);

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
  await advanceGenerationState(env, clientId, Number(newGen));

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

 

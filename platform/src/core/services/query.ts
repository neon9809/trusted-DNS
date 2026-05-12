import {
  ProtocolHeader,
  encodeHeader,
  decodeSessionTicket,
  HEADER_SIZE,
  PROTOCOL_VERSION,
  FLAG_HAS_PADDING,
  MSG_QUERY_RESP,
  ERR_BAD_TYPE,
  ERR_BAD_TICKET,
  ERR_OLD_GENERATION,
  ERR_REPLAY_SUSPECTED,
  ERR_DECRYPT_FAILED,
  ERR_UPSTREAM_FAILURE,
  SESSION_TICKET_SIZE,
  NONCE_SIZE,
  buildErrorResponse,
} from '../../protocol';
import {
  deriveAllKeys,
  deriveQueryKeys,
  deriveClientId,
  aeadEncrypt,
  aeadDecrypt,
  hexToBytes,
} from '../../crypto';
import { verifySessionTicket } from '../../tickets';
import { resolve, parseUpstreams, ResolverConfig } from '../../resolver';
import { AntiReplayCache } from '../../replay';
import { binaryResponse } from '../binary-response';
import type { ServiceDeps } from './deps';

const replayCache = new AntiReplayCache(8192, 120_000);

export async function handleQuery(
  header: ProtocolHeader,
  payload: Uint8Array,
  deps: ServiceDeps,
): Promise<Response> {
  const clientConfig = await deps.clients.getClientConfig(header.clientIdPrefix);
  if (!clientConfig) {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_BAD_TICKET),
    );
  }

  const rootSeed = hexToBytes(clientConfig.rootSeedHex);
  const keys = await deriveAllKeys(rootSeed);
  const clientId = await deriveClientId(rootSeed);

  if (payload.length < SESSION_TICKET_SIZE + NONCE_SIZE + 1) {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_BAD_TICKET),
    );
  }

  let actualPayloadLen = payload.length;
  if ((header.flags & FLAG_HAS_PADDING) !== 0) {
    if (payload.length < SESSION_TICKET_SIZE + NONCE_SIZE + 1 + 2) {
      return binaryResponse(
        buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_BAD_TYPE),
      );
    }
    const padLenDv = new DataView(payload.buffer, payload.byteOffset + payload.length - 2, 2);
    const padLen = padLenDv.getUint16(0, false);
    actualPayloadLen = payload.length - padLen - 2;
    if (actualPayloadLen < SESSION_TICKET_SIZE + NONCE_SIZE + 1) {
      return binaryResponse(
        buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_BAD_TYPE),
      );
    }
  }

  const ticketBlob = payload.slice(0, SESSION_TICKET_SIZE);
  const nonce = payload.slice(SESSION_TICKET_SIZE, SESSION_TICKET_SIZE + NONCE_SIZE);
  const ciphertext = payload.slice(SESSION_TICKET_SIZE + NONCE_SIZE, actualPayloadLen);

  const ticket = decodeSessionTicket(ticketBlob);
  const nowMs = deps.nowMs();

  const genState = await deps.generation.getState(clientId);

  if (Number(ticket.bundleGen) < genState.latestBundleGen) {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_OLD_GENERATION),
    );
  }

  const ticketError = await verifySessionTicket(
    ticket, keys.ticketAuthKey, header.clientIdPrefix,
    BigInt(genState.latestBundleGen), nowMs,
  );
  if (ticketError) {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_BAD_TICKET),
    );
  }

  if (replayCache.check(header.clientIdPrefix, ticket.ticketId, header.seq, header.bundleGen)) {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_REPLAY_SUSPECTED),
    );
  }

  if (!replayCache.checkSeqWindow(header.seq, ticket.counterBase, ticket.queryBudget)) {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_REPLAY_SUSPECTED),
    );
  }

  await deps.generation.markUsed(clientId, Number(ticket.bundleGen));

  const queryKeys = await deriveQueryKeys(ticket.resumeSeed);

  const aad = encodeHeader({
    ...header,
    payloadLen: 0,
    headerMac: 0,
  });

  let dnsQuery: Uint8Array;
  try {
    dnsQuery = await aeadDecrypt(queryKeys.reqKey, nonce, ciphertext, aad);
  } catch {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_DECRYPT_FAILED),
    );
  }

  const upstreams = parseUpstreams(clientConfig.dohUpstreams);
  const resolverConfig: ResolverConfig = {
    upstreams,
    timeoutMs: clientConfig.dohTimeoutMs,
  };

  let resolverResult;
  try {
    resolverResult = await resolve(dnsQuery, resolverConfig);
  } catch {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_UPSTREAM_FAILURE),
    );
  }

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

  const respPayloadLen = 1 + 1 + 2 + NONCE_SIZE + encResp.ciphertext.length;
  const respPayload = new Uint8Array(respPayloadLen);
  const rpDv = new DataView(respPayload.buffer);
  respPayload[0] = resolverResult.resolverId;
  respPayload[1] = resolverResult.fallback ? 0x01 : 0x00;
  rpDv.setUint16(2, Math.min(resolverResult.rttMs, 65535), false);
  respPayload.set(encResp.nonce, 4);
  respPayload.set(encResp.ciphertext, 4 + NONCE_SIZE);

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

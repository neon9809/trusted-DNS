import {
  ProtocolHeader,
  encodeHeader,
  decodeRefreshTicket,
  HEADER_SIZE,
  PROTOCOL_VERSION,
  MSG_REFRESH_RESP,
  ERR_BAD_TICKET,
  REFRESH_TICKET_SIZE,
  NONCE_SIZE,
  buildErrorResponse,
} from '../../protocol';
import {
  deriveAllKeys,
  deriveClientId,
  aeadEncrypt,
  hexToBytes,
} from '../../crypto';
import {
  issueKeyBundle,
  verifyRefreshTicket,
  serializeKeyBundle,
} from '../../tickets';
import type { CloudflareEnv } from '../../adapters/cloudflare/env';
import { advanceGenerationState, getGenerationState } from '../../adapters/cloudflare/generation-store';
import { binaryResponse } from '../binary-response';

export async function handleRefresh(
  header: ProtocolHeader,
  payload: Uint8Array,
  env: CloudflareEnv,
): Promise<Response> {
  const rootSeed = hexToBytes(env.ROOT_SEED);
  const keys = await deriveAllKeys(rootSeed);
  const clientId = await deriveClientId(rootSeed);

  const minPayloadLen = REFRESH_TICKET_SIZE + 8 + 4 + 32 + 1;
  if (payload.length < minPayloadLen) {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_BAD_TICKET),
    );
  }

  let off = 0;
  const refreshTicketBlob = payload.slice(off, off + REFRESH_TICKET_SIZE); off += REFRESH_TICKET_SIZE;
  const dv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  dv.getBigUint64(off, false); off += 8;
  dv.getUint32(off, false); off += 4;
  payload.slice(off, off + 32); off += 32;
  payload[off];

  const refreshTicket = decodeRefreshTicket(refreshTicketBlob);
  const nowMs = BigInt(Date.now());

  const genState = await getGenerationState(env, clientId);

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

  const newGen = currentGen + 1n;
  await advanceGenerationState(env, clientId, Number(newGen));

  const bundle = await issueKeyBundle(
    clientId, newGen, keys.ticketAuthKey, keys.refreshAuthKey,
  );

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

  const respPayloadLen = 8 + 8 + NONCE_SIZE + ciphertext.length;
  const respPayload = new Uint8Array(respPayloadLen);
  const rpDv = new DataView(respPayload.buffer);
  rpDv.setBigUint64(0, nowMs, false);
  rpDv.setBigUint64(8, newGen, false);
  respPayload.set(nonce, 16);
  respPayload.set(ciphertext, 16 + NONCE_SIZE);

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

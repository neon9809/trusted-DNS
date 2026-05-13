import {
  ProtocolHeader,
  encodeHeader,
  HEADER_SIZE,
  PROTOCOL_VERSION,
  MSG_BOOTSTRAP_RESP,
  ERR_BAD_TICKET,
  ERR_EXPIRED,
  NONCE_SIZE,
  buildErrorResponse,
} from '../../protocol';
import {
  aeadEncrypt,
  deriveAllKeys,
  deriveClientId,
  hexToBytes,
  verifyBootstrapProof,
} from '../../crypto';
import { issueKeyBundle, serializeKeyBundle } from '../../tickets';
import { binaryResponse } from '../binary-response';
import type { ServiceDeps } from './deps';

export async function handleBootstrap(
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

  if (payload.length < 44) {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_BAD_TICKET),
    );
  }

  const bootNonce = payload.slice(0, 16);
  const dv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const timestampMs = dv.getBigUint64(16, false);
  const bootstrapProof = payload.slice(24, 40);

  const proofValid = await verifyBootstrapProof(
    keys.bootstrapKey, bootNonce, timestampMs, bootstrapProof,
  );
  if (!proofValid) {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_BAD_TICKET),
    );
  }

  const now = deps.nowMs();
  const skew = BigInt(300_000);
  if (now < timestampMs - skew || now > timestampMs + skew) {
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_EXPIRED),
    );
  }

  const genState = await deps.generation.getState(clientId, { consistency: 'strong' });
  const newGen = BigInt(genState.latestBundleGen + 1);

  const committedState = await deps.generation.advance(clientId, Number(newGen));
  const committedGen = BigInt(committedState.latestBundleGen);

  const bundle = await issueKeyBundle(
    clientId, committedGen, keys.ticketAuthKey, keys.refreshAuthKey,
  );

  const bundleBytes = serializeKeyBundle(bundle);
  const aad = encodeHeader({
    ...header,
    msgType: MSG_BOOTSTRAP_RESP,
    bundleGen: committedGen,
    payloadLen: 0,
  });

  const { nonce, ciphertext } = await aeadEncrypt(keys.bundleWrapKey, bundleBytes, aad);

  const respPayloadLen = 8 + 8 + NONCE_SIZE + ciphertext.length;
  const respPayload = new Uint8Array(respPayloadLen);
  const rpDv = new DataView(respPayload.buffer);
  rpDv.setBigUint64(0, now, false);
  rpDv.setBigUint64(8, committedGen, false);
  respPayload.set(nonce, 16);
  respPayload.set(ciphertext, 16 + NONCE_SIZE);

  const respHeader = encodeHeader({
    ver: PROTOCOL_VERSION,
    msgType: MSG_BOOTSTRAP_RESP,
    flags: 0,
    clientIdPrefix: clientId.slice(0, 8),
    bundleGen: committedGen,
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

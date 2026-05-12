import {
  decodeHeader,
  HEADER_SIZE,
  PROTOCOL_VERSION,
  MSG_BOOTSTRAP_REQ,
  MSG_QUERY_REQ,
  MSG_REFRESH_REQ,
  ERR_BAD_VERSION,
  ERR_BAD_TYPE,
  ERR_INTERNAL,
  buildErrorResponse,
} from './protocol';
import { binaryResponse } from './core/binary-response';
import { handleBootstrap } from './core/services/bootstrap';
import { handleQuery } from './core/services/query';
import { handleRefresh } from './core/services/refresh';
import type { ServiceDeps } from './core/services/deps';
import type { Logger } from './core/interfaces';

export async function handleProtocolRequest(
  request: Request,
  deps: ServiceDeps,
  logger?: Pick<Logger, 'error'>,
): Promise<Response> {
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
        return await handleBootstrap(header, payload, deps);
      case MSG_QUERY_REQ:
        return await handleQuery(header, payload, deps);
      case MSG_REFRESH_REQ:
        return await handleRefresh(header, payload, deps);
      default:
        return binaryResponse(
          buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_BAD_TYPE),
        );
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : 'unknown error';
    logger?.error?.('Protocol handler error', { message });
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_INTERNAL),
    );
  }
}

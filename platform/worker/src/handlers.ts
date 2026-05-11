/**
 * Trusted-DNS Worker API Handlers
 *
 * Implements Bootstrap, Query, and Refresh request handlers.
 * Each handler parses the binary protocol, performs verification,
 * and returns the appropriate response.
 */

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

import type { CloudflareEnv } from './adapters/cloudflare/env';
import { binaryResponse } from './core/binary-response';
import { handleBootstrap } from './core/services/bootstrap';
import { handleQuery } from './core/services/query';
import { handleRefresh } from './core/services/refresh';
import { createCloudflareServiceDeps } from './adapters/cloudflare/service-deps';

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
  const deps = createCloudflareServiceDeps(env);

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
  } catch (err: any) {
    console.error('Handler error:', err.message);
    return binaryResponse(
      buildErrorResponse(header.clientIdPrefix, header.bundleGen, ERR_INTERNAL),
    );
  }
}
 

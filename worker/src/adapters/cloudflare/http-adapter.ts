/**
 * Cloudflare HTTP adapter for the current Worker runtime.
 *
 * For the first implementation step, this adapter intentionally delegates the
 * binary protocol flow to the existing request handler so we can introduce the
 * new v2 structure without changing protocol behavior.
 */

import { createHttpService } from '../../core/http-service';
import type { CloudflareEnv } from './env';
import { createCloudflareProtocolService } from './protocol-service';

export function createCloudflareHttpAdapter(env: CloudflareEnv) {
  const protocolService = createCloudflareProtocolService();
  const service = createHttpService(
    {
      protocolPath: env.PROTOCOL_PATH || '/dns-query',
      protocolVersion: 1,
      appVersion: '0.1.0',
    },
    {
      handleProtocolRequest: (request) => protocolService.handleProtocolRequest(request, env),
    },
  );

  return {
    handle(request: Request): Promise<Response> {
      return service.handle(request);
    },
  };
}

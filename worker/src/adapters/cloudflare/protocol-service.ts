/**
 * Cloudflare-backed protocol service.
 *
 * For the initial v2 refactor, this facade delegates to the existing
 * `handleRequest()` implementation. Future steps will move bootstrap/query/
 * refresh logic out of `handlers.ts` and into service-core modules behind this
 * same contract.
 */

import { createProtocolService } from '../../core/protocol-service';
import { handleRequest } from '../../handlers';
import type { CloudflareEnv } from './env';

export function createCloudflareProtocolService() {
  return createProtocolService<CloudflareEnv>({
    handleProtocolRequest(request, env) {
      return handleRequest(request, env);
    },
  });
}

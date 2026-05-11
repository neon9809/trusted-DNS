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

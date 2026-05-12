import { createRuntimeHttpHandler } from '../../../../src/runtime-service';
import type { CloudflareEnv } from './env';
import { createCloudflareServiceDeps } from './service-deps';

export function createCloudflareHttpAdapter(env: CloudflareEnv) {
  const service = createRuntimeHttpHandler({
    http: {
      protocolPath: env.PROTOCOL_PATH || '/dns-query',
      protocolVersion: 1,
      appVersion: '2.1.0',
    },
    clients: {
      rootSeedHex: env.ROOT_SEED,
      dohUpstreams: env.DOH_UPSTREAMS,
      dohTimeoutMs: parseInt(env.DOH_TIMEOUT_MS || '5000', 10),
      clientRegistry: env.CLIENT_REGISTRY,
    },
    generation: createCloudflareServiceDeps(env).generation,
    logger: console,
    nowMs() {
      return BigInt(Date.now());
    },
  });

  return {
    handle(request: Request): Promise<Response> {
      return service.handle(request);
    },
  };
}

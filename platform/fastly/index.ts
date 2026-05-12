import { createRuntimeHttpHandler } from '../src/runtime-service';
import { createInMemoryGenerationBackend } from '../src/in-memory-generation-store';

export interface FastlyRuntimeConfig {
  rootSeed?: string;
  dohUpstreams: string;
  dohTimeoutMs: number;
  protocolPath: string;
  clientRegistry?: string;
}

export function createFastlyHandler(config: FastlyRuntimeConfig) {
  return createRuntimeHttpHandler({
    http: {
      protocolPath: config.protocolPath,
      protocolVersion: 1,
      appVersion: '2.1.0-fastly-poc',
    },
    clients: {
      rootSeedHex: config.rootSeed,
      dohUpstreams: config.dohUpstreams,
      dohTimeoutMs: config.dohTimeoutMs,
      clientRegistry: config.clientRegistry,
    },
    generation: createInMemoryGenerationBackend(),
    logger: console,
    nowMs() {
      return BigInt(Date.now());
    },
  });
}

export default {
  async fetch(request: Request, env: Record<string, string>): Promise<Response> {
    const handler = createFastlyHandler({
      rootSeed: env.ROOT_SEED,
      dohUpstreams: env.DOH_UPSTREAMS ?? '["https://dns.google/dns-query"]',
      dohTimeoutMs: Number(env.DOH_TIMEOUT_MS ?? '5000'),
      protocolPath: env.PROTOCOL_PATH ?? '/dns-query',
      clientRegistry: env.CLIENT_REGISTRY,
    });

    return handler.handle(request);
  },
};

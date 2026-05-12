import { createRuntimeHttpHandler } from '../src/runtime-service';
import { createInMemoryGenerationBackend } from '../src/in-memory-generation-store';

export interface DenoRuntimeConfig {
  rootSeed?: string;
  dohUpstreams: string;
  dohTimeoutMs: number;
  protocolPath: string;
  clientRegistry?: string;
}

export function loadDenoRuntimeConfig(
  env: Pick<typeof Deno.env, 'get'> = Deno.env,
): DenoRuntimeConfig {
  return {
    rootSeed: env.get('ROOT_SEED') ?? undefined,
    dohUpstreams: env.get('DOH_UPSTREAMS') ?? '["https://dns.google/dns-query"]',
    dohTimeoutMs: Number(env.get('DOH_TIMEOUT_MS') ?? '5000'),
    protocolPath: env.get('PROTOCOL_PATH') ?? '/dns-query',
    clientRegistry: env.get('CLIENT_REGISTRY') ?? undefined,
  };
}

export function createDenoHandler(config = loadDenoRuntimeConfig()) {
  return createRuntimeHttpHandler({
    http: {
      protocolPath: config.protocolPath,
      protocolVersion: 1,
      appVersion: '2.1.0-deno-poc',
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

if (import.meta.main) {
  const handler = createDenoHandler();
  Deno.serve((request) => handler.handle(request));
}

import { createStaticClientSelector } from '../../../../src/client-registry';
import type { ClientSelector } from '../../../../src/core/services/deps';
import type { CloudflareEnv } from './env';

export function createCloudflareClientSelector(env: CloudflareEnv): ClientSelector {
  return createStaticClientSelector({
    rootSeedHex: env.ROOT_SEED,
    dohUpstreams: env.DOH_UPSTREAMS,
    dohTimeoutMs: parseInt(env.DOH_TIMEOUT_MS || '5000', 10),
    clientRegistry: env.CLIENT_REGISTRY,
  });
}

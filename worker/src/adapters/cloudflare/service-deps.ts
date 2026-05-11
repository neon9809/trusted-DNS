import type { CloudflareEnv } from './env';
import {
  advanceGenerationState,
  getGenerationState,
  markGenerationUsed,
} from './generation-store';
import type { ServiceDeps } from '../../core/services/deps';

export function createCloudflareServiceDeps(env: CloudflareEnv): ServiceDeps {
  return {
    clients: {
      async getClientConfig(clientIdPrefix: Uint8Array) {
        return {
          rootSeedHex: env.ROOT_SEED,
          dohUpstreams: env.DOH_UPSTREAMS,
          dohTimeoutMs: parseInt(env.DOH_TIMEOUT_MS || '5000', 10),
        };
      },
    },
    generation: {
      getState(clientId) {
        return getGenerationState(env, clientId);
      },
      advance(clientId, newGen) {
        return advanceGenerationState(env, clientId, newGen);
      },
      markUsed(clientId, gen) {
        return markGenerationUsed(env, clientId, gen);
      },
    },
    nowMs() {
      return BigInt(Date.now());
    },
  };
}

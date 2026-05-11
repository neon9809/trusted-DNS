import type { CloudflareEnv } from './env';
import {
  advanceGenerationState,
  getGenerationState,
  markGenerationUsed,
} from './generation-store';
import type { ServiceDeps } from '../../core/services/deps';
import { createCloudflareClientSelector } from './client-registry';

export function createCloudflareServiceDeps(env: CloudflareEnv): ServiceDeps {
  return {
    clients: createCloudflareClientSelector(env),
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

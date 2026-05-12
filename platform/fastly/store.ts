import type { GenerationBackend, GenerationStateLike } from '../src/core/services/deps';

export interface FastlyStoreLike {
  get(key: string): Promise<GenerationStateLike | null>;
  put(key: string, value: GenerationStateLike): Promise<void>;
}

function keyFor(clientId: Uint8Array) {
  return Array.from(clientId)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

export function createFastlyGenerationBackend(store: FastlyStoreLike): GenerationBackend {
  function now() {
    return Date.now();
  }

  return {
    async getState(clientId) {
      return (await store.get(keyFor(clientId))) ?? {
        latestBundleGen: 0,
        updatedAt: 0,
      };
    },

    async advance(clientId, newGen) {
      const key = keyFor(clientId);
      const current = (await store.get(key)) ?? {
        latestBundleGen: 0,
        updatedAt: 0,
      };

      if (newGen <= current.latestBundleGen) {
        return current;
      }

      const nextState: GenerationStateLike = {
        latestBundleGen: newGen,
        updatedAt: now(),
      };
      await store.put(key, nextState);
      return nextState;
    },

    async markUsed(clientId, gen) {
      const key = keyFor(clientId);
      const current = (await store.get(key)) ?? {
        latestBundleGen: gen,
        updatedAt: now(),
      };

      if (current.latestBundleGen !== gen || current.firstUsedAt) {
        return current;
      }

      const nextState: GenerationStateLike = {
        ...current,
        firstUsedAt: now(),
        updatedAt: now(),
      };
      await store.put(key, nextState);
      return nextState;
    },
  };
}

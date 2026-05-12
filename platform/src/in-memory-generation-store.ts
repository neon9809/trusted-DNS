import type { GenerationBackend, GenerationStateLike } from './core/services/deps';

export function createInMemoryGenerationBackend(): GenerationBackend {
  const states = new Map<string, GenerationStateLike>();

  function keyFor(clientId: Uint8Array) {
    return Array.from(clientId)
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('');
  }

  function now() {
    return Date.now();
  }

  return {
    async getState(clientId) {
      return states.get(keyFor(clientId)) ?? {
        latestBundleGen: 0,
        updatedAt: 0,
      };
    },

    async advance(clientId, newGen) {
      const key = keyFor(clientId);
      const current = states.get(key);
      const currentGen = current?.latestBundleGen ?? 0;
      if (newGen <= currentGen) {
        return current ?? {
          latestBundleGen: currentGen,
          updatedAt: current?.updatedAt ?? 0,
        };
      }

      const nextState: GenerationStateLike = {
        latestBundleGen: newGen,
        updatedAt: now(),
      };
      states.set(key, nextState);
      return nextState;
    },

    async markUsed(clientId, gen) {
      const key = keyFor(clientId);
      const current = states.get(key) ?? {
        latestBundleGen: gen,
        updatedAt: now(),
      };

      if (!current.firstUsedAt && current.latestBundleGen === gen) {
        current.firstUsedAt = now();
        current.updatedAt = current.firstUsedAt;
        states.set(key, current);
      }

      return current;
    },
  };
}

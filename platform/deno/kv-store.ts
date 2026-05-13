import type { GenerationBackend, GenerationStateLike } from '../src/core/services/deps';

export interface DenoKvLike {
  get<T>(key: readonly unknown[]): Promise<{ value: T | null }>;
  set(key: readonly unknown[], value: unknown): Promise<unknown>;
}

function keyFor(clientId: Uint8Array) {
  return ['trusted-dns', 'generation', Array.from(clientId).join('')];
}

export function createDenoKvGenerationBackend(kv: DenoKvLike): GenerationBackend {
  function now() {
    return Date.now();
  }

  return {
    async getState(clientId) {
      const record = await kv.get<GenerationStateLike>(keyFor(clientId));
      return record.value ?? {
        latestBundleGen: 0,
        updatedAt: 0,
      };
    },

    async getCachedState() {
      return null;
    },

    async advance(clientId, newGen) {
      const current = await this.getState(clientId);
      if (newGen <= current.latestBundleGen) {
        return current;
      }

      const nextState: GenerationStateLike = {
        latestBundleGen: newGen,
        updatedAt: now(),
      };
      await kv.set(keyFor(clientId), nextState);
      return nextState;
    },

    async markUsed(clientId, gen) {
      const current = await this.getState(clientId);
      if (current.latestBundleGen !== gen || current.firstUsedAt) {
        return current;
      }

      const nextState: GenerationStateLike = {
        ...current,
        firstUsedAt: now(),
        updatedAt: now(),
      };
      await kv.set(keyFor(clientId), nextState);
      return nextState;
    },
  };
}

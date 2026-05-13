import { bytesToHex } from '../../../../src/crypto';
import type {
  CachedGenerationStateLike,
  GenerationReadOptions,
} from '../../../../src/core/services/deps';
import type { CloudflareEnv } from './env';
import type { GenerationState } from '../../generation-store';

const DEFAULT_GENERATION_CACHE_TTL_MS = 120_000;
const GENERATION_CACHE_LIMIT = 8192;
const MARK_USED_CACHE_LIMIT = 8192;
const generationStateCache = new Map<string, CachedGenerationStateLike>();
const markUsedWatermarks = new Map<string, number>();

function getGenerationStub(env: CloudflareEnv, clientId: Uint8Array) {
  const doId = env.GENERATION_STORE.idFromName(bytesToHex(clientId));
  return env.GENERATION_STORE.get(doId);
}

function getClientKey(clientId: Uint8Array): string {
  return bytesToHex(clientId);
}

function getGenerationCacheTtlMs(env: CloudflareEnv): number {
  const rawValue = env.GENERATION_CACHE_TTL_MS;
  if (!rawValue) {
    return DEFAULT_GENERATION_CACHE_TTL_MS;
  }

  const parsedValue = parseInt(rawValue, 10);
  if (Number.isNaN(parsedValue)) {
    return DEFAULT_GENERATION_CACHE_TTL_MS;
  }

  return Math.max(0, parsedValue);
}

function touchLimitedMapEntry<T>(cache: Map<string, T>, key: string, value: T, limit: number): void {
  cache.set(key, value);
  if (cache.size > limit) {
    const oldestKey = cache.keys().next().value;
    if (oldestKey !== undefined) {
      cache.delete(oldestKey);
    }
  }
}

function updateGenerationCache(
  clientId: Uint8Array,
  state: GenerationState,
  source: 'do' | 'local-write',
): CachedGenerationStateLike {
  const cachedState: CachedGenerationStateLike = {
    ...state,
    fetchedAt: Date.now(),
    source,
  };
  touchLimitedMapEntry(generationStateCache, getClientKey(clientId), cachedState, GENERATION_CACHE_LIMIT);
  return cachedState;
}

async function parseJsonResponse<T>(response: Response, path: string): Promise<T> {
  const text = await response.text();
  let parsedBody: unknown = null;

  if (text) {
    try {
      parsedBody = JSON.parse(text);
    } catch {
      parsedBody = text;
    }
  }

  if (!response.ok) {
    const details = typeof parsedBody === 'string' ? parsedBody : JSON.stringify(parsedBody);
    throw new Error(`GenerationStore ${path} failed with ${response.status}: ${details}`);
  }

  return parsedBody as T;
}

async function fetchGenerationStateFromDO(
  env: CloudflareEnv,
  clientId: Uint8Array,
): Promise<GenerationState> {
  const stub = getGenerationStub(env, clientId);
  const response = await stub.fetch(new Request('https://do/get'));
  const state = await parseJsonResponse<GenerationState>(response, 'GET /get');
  updateGenerationCache(clientId, state, 'do');
  return state;
}

function updateMarkUsedWatermark(clientId: Uint8Array, gen: number): string | null {
  const key = getClientKey(clientId);
  const cachedGen = markUsedWatermarks.get(key);
  if (cachedGen !== undefined && gen <= cachedGen) {
    return null;
  }

  touchLimitedMapEntry(markUsedWatermarks, key, gen, MARK_USED_CACHE_LIMIT);

  return key;
}

export async function getCachedGenerationState(
  env: CloudflareEnv,
  clientId: Uint8Array,
): Promise<CachedGenerationStateLike | null> {
  const ttlMs = getGenerationCacheTtlMs(env);
  if (ttlMs <= 0) {
    return null;
  }

  const key = getClientKey(clientId);
  const cachedState = generationStateCache.get(key);
  if (!cachedState) {
    return null;
  }

  if (Date.now() - cachedState.fetchedAt > ttlMs) {
    generationStateCache.delete(key);
    return null;
  }

  return cachedState;
}

export async function getGenerationState(
  env: CloudflareEnv,
  clientId: Uint8Array,
  options?: GenerationReadOptions,
): Promise<GenerationState> {
  if (options?.consistency === 'strong') {
    return fetchGenerationStateFromDO(env, clientId);
  }

  return fetchGenerationStateFromDO(env, clientId);
}

export async function advanceGenerationState(
  env: CloudflareEnv,
  clientId: Uint8Array,
  newGen: number,
): Promise<GenerationState> {
  const stub = getGenerationStub(env, clientId);
  const response = await stub.fetch(new Request('https://do/advance', {
    method: 'POST',
    body: JSON.stringify({ newGen }),
    headers: { 'Content-Type': 'application/json' },
  }));
  const state = await parseJsonResponse<GenerationState>(response, 'POST /advance');
  if (state.latestBundleGen !== newGen) {
    throw new Error(
      `GenerationStore POST /advance committed unexpected generation ${state.latestBundleGen}, expected ${newGen}`,
    );
  }

  updateGenerationCache(clientId, state, 'local-write');
  return state;
}

export async function markGenerationUsed(
  env: CloudflareEnv,
  clientId: Uint8Array,
  gen: number,
): Promise<GenerationState> {
  const cacheKey = updateMarkUsedWatermark(clientId, gen);
  if (!cacheKey) {
    return {
      latestBundleGen: gen,
      updatedAt: Date.now(),
    };
  }

  const stub = getGenerationStub(env, clientId);
  try {
    const response = await stub.fetch(new Request('https://do/mark-used', {
      method: 'POST',
      body: JSON.stringify({ gen }),
      headers: { 'Content-Type': 'application/json' },
    }));

    const text = await response.text();
    let parsedBody: unknown = {};
    if (text) {
      try {
        parsedBody = JSON.parse(text);
      } catch {
        parsedBody = text;
      }
    }

    if (response.ok) {
      const state = parsedBody as GenerationState;
      updateGenerationCache(clientId, state, 'do');
      return state;
    }

    const conflictBody = parsedBody as { current?: number };
    if (response.status === 409 && typeof conflictBody.current === 'number' && conflictBody.current > gen) {
      const recoveredState: GenerationState = {
        latestBundleGen: conflictBody.current,
        updatedAt: Date.now(),
      };
      updateGenerationCache(clientId, recoveredState, 'do');
      return recoveredState;
    }

    throw new Error(
      `GenerationStore POST /mark-used failed with ${response.status}: ${text || 'empty response'}`,
    );
  } catch (error) {
    if (markUsedWatermarks.get(cacheKey) === gen) {
      markUsedWatermarks.delete(cacheKey);
    }
    throw error;
  }
}

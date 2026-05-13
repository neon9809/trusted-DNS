import { bytesToHex } from '../../../../src/crypto';
import type { CloudflareEnv } from './env';
import type { GenerationState } from '../../generation-store';

const MARK_USED_CACHE_LIMIT = 8192;
const markUsedWatermarks = new Map<string, number>();

function getGenerationStub(env: CloudflareEnv, clientId: Uint8Array) {
  const doId = env.GENERATION_STORE.idFromName(bytesToHex(clientId));
  return env.GENERATION_STORE.get(doId);
}

function updateMarkUsedWatermark(clientId: Uint8Array, gen: number): string | null {
  const key = bytesToHex(clientId);
  const cachedGen = markUsedWatermarks.get(key);
  if (cachedGen !== undefined && gen <= cachedGen) {
    return null;
  }

  markUsedWatermarks.set(key, gen);
  if (markUsedWatermarks.size > MARK_USED_CACHE_LIMIT) {
    const oldestKey = markUsedWatermarks.keys().next().value;
    if (oldestKey !== undefined) {
      markUsedWatermarks.delete(oldestKey);
    }
  }

  return key;
}

export async function getGenerationState(
  env: CloudflareEnv,
  clientId: Uint8Array,
): Promise<GenerationState> {
  const stub = getGenerationStub(env, clientId);
  const response = await stub.fetch(new Request('https://do/get'));
  return response.json() as Promise<GenerationState>;
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
  return response.json() as Promise<GenerationState>;
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
    return response.json() as Promise<GenerationState>;
  } catch (error) {
    if (markUsedWatermarks.get(cacheKey) === gen) {
      markUsedWatermarks.delete(cacheKey);
    }
    throw error;
  }
}

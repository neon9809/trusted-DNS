/**
 * Cloudflare GenerationStore adapter helpers.
 *
 * These helpers isolate the concrete Durable Object request pattern used by the
 * current implementation so query/bootstrap/refresh logic can gradually move to
 * service-core without carrying Cloudflare-specific fetch details around.
 */

import { bytesToHex } from '../../crypto';
import type { CloudflareEnv } from './env';
import type { GenerationState } from '../../generation-store';

function getGenerationStub(env: CloudflareEnv, clientId: Uint8Array) {
  const doId = env.GENERATION_STORE.idFromName(bytesToHex(clientId));
  return env.GENERATION_STORE.get(doId);
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
  const stub = getGenerationStub(env, clientId);
  const response = await stub.fetch(new Request('https://do/mark-used', {
    method: 'POST',
    body: JSON.stringify({ gen }),
    headers: { 'Content-Type': 'application/json' },
  }));
  return response.json() as Promise<GenerationState>;
}

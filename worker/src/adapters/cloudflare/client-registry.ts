import { deriveClientId, hexToBytes, bytesToHex } from '../../crypto';
import type { ClientConfig, ClientSelector } from '../../core/services/deps';
import type { CloudflareEnv } from './env';

type ClientRegistryEntry = {
  root_seed?: string;
  rootSeedHex?: string;
  doh_upstreams?: string;
  dohUpstreams?: string;
  doh_timeout_ms?: number;
  dohTimeoutMs?: number;
  enabled?: boolean;
};

function isValidRootSeedHex(value: string) {
  return /^[0-9a-fA-F]{64}$/.test(value);
}

function normalizeEntry(
  entry: ClientRegistryEntry,
  defaults: Omit<ClientConfig, 'rootSeedHex'>,
): ClientConfig | null {
  const rootSeedHex = entry.rootSeedHex || entry.root_seed;
  if (!rootSeedHex) return null;
  if (!isValidRootSeedHex(rootSeedHex)) return null;

  return {
    rootSeedHex: rootSeedHex.toLowerCase(),
    dohUpstreams: entry.dohUpstreams || entry.doh_upstreams || defaults.dohUpstreams,
    dohTimeoutMs: entry.dohTimeoutMs ?? entry.doh_timeout_ms ?? defaults.dohTimeoutMs,
  };
}

function prefixKey(prefix: Uint8Array) {
  return bytesToHex(prefix);
}

let cachedRegistryKey: string | undefined;
let cachedRegistryPromise: Promise<Map<string, ClientConfig>> | null = null;

async function buildRegistry(
  env: CloudflareEnv,
  defaults: Omit<ClientConfig, 'rootSeedHex'>,
): Promise<Map<string, ClientConfig>> {
  const reg = new Map<string, ClientConfig>();
  const raw = env.CLIENT_REGISTRY;
  if (!raw) return reg;

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return reg;
  }

  if (!Array.isArray(parsed)) return reg;

  const entries = parsed as ClientRegistryEntry[];
  for (const e of entries) {
    if (e && e.enabled === false) continue;
    const cfg = normalizeEntry(e, defaults);
    if (!cfg) continue;
    try {
      const clientId = await deriveClientId(hexToBytes(cfg.rootSeedHex));
      const key = bytesToHex(clientId.slice(0, 8));
      if (!reg.has(key)) reg.set(key, cfg);
    } catch {
      continue;
    }
  }

  return reg;
}

export function createCloudflareClientSelector(env: CloudflareEnv): ClientSelector {
  const defaults = {
    dohUpstreams: env.DOH_UPSTREAMS,
    dohTimeoutMs: parseInt(env.DOH_TIMEOUT_MS || '5000', 10),
  };

  return {
    async getClientConfig(clientIdPrefix: Uint8Array): Promise<ClientConfig | null> {
      if (!env.CLIENT_REGISTRY) {
        return {
          rootSeedHex: env.ROOT_SEED,
          dohUpstreams: defaults.dohUpstreams,
          dohTimeoutMs: defaults.dohTimeoutMs,
        };
      }

      if (cachedRegistryKey !== env.CLIENT_REGISTRY || !cachedRegistryPromise) {
        cachedRegistryKey = env.CLIENT_REGISTRY;
        cachedRegistryPromise = buildRegistry(env, defaults);
      }

      const registry = await cachedRegistryPromise;
      return registry.get(prefixKey(clientIdPrefix)) || null;
    },
  };
}

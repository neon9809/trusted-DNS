import { bytesToHex, deriveClientId, hexToBytes } from './crypto';
import type { ClientConfig, ClientSelector } from './core/services/deps';

type ClientRegistryEntry = {
  root_seed?: string;
  rootSeedHex?: string;
  doh_upstreams?: string;
  dohUpstreams?: string;
  doh_timeout_ms?: number;
  dohTimeoutMs?: number;
  enabled?: boolean;
};

export interface StaticClientSelectorConfig {
  rootSeedHex?: string;
  dohUpstreams: string;
  dohTimeoutMs?: number;
  clientRegistry?: string;
}

function isValidRootSeedHex(value: string) {
  return /^[0-9a-fA-F]{64}$/.test(value);
}

function normalizeEntry(
  entry: ClientRegistryEntry,
  defaults: Omit<ClientConfig, 'rootSeedHex'>,
): ClientConfig | null {
  const rootSeedHex = entry.rootSeedHex || entry.root_seed;
  if (!rootSeedHex || !isValidRootSeedHex(rootSeedHex)) {
    return null;
  }

  return {
    rootSeedHex: rootSeedHex.toLowerCase(),
    dohUpstreams: entry.dohUpstreams || entry.doh_upstreams || defaults.dohUpstreams,
    dohTimeoutMs: entry.dohTimeoutMs ?? entry.doh_timeout_ms ?? defaults.dohTimeoutMs,
  };
}

async function buildRegistry(
  clientRegistry: string,
  defaults: Omit<ClientConfig, 'rootSeedHex'>,
): Promise<Map<string, ClientConfig>> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(clientRegistry);
  } catch {
    return new Map();
  }

  if (!Array.isArray(parsed)) {
    return new Map();
  }

  const registry = new Map<string, ClientConfig>();
  for (const entry of parsed as ClientRegistryEntry[]) {
    if (!entry || entry.enabled === false) {
      continue;
    }

    const cfg = normalizeEntry(entry, defaults);
    if (!cfg) {
      continue;
    }

    try {
      const clientId = await deriveClientId(hexToBytes(cfg.rootSeedHex));
      const key = bytesToHex(clientId.slice(0, 8));
      if (!registry.has(key)) {
        registry.set(key, cfg);
      }
    } catch {
      continue;
    }
  }

  return registry;
}

export function createStaticClientSelector(
  config: StaticClientSelectorConfig,
): ClientSelector {
  const defaults = {
    dohUpstreams: config.dohUpstreams,
    dohTimeoutMs: config.dohTimeoutMs ?? 5000,
  };

  let cachedRegistryKey: string | undefined;
  let cachedRegistryPromise: Promise<Map<string, ClientConfig>> | null = null;

  return {
    async getClientConfig(clientIdPrefix: Uint8Array): Promise<ClientConfig | null> {
      if (!config.clientRegistry) {
        if (!config.rootSeedHex) {
          return null;
        }

        return {
          rootSeedHex: config.rootSeedHex,
          dohUpstreams: defaults.dohUpstreams,
          dohTimeoutMs: defaults.dohTimeoutMs,
        };
      }

      if (cachedRegistryKey !== config.clientRegistry || !cachedRegistryPromise) {
        cachedRegistryKey = config.clientRegistry;
        cachedRegistryPromise = buildRegistry(config.clientRegistry, defaults);
      }

      const registry = await cachedRegistryPromise;
      return registry.get(bytesToHex(clientIdPrefix)) || null;
    },
  };
}

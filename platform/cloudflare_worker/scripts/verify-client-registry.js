function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error('bad hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function hkdfDerive(rootSeed, info, length = 32) {
  const baseKey = await crypto.subtle.importKey('raw', rootSeed, { name: 'HKDF' }, false, ['deriveBits']);
  const infoBytes = new TextEncoder().encode(info);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: infoBytes },
    baseKey,
    length * 8,
  );
  return new Uint8Array(bits);
}

async function deriveClientId(rootSeed) {
  return hkdfDerive(rootSeed, 'trusted-dns/client-id', 32);
}

async function buildRegistryMap(raw, defaults) {
  const map = new Map();
  if (!raw) return map;
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed)) return map;

  for (const e of parsed) {
    if (!e || e.enabled === false) continue;
    const seed = e.rootSeedHex || e.root_seed;
    if (!seed) continue;

    const clientId = await deriveClientId(hexToBytes(seed));
    const prefix = bytesToHex(clientId.slice(0, 8));
    if (map.has(prefix)) continue;

    map.set(prefix, {
      rootSeedHex: seed,
      dohUpstreams: e.dohUpstreams || e.doh_upstreams || defaults.dohUpstreams,
      dohTimeoutMs: e.dohTimeoutMs ?? e.doh_timeout_ms ?? defaults.dohTimeoutMs,
    });
  }
  return map;
}

async function main() {
  const registry = process.env.CLIENT_REGISTRY || '';
  const defaults = {
    dohUpstreams: process.env.DOH_UPSTREAMS || '[]',
    dohTimeoutMs: Number(process.env.DOH_TIMEOUT_MS || 5000),
  };

  if (!registry) {
    console.log('CLIENT_REGISTRY is empty; nothing to verify.');
    return;
  }

  const map = await buildRegistryMap(registry, defaults);
  if (map.size === 0) throw new Error('registry parsed but produced empty map');

  const parsed = JSON.parse(registry);
  for (const e of parsed) {
    if (!e || e.enabled === false) continue;
    const seed = e.rootSeedHex || e.root_seed;
    if (!seed) continue;
    const clientId = await deriveClientId(hexToBytes(seed));
    const prefix = bytesToHex(clientId.slice(0, 8));
    const cfg = map.get(prefix);
    if (!cfg) throw new Error(`missing prefix mapping: ${prefix}`);
    if (cfg.rootSeedHex !== seed) throw new Error(`seed mismatch for prefix ${prefix}`);
  }

  console.log(`ok: registry entries=${parsed.length}, activePrefixes=${map.size}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});


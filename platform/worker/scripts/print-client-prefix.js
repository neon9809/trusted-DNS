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

async function main() {
  const seedHex = (process.argv[2] || '').trim();
  if (!seedHex) throw new Error('usage: node scripts/print-client-prefix.js <root_seed_hex>');
  const seed = hexToBytes(seedHex);
  const clientId = await deriveClientId(seed);
  const prefix = clientId.slice(0, 8);
  process.stdout.write(JSON.stringify({
    client_id: bytesToHex(clientId),
    client_id_prefix: bytesToHex(prefix),
  }, null, 2));
  process.stdout.write('\n');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});


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

async function deriveBootstrapKey(rootSeed) {
  return hkdfDerive(rootSeed, 'trusted-dns/bootstrap', 32);
}

async function computeTicketTag(authKey, ticketData) {
  const key = await crypto.subtle.importKey('raw', authKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, ticketData);
  return new Uint8Array(sig).slice(0, 16);
}

async function computeBootstrapProof(bootstrapKey, bootNonce, timestampMs) {
  const data = new Uint8Array(bootNonce.length + 8);
  data.set(bootNonce, 0);
  const dv = new DataView(data.buffer);
  dv.setBigUint64(bootNonce.length, timestampMs, false);
  return computeTicketTag(bootstrapKey, data);
}

function encodeHeader(h) {
  const buf = new ArrayBuffer(32);
  const dv = new DataView(buf);
  const u8 = new Uint8Array(buf);
  dv.setUint8(0, h.ver);
  dv.setUint8(1, h.msgType);
  dv.setUint16(2, h.flags, false);
  u8.set(h.clientIdPrefix.subarray(0, 8), 4);
  dv.setBigUint64(12, h.bundleGen, false);
  dv.setUint16(20, h.ticketId, false);
  dv.setUint32(22, h.seq, false);
  dv.setUint32(26, h.payloadLen, false);
  dv.setUint16(30, h.headerMac, false);
  return u8;
}

function decodeHeader(data) {
  if (data.length < 32) throw new Error('header too short');
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return {
    ver: dv.getUint8(0),
    msgType: dv.getUint8(1),
    flags: dv.getUint16(2, false),
    clientIdPrefix: data.slice(4, 12),
    bundleGen: dv.getBigUint64(12, false),
    ticketId: dv.getUint16(20, false),
    seq: dv.getUint32(22, false),
    payloadLen: dv.getUint32(26, false),
    headerMac: dv.getUint16(30, false),
  };
}

async function bootstrapOnce(workerUrl, seedHex) {
  const rootSeed = hexToBytes(seedHex);
  const clientId = await deriveClientId(rootSeed);
  const prefix = clientId.slice(0, 8);
  const bootstrapKey = await deriveBootstrapKey(rootSeed);

  const bootNonce = crypto.getRandomValues(new Uint8Array(16));
  const ts = BigInt(Date.now());
  const proof = await computeBootstrapProof(bootstrapKey, bootNonce, ts);
  const capabilities = new Uint8Array(4);

  const payload = new Uint8Array(16 + 8 + 16 + 4);
  payload.set(bootNonce, 0);
  const pv = new DataView(payload.buffer);
  pv.setBigUint64(16, ts, false);
  payload.set(proof, 24);
  payload.set(capabilities, 40);

  const header = encodeHeader({
    ver: 1,
    msgType: 0x01,
    flags: 0,
    clientIdPrefix: prefix,
    bundleGen: 0n,
    ticketId: 0,
    seq: 0,
    payloadLen: payload.length,
    headerMac: 0,
  });

  const req = new Uint8Array(header.length + payload.length);
  req.set(header, 0);
  req.set(payload, header.length);

  const resp = await fetch(workerUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: req,
  });
  if (!resp.ok) throw new Error(`bootstrap failed: http ${resp.status}`);
  const respBuf = new Uint8Array(await resp.arrayBuffer());
  const rh = decodeHeader(respBuf);
  const errCode = rh.msgType === 0x7f ? respBuf[32] : null;
  return {
    client_id_prefix: bytesToHex(prefix),
    resp_client_id_prefix: bytesToHex(rh.clientIdPrefix),
    msg_type: rh.msgType,
    bundle_gen: String(rh.bundleGen),
    err_code: errCode,
  };
}

async function main() {
  const workerUrl = process.env.WORKER_URL || 'http://127.0.0.1:8787/dns-query';
  const seedA = process.env.SEED_A;
  const seedB = process.env.SEED_B;
  if (!seedA || !seedB) throw new Error('SEED_A and SEED_B are required');

  const a1 = await bootstrapOnce(workerUrl, seedA);
  const b1 = await bootstrapOnce(workerUrl, seedB);
  const a2 = await bootstrapOnce(workerUrl, seedA);
  const b2 = await bootstrapOnce(workerUrl, seedB);

  console.log(JSON.stringify({ a1, b1, a2, b2 }, null, 2));

  if (a1.client_id_prefix === b1.client_id_prefix) throw new Error('prefix collision');
  if (BigInt(a2.bundle_gen) !== BigInt(a1.bundle_gen) + 1n) throw new Error('A generation did not advance by 1');
  if (BigInt(b2.bundle_gen) !== BigInt(b1.bundle_gen) + 1n) throw new Error('B generation did not advance by 1');
  console.log('ok');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

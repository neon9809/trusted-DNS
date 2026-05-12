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

async function deriveAllKeys(rootSeed) {
  const [bootstrapKey, ticketAuthKey, refreshAuthKey, bundleWrapKey] = await Promise.all([
    hkdfDerive(rootSeed, 'trusted-dns/bootstrap'),
    hkdfDerive(rootSeed, 'trusted-dns/ticket-mac'),
    hkdfDerive(rootSeed, 'trusted-dns/refresh-mac'),
    hkdfDerive(rootSeed, 'trusted-dns/bundle-wrap'),
  ]);
  return { bootstrapKey, ticketAuthKey, refreshAuthKey, bundleWrapKey };
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

async function aeadDecrypt(keyBytes, nonce, ciphertext, aad) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 16 * 8 },
    key,
    ciphertext,
  );
  return new Uint8Array(decrypted);
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

function deserializeKeyBundle(data) {
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let off = 0;
  const bundleGen = dv.getBigUint64(off, false); off += 8;
  dv.getBigUint64(off, false); off += 8;
  dv.getBigUint64(off, false); off += 8;
  dv.getUint16(off, false); off += 2;
  const ticketsPerBundle = dv.getUint8(off); off += 1;
  off += 1;
  dv.getUint16(off, false); off += 2;
  dv.getUint16(off, false); off += 2;
  dv.getUint32(off, false); off += 4;
  dv.getUint16(off, false); off += 2;
  dv.getBigUint64(off, false); off += 8;
  off += ticketsPerBundle * 114;
  const refreshTicket = data.slice(off, off + 122);
  return { bundleGen, refreshTicket };
}

async function bootstrap(workerUrl, seedHex) {
  const rootSeed = hexToBytes(seedHex);
  const clientId = await deriveClientId(rootSeed);
  const prefix = clientId.slice(0, 8);
  const { bootstrapKey, bundleWrapKey } = await deriveAllKeys(rootSeed);

  const bootNonce = crypto.getRandomValues(new Uint8Array(16));
  const ts = BigInt(Date.now());
  const proof = await computeBootstrapProof(bootstrapKey, bootNonce, ts);
  const payload = new Uint8Array(44);
  payload.set(bootNonce, 0);
  const pv = new DataView(payload.buffer);
  pv.setBigUint64(16, ts, false);
  payload.set(proof, 24);

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

  const req = new Uint8Array(32 + payload.length);
  req.set(header, 0);
  req.set(payload, 32);

  const resp = await fetch(workerUrl, { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: req });
  const respBuf = new Uint8Array(await resp.arrayBuffer());
  const rh = decodeHeader(respBuf);
  if (rh.msgType === 0x7f) throw new Error(`bootstrap error code=${respBuf[32]}`);

  const respPayload = respBuf.slice(32, 32 + rh.payloadLen);
  const nonce = respPayload.slice(16, 28);
  const ciphertext = respPayload.slice(28);
  const aad = encodeHeader({
    ver: 1,
    msgType: 0x02,
    flags: 0,
    clientIdPrefix: prefix,
    bundleGen: rh.bundleGen,
    ticketId: 0,
    seq: 0,
    payloadLen: 0,
    headerMac: 0,
  });
  const bundleBytes = await aeadDecrypt(bundleWrapKey, nonce, ciphertext, aad);
  const bundle = deserializeKeyBundle(bundleBytes);
  return { prefix, bundle, keys: await deriveAllKeys(rootSeed) };
}

async function refreshOnce(workerUrl, seedHex) {
  const { prefix, bundle, keys } = await bootstrap(workerUrl, seedHex);
  const refreshTicketBlob = bundle.refreshTicket;

  const spentBundleGen = BigInt(bundle.bundleGen);
  const spentQueryCount = 0;
  const refreshProof = new Uint8Array(32);
  const reason = 0;

  const payload = new Uint8Array(122 + 8 + 4 + 32 + 1);
  payload.set(refreshTicketBlob, 0);
  const dv = new DataView(payload.buffer);
  dv.setBigUint64(122, spentBundleGen, false);
  dv.setUint32(130, spentQueryCount, false);
  payload.set(refreshProof, 134);
  payload[166] = reason;

  const header = encodeHeader({
    ver: 1,
    msgType: 0x05,
    flags: 0,
    clientIdPrefix: prefix,
    bundleGen: spentBundleGen,
    ticketId: 0,
    seq: 0,
    payloadLen: payload.length,
    headerMac: 0,
  });

  const req = new Uint8Array(32 + payload.length);
  req.set(header, 0);
  req.set(payload, 32);

  const resp = await fetch(workerUrl, { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: req });
  const respBuf = new Uint8Array(await resp.arrayBuffer());
  const rh = decodeHeader(respBuf);
  if (rh.msgType === 0x7f) return { ok: false, err: respBuf[32], prefix: bytesToHex(prefix) };

  const respPayload = respBuf.slice(32, 32 + rh.payloadLen);
  const nonce = respPayload.slice(16, 28);
  const ciphertext = respPayload.slice(28);
  const aad = encodeHeader({
    ver: 1,
    msgType: 0x06,
    flags: 0,
    clientIdPrefix: prefix,
    bundleGen: rh.bundleGen,
    ticketId: 0,
    seq: 0,
    payloadLen: 0,
    headerMac: 0,
  });
  const bundleBytes = await aeadDecrypt(keys.bundleWrapKey, nonce, ciphertext, aad);
  const nextBundle = deserializeKeyBundle(bundleBytes);
  return {
    ok: true,
    prefix: bytesToHex(prefix),
    bootstrapGen: String(bundle.bundleGen),
    respGen: String(rh.bundleGen),
    bundleGen: String(nextBundle.bundleGen),
  };
}

async function main() {
  const workerUrl = process.env.WORKER_URL || 'http://127.0.0.1:8787/dns-query';
  const seedA = process.env.SEED_A;
  const seedB = process.env.SEED_B;
  if (!seedA || !seedB) throw new Error('SEED_A and SEED_B are required');

  const a1 = await refreshOnce(workerUrl, seedA);
  const b1 = await refreshOnce(workerUrl, seedB);
  if (!a1.ok) throw new Error('refresh A failed');
  if (!b1.ok) throw new Error('refresh B failed');
  if (a1.respGen !== String(BigInt(a1.bootstrapGen) + 1n) || a1.bundleGen !== a1.respGen) {
    throw new Error('A generation did not advance by 1');
  }
  if (b1.respGen !== String(BigInt(b1.bootstrapGen) + 1n) || b1.bundleGen !== b1.respGen) {
    throw new Error('B generation did not advance by 1');
  }
  console.log(JSON.stringify({ a1, b1 }, null, 2));
  console.log('ok');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

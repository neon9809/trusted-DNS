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

async function deriveQueryKeys(resumeSeed) {
  const [reqKey, respKey] = await Promise.all([
    hkdfDerive(resumeSeed, 'trusted-dns/query/req'),
    hkdfDerive(resumeSeed, 'trusted-dns/query/resp'),
  ]);
  return { reqKey, respKey };
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

async function aeadEncrypt(keyBytes, plaintext, aad) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 16 * 8 },
    key,
    plaintext,
  );
  return { nonce, ciphertext: new Uint8Array(encrypted) };
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
  const issuedAtMs = dv.getBigUint64(off, false); off += 8;
  const expireAtMs = dv.getBigUint64(off, false); off += 8;
  const workerKid = dv.getUint16(off, false); off += 2;
  const ticketsPerBundle = dv.getUint8(off); off += 1;
  off += 1;
  const queriesPerTicket = dv.getUint16(off, false); off += 2;
  const queriesPerBundle = dv.getUint16(off, false); off += 2;
  const maxClockSkewMs = dv.getUint32(off, false); off += 4;
  const antiReplayWindow = dv.getUint16(off, false); off += 2;
  const ticketLifetimeMs = Number(dv.getBigUint64(off, false)); off += 8;
  const policy = {
    ticketsPerBundle,
    queriesPerTicket,
    queriesPerBundle,
    maxClockSkewMs,
    antiReplayWindow,
    ticketLifetimeMs,
  };
  const sessionTickets = [];
  for (let i = 0; i < ticketsPerBundle; i++) {
    sessionTickets.push(data.slice(off, off + 114));
    off += 114;
  }
  const refreshTicket = data.slice(off, off + 122);
  return { bundleGen, issuedAtMs, expireAtMs, workerKid, policy, sessionTickets, refreshTicket };
}

function decodeSessionTicket(data) {
  if (data.length < 114) throw new Error('ticket too short');
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let off = 0;
  const ticketId = dv.getUint16(off, false); off += 2;
  const slot = dv.getUint8(off); off += 1;
  const reserved = dv.getUint8(off); off += 1;
  const clientId = data.slice(off, off + 32); off += 32;
  const bundleGen = dv.getBigUint64(off, false); off += 8;
  const notBeforeMs = dv.getBigUint64(off, false); off += 8;
  const notAfterMs = dv.getBigUint64(off, false); off += 8;
  const queryBudget = dv.getUint16(off, false); off += 2;
  const counterBase = dv.getUint32(off, false); off += 4;
  const resumeSeed = data.slice(off, off + 32); off += 32;
  const ticketTag = data.slice(off, off + 16);
  return { ticketId, slot, reserved, clientId, bundleGen, notBeforeMs, notAfterMs, queryBudget, counterBase, resumeSeed, ticketTag };
}

function buildDnsQuery(name) {
  const id = 0x1234;
  const header = new Uint8Array(12);
  const dv = new DataView(header.buffer);
  dv.setUint16(0, id, false);
  dv.setUint16(2, 0x0100, false);
  dv.setUint16(4, 1, false);
  dv.setUint16(6, 0, false);
  dv.setUint16(8, 0, false);
  dv.setUint16(10, 0, false);

  const parts = name.split('.');
  const labels = [];
  for (const p of parts) {
    const b = new TextEncoder().encode(p);
    labels.push(Uint8Array.from([b.length]));
    labels.push(b);
  }
  labels.push(Uint8Array.from([0]));
  const qnameLen = labels.reduce((a, b) => a + b.length, 0);
  const qname = new Uint8Array(qnameLen);
  let off = 0;
  for (const l of labels) {
    qname.set(l, off);
    off += l.length;
  }
  const q = new Uint8Array(4);
  const qdv = new DataView(q.buffer);
  qdv.setUint16(0, 1, false);
  qdv.setUint16(2, 1, false);

  const out = new Uint8Array(header.length + qname.length + q.length);
  out.set(header, 0);
  out.set(qname, header.length);
  out.set(q, header.length + qname.length);
  return { bytes: out, id };
}

async function bootstrap(workerUrl, seedHex) {
  const rootSeed = hexToBytes(seedHex);
  const clientId = await deriveClientId(rootSeed);
  const prefix = clientId.slice(0, 8);
  const { bootstrapKey, bundleWrapKey } = await deriveAllKeys(rootSeed);

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
  return { prefix, bundle, rootSeed };
}

async function queryOnce(workerUrl, seedHex, overridePrefixHex) {
  const { prefix, bundle, rootSeed } = await bootstrap(workerUrl, seedHex);
  const { ticketAuthKey } = await deriveAllKeys(rootSeed);
  const ticketBlob = bundle.sessionTickets[0];
  const t = decodeSessionTicket(ticketBlob);
  const { reqKey, respKey } = await deriveQueryKeys(t.resumeSeed);

  const dns = buildDnsQuery('example.com');
  const reqHeader = encodeHeader({
    ver: 1,
    msgType: 0x03,
    flags: 0,
    clientIdPrefix: overridePrefixHex ? hexToBytes(overridePrefixHex) : prefix,
    bundleGen: BigInt(bundle.bundleGen),
    ticketId: t.ticketId,
    seq: t.counterBase,
    payloadLen: 0,
    headerMac: 0,
  });
  const aad = encodeHeader({
    ...decodeHeader(reqHeader),
    payloadLen: 0,
    headerMac: 0,
  });
  const enc = await aeadEncrypt(reqKey, dns.bytes, aad);
  const payload = new Uint8Array(114 + 12 + enc.ciphertext.length);
  payload.set(ticketBlob, 0);
  payload.set(enc.nonce, 114);
  payload.set(enc.ciphertext, 114 + 12);

  const finalHeader = encodeHeader({
    ...decodeHeader(reqHeader),
    payloadLen: payload.length,
  });

  const req = new Uint8Array(32 + payload.length);
  req.set(finalHeader, 0);
  req.set(payload, 32);

  const resp = await fetch(workerUrl, { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: req });
  const respBuf = new Uint8Array(await resp.arrayBuffer());
  const rh = decodeHeader(respBuf);
  if (rh.msgType === 0x7f) return { ok: false, err: respBuf[32], prefix: bytesToHex(prefix) };
  const respPayload = respBuf.slice(32, 32 + rh.payloadLen);
  const rnonce = respPayload.slice(4, 16);
  const rcipher = respPayload.slice(16);
  const respAad = encodeHeader({
    ver: 1,
    msgType: 0x04,
    flags: 0,
    clientIdPrefix: prefix,
    bundleGen: rh.bundleGen,
    ticketId: rh.ticketId,
    seq: rh.seq,
    payloadLen: 0,
    headerMac: 0,
  });
  const dnsResp = await aeadDecrypt(respKey, rnonce, rcipher, respAad);
  const id = new DataView(dnsResp.buffer, dnsResp.byteOffset, dnsResp.byteLength).getUint16(0, false);
  return { ok: id === dns.id, prefix: bytesToHex(prefix), id };
}

async function main() {
  const workerUrl = process.env.WORKER_URL || 'http://127.0.0.1:8787/dns-query';
  const seedA = process.env.SEED_A;
  const seedB = process.env.SEED_B;
  if (!seedA || !seedB) throw new Error('SEED_A and SEED_B are required');

  const a = await queryOnce(workerUrl, seedA);
  const b = await queryOnce(workerUrl, seedB);
  if (!a.ok) {
    console.log(JSON.stringify({ a }, null, 2));
    throw new Error('query A failed');
  }
  if (!b.ok) {
    console.log(JSON.stringify({ b }, null, 2));
    throw new Error('query B failed');
  }

  const cross = await queryOnce(workerUrl, seedA, b.prefix);
  if (cross.ok) throw new Error('cross-client ticket unexpectedly succeeded');

  console.log(JSON.stringify({ a, b, cross }, null, 2));
  console.log('ok');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

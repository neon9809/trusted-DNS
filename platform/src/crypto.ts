/**
 * Trusted-DNS Cryptographic Utilities
 *
 * Implements HKDF key derivation, AES-256-GCM AEAD encryption/decryption,
 * HMAC-based ticket authentication, and client identity derivation.
 *
 * All operations use the Web Crypto API available in Cloudflare Workers.
 */

import {
  NONCE_SIZE,
  TAG_SIZE,
  TICKET_TAG_SIZE,
  CLIENT_ID_SIZE,
  RESUME_SEED_SIZE,
} from './protocol';

// ─── HKDF Key Derivation ───────────────────────────────────────────

/**
 * Derive a key from root seed using HKDF-SHA256.
 * @param rootSeed - The root seed bytes
 * @param info - Purpose string (e.g. "trusted-dns/bootstrap")
 * @param length - Output key length in bytes (default 32)
 */
export async function hkdfDerive(
  rootSeed: Uint8Array,
  info: string,
  length: number = 32,
): Promise<Uint8Array> {
  const baseKey = await crypto.subtle.importKey(
    'raw', rootSeed, { name: 'HKDF' }, false, ['deriveBits'],
  );
  const infoBytes = new TextEncoder().encode(info);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32), // fixed zero salt for simplicity
      info: infoBytes,
    },
    baseKey,
    length * 8,
  );
  return new Uint8Array(bits);
}

/**
 * Derive the full set of purpose-specific keys from root_seed.
 */
export async function deriveAllKeys(rootSeed: Uint8Array) {
  const [bootstrapKey, ticketAuthKey, refreshAuthKey, bundleWrapKey] =
    await Promise.all([
      hkdfDerive(rootSeed, 'trusted-dns/bootstrap'),
      hkdfDerive(rootSeed, 'trusted-dns/ticket-mac'),
      hkdfDerive(rootSeed, 'trusted-dns/refresh-mac'),
      hkdfDerive(rootSeed, 'trusted-dns/bundle-wrap'),
    ]);
  return { bootstrapKey, ticketAuthKey, refreshAuthKey, bundleWrapKey };
}

/**
 * Derive query-phase keys from a session ticket's resume_seed.
 */
export async function deriveQueryKeys(resumeSeed: Uint8Array) {
  const [reqKey, respKey] = await Promise.all([
    hkdfDerive(resumeSeed, 'trusted-dns/query/req'),
    hkdfDerive(resumeSeed, 'trusted-dns/query/resp'),
  ]);
  return { reqKey, respKey };
}

// ─── Client Identity ────────────────────────────────────────────────

/**
 * Derive a stable 32-byte client_id from root_seed.
 */
export async function deriveClientId(rootSeed: Uint8Array): Promise<Uint8Array> {
  return hkdfDerive(rootSeed, 'trusted-dns/client-id', CLIENT_ID_SIZE);
}

// ─── AES-256-GCM AEAD ──────────────────────────────────────────────

/**
 * Encrypt plaintext with AES-256-GCM.
 * Returns { nonce, ciphertext } where ciphertext includes the 16-byte tag.
 */
export async function aeadEncrypt(
  keyBytes: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<{ nonce: Uint8Array; ciphertext: Uint8Array }> {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE));
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt'],
  );
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: TAG_SIZE * 8 },
    key,
    plaintext,
  );
  return { nonce, ciphertext: new Uint8Array(encrypted) };
}

/**
 * Decrypt ciphertext with AES-256-GCM.
 * The ciphertext must include the 16-byte tag appended by encrypt.
 */
export async function aeadDecrypt(
  keyBytes: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt'],
  );
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: TAG_SIZE * 8 },
    key,
    ciphertext,
  );
  return new Uint8Array(decrypted);
}

// ─── HMAC Ticket Authentication ─────────────────────────────────────

/**
 * Compute HMAC-SHA256 tag for ticket authentication.
 * Returns the first 16 bytes of the HMAC as the ticket_tag.
 */
export async function computeTicketTag(
  authKey: Uint8Array,
  ticketData: Uint8Array,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw', authKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, ticketData);
  return new Uint8Array(sig).slice(0, TICKET_TAG_SIZE);
}

/**
 * Verify HMAC-SHA256 tag for ticket authentication.
 */
export async function verifyTicketTag(
  authKey: Uint8Array,
  ticketData: Uint8Array,
  expectedTag: Uint8Array,
): Promise<boolean> {
  const computed = await computeTicketTag(authKey, ticketData);
  if (computed.length !== expectedTag.length) return false;
  let diff = 0;
  for (let i = 0; i < computed.length; i++) {
    diff |= computed[i] ^ expectedTag[i];
  }
  return diff === 0;
}

/**
 * Compute a bootstrap proof from bootstrap_key and boot_nonce + timestamp.
 */
export async function computeBootstrapProof(
  bootstrapKey: Uint8Array,
  bootNonce: Uint8Array,
  timestampMs: bigint,
): Promise<Uint8Array> {
  const data = new Uint8Array(bootNonce.length + 8);
  data.set(bootNonce, 0);
  const dv = new DataView(data.buffer);
  dv.setBigUint64(bootNonce.length, timestampMs, false);
  return computeTicketTag(bootstrapKey, data);
}

/**
 * Verify bootstrap proof.
 */
export async function verifyBootstrapProof(
  bootstrapKey: Uint8Array,
  bootNonce: Uint8Array,
  timestampMs: bigint,
  proof: Uint8Array,
): Promise<boolean> {
  const data = new Uint8Array(bootNonce.length + 8);
  data.set(bootNonce, 0);
  const dv = new DataView(data.buffer);
  dv.setBigUint64(bootNonce.length, timestampMs, false);
  return verifyTicketTag(bootstrapKey, data, proof);
}

/**
 * Compute refresh proof from refresh_seed and spent info.
 */
export async function computeRefreshProof(
  refreshAuthKey: Uint8Array,
  refreshSeed: Uint8Array,
  spentBundleGen: bigint,
  spentQueryCount: number,
): Promise<Uint8Array> {
  const data = new Uint8Array(refreshSeed.length + 12);
  data.set(refreshSeed, 0);
  const dv = new DataView(data.buffer);
  dv.setBigUint64(refreshSeed.length, spentBundleGen, false);
  dv.setUint32(refreshSeed.length + 8, spentQueryCount, false);
  return computeTicketTag(refreshAuthKey, data);
}

// ─── Utility ────────────────────────────────────────────────────────

/** Parse a hex string to Uint8Array */
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Convert Uint8Array to hex string */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Generate random bytes */
export function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

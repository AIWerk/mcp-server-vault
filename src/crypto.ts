/**
 * Bitwarden/Vaultwarden client-side crypto.
 *
 * Key derivation chain:
 *   masterPassword + email → PBKDF2 or Argon2id → masterKey (32 bytes)
 *   masterKey → HKDF-Expand("enc") + HKDF-Expand("mac") → stretchedKey (encKey 32B + macKey 32B)
 *   stretchedKey decrypt profile.key (EncString) → vaultSymKey (encKey 32B + macKey 32B)
 *   vaultSymKey decrypt profile.privateKey (EncString) → RSA private key (PKCS8 DER)
 *   RSA-OAEP-SHA1 decrypt org.key → orgSymKey (encKey 32B + macKey 32B)
 *   orgSymKey decrypt collection.name / cipher.fields / cipher.notes / etc.
 *
 * EncString format (type 2 — AesCbc256_HmacSha256_B64):
 *   "2.<iv_b64>|<ct_b64>|<mac_b64>"
 *
 * RSA EncString (type 4 — Rsa2048_OaepSha1_B64):
 *   "4.<ciphertext_b64>"
 *
 * Send key derivation:
 *   keyMaterial (16 random bytes) → HKDF("bitwarden-send","send",64) → sendKey
 *   sendKey[0:32] = sendEncKey, sendKey[32:64] = sendMacKey
 *   URL fragment = base64url(keyMaterial)
 */

import * as crypto from 'node:crypto';
import argon2 from 'argon2';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface KdfSettings {
  kdfType: 0 | 1;
  kdfIterations: number;
  kdfMemory?: number;
  kdfParallelism?: number;
}

export interface SymKey {
  encKey: Buffer;
  macKey: Buffer;
}

interface ParsedEncString {
  type: number;
  iv: Buffer;
  ct: Buffer;
  mac: Buffer;
}

// ---------------------------------------------------------------------------
// EncString parsing
// ---------------------------------------------------------------------------

export function parseEncString(enc: string): ParsedEncString {
  const dotIdx = enc.indexOf('.');
  if (dotIdx === -1) throw new Error(`Invalid EncString (no type prefix): ${enc.substring(0, 40)}`);
  const type = parseInt(enc.substring(0, dotIdx), 10);
  if (type !== 2) throw new Error(`Unsupported EncString type ${type} (only type 2 supported)`);
  const parts = enc.substring(dotIdx + 1).split('|');
  if (parts.length !== 3) throw new Error(`Invalid EncString type-2 (expected 3 parts): ${enc.substring(0, 40)}`);
  return {
    type,
    iv: Buffer.from(parts[0], 'base64'),
    ct: Buffer.from(parts[1], 'base64'),
    mac: Buffer.from(parts[2], 'base64'),
  };
}

// ---------------------------------------------------------------------------
// AES-256-CBC + HMAC-SHA256
// ---------------------------------------------------------------------------

export function decryptAesCbc256(enc: string, symKey: SymKey): Buffer {
  const { iv, ct, mac } = parseEncString(enc);

  // Verify HMAC before decrypting
  const expected = crypto.createHmac('sha256', symKey.macKey)
    .update(Buffer.concat([iv, ct]))
    .digest();
  if (!crypto.timingSafeEqual(expected, mac)) {
    throw new Error('HMAC verification failed — wrong key or tampered data');
  }

  const decipher = crypto.createDecipheriv('aes-256-cbc', symKey.encKey, iv);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

export function encryptAesCbc256(plaintext: Buffer | string, symKey: SymKey): string {
  const pt = typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : plaintext;
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', symKey.encKey, iv);
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const mac = crypto.createHmac('sha256', symKey.macKey)
    .update(Buffer.concat([iv, ct]))
    .digest();
  return `2.${iv.toString('base64')}|${ct.toString('base64')}|${mac.toString('base64')}`;
}

// ---------------------------------------------------------------------------
// RSA-OAEP decryption (for org keys)
// ---------------------------------------------------------------------------

export function decryptRsaEncString(enc: string, privateKeyDer: Buffer): Buffer {
  const dotIdx = enc.indexOf('.');
  if (dotIdx === -1) throw new Error(`Invalid RSA EncString: ${enc.substring(0, 40)}`);
  const type = parseInt(enc.substring(0, dotIdx), 10);
  // Bitwarden EncString RSA types (no-HMAC variants, supported in v0.1.0):
  //   3 = Rsa2048_OaepSha256_B64  (SHA-256, format: "3.<ct_b64>")
  //   4 = Rsa2048_OaepSha1_B64    (SHA-1,   format: "4.<ct_b64>")  — most common in Vaultwarden
  // HMAC variants (5 = SHA256+HMAC, 6 = SHA1+HMAC) have a pipe-separated payload and are
  // not needed for personal vault org keys in Vaultwarden v1.36.x — throw a clear error if seen.
  if (type === 5 || type === 6) {
    throw new Error(
      `RSA EncString type ${type} (HMAC variant) is not supported in v0.1.0. ` +
      'Vaultwarden org keys typically use type 4. Please report this to Brian.',
    );
  }
  if (type !== 3 && type !== 4) {
    throw new Error(`Unsupported RSA EncString type ${type} (expected 3 or 4)`);
  }
  // For types 3 and 4, the payload is just the RSA ciphertext (no HMAC, no pipe separators)
  const ct = Buffer.from(enc.substring(dotIdx + 1), 'base64');
  const oaepHash = type === 3 ? 'sha256' : 'sha1';
  const privateKey = crypto.createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' });
  return crypto.privateDecrypt(
    { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash },
    ct,
  );
}

// ---------------------------------------------------------------------------
// HKDF-Expand only (PRK already extracted)
// ---------------------------------------------------------------------------
// Bitwarden uses HKDF-Expand with the master key AS the PRK (no extract step).
// T(1) = HMAC-SHA256(PRK, info || 0x01) — sufficient for 32-byte output.

function hkdfExpandOnly(prk: Buffer, info: string, len: number): Buffer {
  const infoBytes = Buffer.from(info, 'utf8');
  const t1 = crypto.createHmac('sha256', prk)
    .update(Buffer.concat([infoBytes, Buffer.from([1])]))
    .digest();
  return t1.subarray(0, len);
}

// ---------------------------------------------------------------------------
// Master key derivation
// ---------------------------------------------------------------------------

export async function deriveMasterKey(password: string, email: string, kdf: KdfSettings): Promise<Buffer> {
  const emailLower = email.toLowerCase();
  if (kdf.kdfType === 0) {
    return Buffer.from(
      crypto.pbkdf2Sync(password, emailLower, kdf.kdfIterations, 32, 'sha256'),
    );
  }
  // Argon2id
  const key = await argon2.hash(Buffer.from(password, 'utf8'), {
    type: argon2.argon2id,
    salt: Buffer.from(emailLower, 'utf8'),
    memoryCost: kdf.kdfMemory ?? 65536,
    timeCost: kdf.kdfIterations,
    parallelism: kdf.kdfParallelism ?? 4,
    hashLength: 32,
    raw: true,
  });
  return key as Buffer;
}

export function stretchMasterKey(masterKey: Buffer): SymKey {
  return {
    encKey: hkdfExpandOnly(masterKey, 'enc', 32),
    macKey: hkdfExpandOnly(masterKey, 'mac', 32),
  };
}

// ---------------------------------------------------------------------------
// Symmetric key from EncString (vault symkey or org symkey)
// ---------------------------------------------------------------------------

export function parseSymKey(raw: Buffer): SymKey {
  if (raw.length !== 64) throw new Error(`Expected 64-byte sym key, got ${raw.length}`);
  return { encKey: raw.subarray(0, 32), macKey: raw.subarray(32, 64) };
}

// ---------------------------------------------------------------------------
// Bitwarden Send key derivation
// ---------------------------------------------------------------------------

export function deriveSendKey(keyMaterial: Buffer): SymKey {
  const sendKey = Buffer.from(
    crypto.hkdfSync('sha256', keyMaterial, 'bitwarden-send', 'send', 64),
  );
  return { encKey: sendKey.subarray(0, 32), macKey: sendKey.subarray(32, 64) };
}

export function generateSendKeyMaterial(): Buffer {
  return crypto.randomBytes(16);
}

export function buildSendUrl(apiBase: string, accessId: string, keyMaterial: Buffer): string {
  const fragment = keyMaterial.toString('base64url');
  return `${apiBase}/#/send/${accessId}/${fragment}`;
}

// ---------------------------------------------------------------------------
// TOTP (RFC 6238)
// ---------------------------------------------------------------------------

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function decodeBase32(s: string): Buffer {
  const cleaned = s.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const ch of cleaned) {
    const idx = BASE32_CHARS.indexOf(ch);
    if (idx === -1) throw new Error(`Invalid base32 character: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

export interface TotpResult {
  code: string;
  period: number;
  remainingSeconds: number;
  algorithm: string;
  digits: number;
}

export function computeTotp(otpauthOrSecret: string): TotpResult {
  let secret = otpauthOrSecret;
  let period = 30;
  let algorithm = 'SHA1';
  let digits = 6;

  if (otpauthOrSecret.startsWith('otpauth://')) {
    const url = new URL(otpauthOrSecret);
    secret = url.searchParams.get('secret') ?? '';
    period = parseInt(url.searchParams.get('period') ?? '30', 10);
    algorithm = (url.searchParams.get('algorithm') ?? 'SHA1').toUpperCase();
    digits = parseInt(url.searchParams.get('digits') ?? '6', 10);
  }

  if (!secret) throw new Error('TOTP secret is empty');

  const key = decodeBase32(secret);
  const nowSeconds = Math.floor(Date.now() / 1000);
  const counter = Math.floor(nowSeconds / period);
  const remaining = period - (nowSeconds % period);

  const counterBuf = Buffer.alloc(8);
  counterBuf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuf.writeUInt32BE(counter >>> 0, 4);

  const hmacAlgo = algorithm === 'SHA256' ? 'sha256' : algorithm === 'SHA512' ? 'sha512' : 'sha1';
  const hmac = crypto.createHmac(hmacAlgo, key).update(counterBuf).digest();

  const offset = hmac[hmac.length - 1] & 0x0f;
  const otp = ((hmac[offset] & 0x7f) << 24)
    | ((hmac[offset + 1] & 0xff) << 16)
    | ((hmac[offset + 2] & 0xff) << 8)
    | (hmac[offset + 3] & 0xff);

  const code = String(otp % Math.pow(10, digits)).padStart(digits, '0');

  return {
    code,
    period,
    remainingSeconds: remaining,
    algorithm,
    digits,
  };
}

// ---------------------------------------------------------------------------
// Audit ID
// ---------------------------------------------------------------------------

export function generateAuditId(): string {
  return crypto.randomUUID();
}

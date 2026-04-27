/**
 * AES-256-GCM at rest for hive-mcp-secrets.
 *
 * Master key sourced from env SECRETS_MASTER_KEY. Accepted forms:
 *   - 64-char hex (32 raw bytes)
 *   - base64-encoded 32 bytes
 *   - any other string is hashed with SHA-256 to derive 32 bytes
 *
 * On encrypt: a fresh 12-byte IV per record. Output stored as
 * (ciphertext, iv, auth_tag) — auth_tag verified on every decrypt.
 * Tampering with any byte of ciphertext or iv causes node:crypto to
 * throw at decipher.final(), surfaced as integrity_check_failed.
 */

import crypto from 'node:crypto';

const ALGO = 'aes-256-gcm';
const IV_BYTES = 12;
const KEY_BYTES = 32;
const TAG_BYTES = 16;

let _key = null;
let _keyError = null;

export function loadMasterKey() {
  const raw = process.env.SECRETS_MASTER_KEY;
  if (!raw) {
    _key = null;
    _keyError = 'SECRETS_MASTER_KEY not set';
    return null;
  }
  let keyBuf;
  if (/^[0-9a-fA-F]{64}$/.test(raw)) {
    keyBuf = Buffer.from(raw, 'hex');
  } else {
    try {
      const b = Buffer.from(raw, 'base64');
      if (b.length === KEY_BYTES) {
        keyBuf = b;
      } else {
        keyBuf = crypto.createHash('sha256').update(raw, 'utf8').digest();
      }
    } catch {
      keyBuf = crypto.createHash('sha256').update(raw, 'utf8').digest();
    }
  }
  if (keyBuf.length !== KEY_BYTES) {
    _key = null;
    _keyError = 'master_key_wrong_length';
    return null;
  }
  _key = keyBuf;
  _keyError = null;
  return _key;
}

export function hasKey() {
  if (_key === null && _keyError === null) loadMasterKey();
  return _key !== null;
}

export function keyError() {
  if (_key === null && _keyError === null) loadMasterKey();
  return _keyError;
}

/**
 * Encrypt a plaintext string. Returns { ciphertext, iv, auth_tag } as
 * base64 strings, suitable for SQLite TEXT columns.
 */
export function encrypt(plaintext) {
  if (!hasKey()) throw new Error('master_key_unavailable');
  if (typeof plaintext !== 'string') plaintext = String(plaintext);
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALGO, _key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    ciphertext: ct.toString('base64'),
    iv: iv.toString('base64'),
    auth_tag: tag.toString('base64'),
  };
}

/**
 * Decrypt a record produced by encrypt(). Throws integrity_check_failed
 * if the ciphertext, iv, or auth_tag has been altered.
 */
export function decrypt({ ciphertext, iv, auth_tag }) {
  if (!hasKey()) throw new Error('master_key_unavailable');
  const ivBuf = Buffer.from(iv, 'base64');
  const tagBuf = Buffer.from(auth_tag, 'base64');
  const ctBuf = Buffer.from(ciphertext, 'base64');
  if (ivBuf.length !== IV_BYTES) throw new Error('integrity_check_failed: bad_iv_length');
  if (tagBuf.length !== TAG_BYTES) throw new Error('integrity_check_failed: bad_tag_length');
  const decipher = crypto.createDecipheriv(ALGO, _key, ivBuf);
  decipher.setAuthTag(tagBuf);
  try {
    const pt = Buffer.concat([decipher.update(ctBuf), decipher.final()]);
    return pt.toString('utf8');
  } catch (err) {
    throw new Error('integrity_check_failed');
  }
}

export const CRYPTO_PARAMS = {
  algorithm: ALGO,
  key_bytes: KEY_BYTES,
  iv_bytes: IV_BYTES,
  tag_bytes: TAG_BYTES,
};

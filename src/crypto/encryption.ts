/**
 * AES-256-GCM encryption and decryption
 *
 * - 12-byte random IV generated fresh for every encrypt call
 * - 16-byte authentication tag for tamper detection
 * - Uses Node.js built-in crypto module (no external deps)
 */

import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;   // NIST recommended for GCM
const TAG_LENGTH = 16;  // 128-bit auth tag

export interface EncryptResult {
  ciphertext: Buffer;
  iv: Buffer;
  tag: Buffer;
}

/**
 * Encrypt plaintext data with AES-256-GCM.
 *
 * @param data - The plaintext string to encrypt
 * @param key  - 32-byte encryption key (from Argon2id derivation)
 * @returns    - ciphertext, iv, and authentication tag
 */
export function encrypt(data: string, key: Buffer): EncryptResult {
  if (key.length !== 32) {
    throw new Error('Encryption key must be 32 bytes (256 bits)');
  }

  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LENGTH });

  const encrypted = Buffer.concat([
    cipher.update(data, 'utf8'),
    cipher.final(),
  ]);

  const tag = cipher.getAuthTag();

  return { ciphertext: encrypted, iv, tag };
}

/**
 * Decrypt AES-256-GCM ciphertext back to plaintext.
 *
 * @param ciphertext - The encrypted data
 * @param key        - 32-byte encryption key (must match the key used to encrypt)
 * @param iv         - The 12-byte IV used during encryption
 * @param tag        - The 16-byte authentication tag from encryption
 * @returns          - The original plaintext string
 * @throws           - If the key is wrong or data has been tampered with
 */
export function decrypt(ciphertext: Buffer, key: Buffer, iv: Buffer, tag: Buffer): string {
  if (key.length !== 32) {
    throw new Error('Encryption key must be 32 bytes (256 bits)');
  }

  const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LENGTH });
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}

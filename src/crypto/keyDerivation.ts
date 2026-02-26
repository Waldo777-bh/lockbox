/**
 * Argon2id key derivation from master password
 *
 * - Argon2id: hybrid mode resistant to both side-channel and GPU/ASIC attacks
 * - 64 MB memory cost makes brute-force expensive
 * - Returns a raw 32-byte key suitable for AES-256
 */

import argon2 from 'argon2';
import { randomBytes } from 'node:crypto';

const SALT_LENGTH = 16;
const KEY_LENGTH = 32;  // 256 bits for AES-256

/** Argon2id parameters — tuned for security on consumer hardware */
const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 65536,    // 64 MB
  timeCost: 3,          // 3 iterations
  parallelism: 4,       // 4 threads
  hashLength: KEY_LENGTH,
  raw: true,            // return raw Buffer, not encoded string
} as const;

/**
 * Derive a 32-byte encryption key from a master password and salt.
 *
 * @param password - The user's master password
 * @param salt     - 16-byte random salt (stored alongside the vault)
 * @returns        - 32-byte derived key for AES-256-GCM
 */
export async function deriveKey(password: string, salt: Buffer): Promise<Buffer> {
  if (salt.length !== SALT_LENGTH) {
    throw new Error(`Salt must be ${SALT_LENGTH} bytes`);
  }

  const key = await argon2.hash(password, {
    ...ARGON2_OPTIONS,
    salt,
  });

  // argon2.hash with raw:true returns a Buffer
  return key as Buffer;
}

/**
 * Generate a cryptographically random 16-byte salt.
 *
 * @returns - 16-byte random salt for use with deriveKey()
 */
export function generateSalt(): Buffer {
  return randomBytes(SALT_LENGTH);
}

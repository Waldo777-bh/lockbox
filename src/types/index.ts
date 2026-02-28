/**
 * Lockbox type definitions
 */

/** Structure of the encrypted vault file on disk */
export interface VaultFile {
  salt: string;       // Base64-encoded salt for Argon2id
  iv: string;         // Base64-encoded AES-GCM IV (12 bytes)
  tag: string;        // Base64-encoded AES-GCM auth tag
  ciphertext: string; // Base64-encoded encrypted vault data
  hmac: string;       // Base64-encoded HMAC-SHA256 for integrity
}

/** A single stored secret */
export interface SecretEntry {
  value: string;
  project: string;
  notes: string;
  createdAt: string;
  expiresAt: string | null;
}

/** Decrypted vault data structure */
export interface VaultData {
  version: number;
  keys: Record<string, SecretEntry>;
  metadata: {
    createdAt: string;
    lastModified: string;
  };
}

/** Lockbox configuration */
export interface LockboxConfig {
  vaultPath: string;
  autoLockMinutes: number;
  defaultProject: string;
  licenceKey?: string;
}

/** Cached tier validation result */
export interface TierCache {
  tier: string;
  validatedAt: number;
  keyLimit: number;
}

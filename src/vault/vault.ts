/**
 * Vault class — encrypted storage and CRUD operations
 *
 * The vault is a single encrypted JSON file on disk. It is decrypted into
 * memory when opened, and re-encrypted on every save. The derived key is
 * held in memory only while the vault is unlocked.
 *
 * File on disk (vault.enc):
 *   { salt, iv, tag, ciphertext, hmac }  — all base64-encoded
 *
 * Decrypted payload:
 *   { version, keys: { "service/KEY_NAME": SecretEntry }, metadata }
 */

import { readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { encrypt, decrypt } from '../crypto/encryption.js';
import { deriveKey, generateSalt } from '../crypto/keyDerivation.js';
import { ensureConfigDir } from './config.js';
import type { VaultFile, VaultData, SecretEntry } from '../types/index.js';

/** Current vault format version */
const VAULT_VERSION = 1;

/** Options when adding a key */
export interface AddKeyOptions {
  project?: string;
  notes?: string;
  expiresAt?: string | null;
}

/** Key listing entry (no secret value exposed) */
export interface KeyListEntry {
  name: string;       // "service/KEY_NAME"
  project: string;
  notes: string;
  createdAt: string;
  expiresAt: string | null;
}

/**
 * Compute HMAC-SHA256 over the ciphertext for integrity verification.
 * This lets us detect tampering *before* attempting decryption.
 */
function computeHmac(ciphertext: string, key: Buffer): string {
  return createHmac('sha256', key).update(ciphertext).digest('base64');
}

export class Vault {
  private data: VaultData | null = null;
  private derivedKey: Buffer | null = null;
  private salt: Buffer | null = null;
  private filePath: string;

  private constructor(filePath: string) {
    this.filePath = filePath;
  }

  /** Get the derived key (needed by session manager to persist unlock state) */
  getDerivedKey(): Buffer {
    if (!this.derivedKey) {
      throw new Error('Vault is locked — no derived key available');
    }
    return this.derivedKey;
  }

  // ---------------------------------------------------------------------------
  // Static factory methods
  // ---------------------------------------------------------------------------

  /**
   * Create a brand-new empty vault, encrypt it, and write to disk.
   *
   * @param filePath - Where to store the vault file
   * @param password - Master password
   * @returns        - An unlocked Vault instance
   */
  static async create(filePath: string, password: string): Promise<Vault> {
    ensureConfigDir();

    const vault = new Vault(filePath);
    const salt = generateSalt();
    const key = await deriveKey(password, salt);

    const now = new Date().toISOString();
    vault.data = {
      version: VAULT_VERSION,
      keys: {},
      metadata: {
        createdAt: now,
        lastModified: now,
      },
    };
    vault.derivedKey = key;
    vault.salt = salt;

    await vault.save();
    return vault;
  }

  /**
   * Open an existing vault file, verify integrity, and decrypt.
   *
   * @param filePath - Path to the vault.enc file
   * @param password - Master password
   * @returns        - An unlocked Vault instance
   * @throws         - On wrong password, tampered file, or missing file
   */
  static async open(filePath: string, password: string): Promise<Vault> {
    if (!existsSync(filePath)) {
      throw new Error(`Vault file not found: ${filePath}`);
    }

    const raw = readFileSync(filePath, 'utf8');
    const file: VaultFile = JSON.parse(raw);

    const salt = Buffer.from(file.salt, 'base64');
    const key = await deriveKey(password, salt);

    return Vault.decryptAndLoad(filePath, key, salt, file);
  }

  /**
   * Open an existing vault with a pre-derived key (from session).
   * Skips Argon2id derivation — used for session-resumed commands.
   *
   * @param filePath - Path to the vault.enc file
   * @param key      - 32-byte derived encryption key
   * @returns        - An unlocked Vault instance
   */
  static openWithKey(filePath: string, key: Buffer): Vault {
    if (!existsSync(filePath)) {
      throw new Error(`Vault file not found: ${filePath}`);
    }

    const raw = readFileSync(filePath, 'utf8');
    const file: VaultFile = JSON.parse(raw);
    const salt = Buffer.from(file.salt, 'base64');

    return Vault.decryptAndLoad(filePath, key, salt, file);
  }

  /**
   * Shared: verify HMAC, decrypt, and construct a Vault instance.
   */
  private static decryptAndLoad(
    filePath: string,
    key: Buffer,
    salt: Buffer,
    file: VaultFile,
  ): Vault {
    // ── HMAC integrity check (constant-time comparison to prevent timing attacks) ──
    const expectedHmac = computeHmac(file.ciphertext, key);
    const expectedBuf = Buffer.from(expectedHmac, 'base64');
    const actualBuf = Buffer.from(file.hmac, 'base64');
    if (expectedBuf.length !== actualBuf.length || !timingSafeEqual(expectedBuf, actualBuf)) {
      throw new Error('Vault integrity check failed — file may be tampered or wrong password');
    }

    // ── Decrypt ──
    const iv = Buffer.from(file.iv, 'base64');
    const tag = Buffer.from(file.tag, 'base64');
    const ciphertext = Buffer.from(file.ciphertext, 'base64');

    let plaintext: string;
    try {
      plaintext = decrypt(ciphertext, key, iv, tag);
    } catch {
      throw new Error('Failed to decrypt vault — wrong password or corrupted file');
    }

    const data: VaultData = JSON.parse(plaintext);

    const vault = new Vault(filePath);
    vault.data = data;
    vault.derivedKey = key;
    vault.salt = salt;

    return vault;
  }

  // ---------------------------------------------------------------------------
  // CRUD operations
  // ---------------------------------------------------------------------------

  /**
   * Add or update a key in the vault.
   *
   * @param service - Service name (e.g. "openai")
   * @param keyName - Key identifier (e.g. "API_KEY")
   * @param value   - The secret value
   * @param options - Optional project, notes, expiry
   */
  addKey(service: string, keyName: string, value: string, options?: AddKeyOptions): void {
    this.ensureUnlocked();

    const fullKey = `${service}/${keyName}`;
    this.data!.keys[fullKey] = {
      value,
      project: options?.project ?? 'default',
      notes: options?.notes ?? '',
      createdAt: new Date().toISOString(),
      expiresAt: options?.expiresAt ?? null,
    };
    this.data!.metadata.lastModified = new Date().toISOString();
  }

  /**
   * Retrieve the decrypted value of a stored key.
   *
   * @param service - Service name
   * @param keyName - Key identifier
   * @returns       - The secret value
   * @throws        - If key doesn't exist or vault is locked
   */
  getKey(service: string, keyName: string): string {
    this.ensureUnlocked();

    const fullKey = `${service}/${keyName}`;
    const entry = this.data!.keys[fullKey];
    if (!entry) {
      throw new Error(`Key not found: ${fullKey}`);
    }
    return entry.value;
  }

  /**
   * Delete a key from the vault.
   *
   * @param service - Service name
   * @param keyName - Key identifier
   * @returns       - true if the key was removed, false if it didn't exist
   */
  removeKey(service: string, keyName: string): boolean {
    this.ensureUnlocked();

    const fullKey = `${service}/${keyName}`;
    if (!(fullKey in this.data!.keys)) {
      return false;
    }
    delete this.data!.keys[fullKey];
    this.data!.metadata.lastModified = new Date().toISOString();
    return true;
  }

  /**
   * List all stored keys (names + metadata, never values).
   *
   * @param project - Optional filter by project name
   * @returns       - Array of key listing entries
   */
  listKeys(project?: string): KeyListEntry[] {
    this.ensureUnlocked();

    const entries: KeyListEntry[] = [];
    for (const [name, entry] of Object.entries(this.data!.keys)) {
      if (project && entry.project !== project) continue;
      entries.push({
        name,
        project: entry.project,
        notes: entry.notes,
        createdAt: entry.createdAt,
        expiresAt: entry.expiresAt,
      });
    }
    return entries;
  }

  /**
   * List all unique project names across stored keys.
   */
  listProjects(): string[] {
    this.ensureUnlocked();

    const projects = new Set<string>();
    for (const entry of Object.values(this.data!.keys)) {
      projects.add(entry.project);
    }
    return [...projects].sort();
  }

  /**
   * Export all keys as name→value pairs, optionally filtered by project.
   * Used by the export command — intentionally returns plaintext values.
   */
  exportKeys(project?: string): { name: string; value: string }[] {
    this.ensureUnlocked();

    const result: { name: string; value: string }[] = [];
    for (const [name, entry] of Object.entries(this.data!.keys)) {
      if (project && entry.project !== project) continue;
      result.push({ name, value: entry.value });
    }
    return result;
  }

  /**
   * Check whether a key exists in the vault.
   */
  hasKey(service: string, keyName: string): boolean {
    this.ensureUnlocked();
    return `${service}/${keyName}` in this.data!.keys;
  }

  // ---------------------------------------------------------------------------
  // Persistence
  // ---------------------------------------------------------------------------

  /**
   * Re-encrypt the vault data and write to disk.
   * Generates a fresh IV on every save (never reused).
   */
  async save(): Promise<void> {
    this.ensureUnlocked();

    const plaintext = JSON.stringify(this.data);
    const { ciphertext, iv, tag } = encrypt(plaintext, this.derivedKey!);

    const ciphertextB64 = ciphertext.toString('base64');
    const hmac = computeHmac(ciphertextB64, this.derivedKey!);

    const file: VaultFile = {
      salt: this.salt!.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: ciphertextB64,
      hmac,
    };

    writeFileSync(this.filePath, JSON.stringify(file, null, 2), { encoding: 'utf8', mode: 0o600 });
    // Ensure restrictive permissions even if file already existed
    try { chmodSync(this.filePath, 0o600); } catch { /* Windows may not support chmod */ }
  }

  // ---------------------------------------------------------------------------
  // Locking
  // ---------------------------------------------------------------------------

  /**
   * Lock the vault — zero out decrypted data and derived key from memory.
   */
  lock(): void {
    if (this.derivedKey) {
      this.derivedKey.fill(0);
    }
    this.derivedKey = null;
    this.data = null;
    this.salt = null;
  }

  /**
   * Check whether the vault is currently locked.
   */
  isLocked(): boolean {
    return this.data === null || this.derivedKey === null;
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  private ensureUnlocked(): void {
    if (this.isLocked()) {
      throw new Error('Vault is locked — unlock it first');
    }
  }
}

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, rmSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Vault } from '../src/vault/vault.js';
import type { VaultFile } from '../src/types/index.js';

/** Create a unique temp directory for each test run */
function makeTempDir(): string {
  const dir = join(tmpdir(), `lockbox-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

describe('Vault', () => {
  let tempDir: string;
  let vaultPath: string;
  const PASSWORD = 'test-master-password';

  beforeEach(() => {
    tempDir = makeTempDir();
    vaultPath = join(tempDir, 'vault.enc');
  });

  afterEach(() => {
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  // -------------------------------------------------------------------------
  // Creation & Opening
  // -------------------------------------------------------------------------

  it('creates a new vault and writes an encrypted file to disk', async () => {
    const vault = await Vault.create(vaultPath, PASSWORD);

    expect(vault.isLocked()).toBe(false);
    expect(existsSync(vaultPath)).toBe(true);

    // File should be valid JSON with expected fields
    const raw = readFileSync(vaultPath, 'utf8');
    const file: VaultFile = JSON.parse(raw);
    expect(file).toHaveProperty('salt');
    expect(file).toHaveProperty('iv');
    expect(file).toHaveProperty('tag');
    expect(file).toHaveProperty('ciphertext');
    expect(file).toHaveProperty('hmac');

    vault.lock();
  });

  it('opens an existing vault with the correct password', async () => {
    await Vault.create(vaultPath, PASSWORD);
    const vault = await Vault.open(vaultPath, PASSWORD);

    expect(vault.isLocked()).toBe(false);
    vault.lock();
  });

  it('throws when opening with wrong password', async () => {
    await Vault.create(vaultPath, PASSWORD);
    await expect(Vault.open(vaultPath, 'wrong-password')).rejects.toThrow();
  });

  it('throws when vault file does not exist', async () => {
    await expect(Vault.open(vaultPath, PASSWORD)).rejects.toThrow('not found');
  });

  // -------------------------------------------------------------------------
  // CRUD: add, get, remove
  // -------------------------------------------------------------------------

  it('adds a key and retrieves the same value', async () => {
    const vault = await Vault.create(vaultPath, PASSWORD);

    vault.addKey('openai', 'API_KEY', 'sk-abc123', {
      project: 'myapp',
      notes: 'Production key',
    });

    expect(vault.getKey('openai', 'API_KEY')).toBe('sk-abc123');
    vault.lock();
  });

  it('persists keys across save → open cycle', async () => {
    const vault = await Vault.create(vaultPath, PASSWORD);

    vault.addKey('openai', 'API_KEY', 'sk-abc123', { project: 'myapp' });
    vault.addKey('stripe', 'SECRET', 'sk_live_xyz', { project: 'billing' });
    await vault.save();
    vault.lock();

    // Re-open from disk
    const vault2 = await Vault.open(vaultPath, PASSWORD);
    expect(vault2.getKey('openai', 'API_KEY')).toBe('sk-abc123');
    expect(vault2.getKey('stripe', 'SECRET')).toBe('sk_live_xyz');
    vault2.lock();
  });

  it('throws when getting a key that does not exist', async () => {
    const vault = await Vault.create(vaultPath, PASSWORD);
    expect(() => vault.getKey('nonexistent', 'KEY')).toThrow('Key not found');
    vault.lock();
  });

  it('removes a key successfully', async () => {
    const vault = await Vault.create(vaultPath, PASSWORD);
    vault.addKey('openai', 'API_KEY', 'sk-abc123');

    const removed = vault.removeKey('openai', 'API_KEY');
    expect(removed).toBe(true);
    expect(() => vault.getKey('openai', 'API_KEY')).toThrow('Key not found');
    vault.lock();
  });

  it('removeKey returns false for nonexistent key', async () => {
    const vault = await Vault.create(vaultPath, PASSWORD);
    expect(vault.removeKey('nope', 'NOTHING')).toBe(false);
    vault.lock();
  });

  it('addKey overwrites an existing key', async () => {
    const vault = await Vault.create(vaultPath, PASSWORD);

    vault.addKey('openai', 'API_KEY', 'old-value');
    vault.addKey('openai', 'API_KEY', 'new-value');

    expect(vault.getKey('openai', 'API_KEY')).toBe('new-value');
    vault.lock();
  });

  // -------------------------------------------------------------------------
  // Listing
  // -------------------------------------------------------------------------

  it('listKeys returns names and metadata but NOT values', async () => {
    const vault = await Vault.create(vaultPath, PASSWORD);

    vault.addKey('openai', 'API_KEY', 'sk-secret', { project: 'myapp', notes: 'prod' });
    vault.addKey('stripe', 'SECRET', 'sk_live_xyz', { project: 'billing' });

    const keys = vault.listKeys();

    expect(keys).toHaveLength(2);

    // Values must NOT appear in listing
    for (const entry of keys) {
      expect(entry).not.toHaveProperty('value');
    }

    const names = keys.map((k) => k.name);
    expect(names).toContain('openai/API_KEY');
    expect(names).toContain('stripe/SECRET');

    vault.lock();
  });

  it('listKeys filters by project', async () => {
    const vault = await Vault.create(vaultPath, PASSWORD);

    vault.addKey('openai', 'API_KEY', 'sk-abc', { project: 'myapp' });
    vault.addKey('stripe', 'SECRET', 'sk_live', { project: 'billing' });
    vault.addKey('aws', 'ACCESS_KEY', 'AKIA...', { project: 'myapp' });

    const myappKeys = vault.listKeys('myapp');
    expect(myappKeys).toHaveLength(2);
    expect(myappKeys.every((k) => k.project === 'myapp')).toBe(true);

    const billingKeys = vault.listKeys('billing');
    expect(billingKeys).toHaveLength(1);
    expect(billingKeys[0].name).toBe('stripe/SECRET');

    vault.lock();
  });

  it('listProjects returns unique sorted project names', async () => {
    const vault = await Vault.create(vaultPath, PASSWORD);

    vault.addKey('a', 'K1', 'v', { project: 'billing' });
    vault.addKey('b', 'K2', 'v', { project: 'myapp' });
    vault.addKey('c', 'K3', 'v', { project: 'billing' });
    vault.addKey('d', 'K4', 'v', { project: 'analytics' });

    expect(vault.listProjects()).toEqual(['analytics', 'billing', 'myapp']);
    vault.lock();
  });

  // -------------------------------------------------------------------------
  // Locking
  // -------------------------------------------------------------------------

  it('lock clears data, subsequent operations throw', async () => {
    const vault = await Vault.create(vaultPath, PASSWORD);
    vault.addKey('openai', 'API_KEY', 'sk-abc123');

    vault.lock();
    expect(vault.isLocked()).toBe(true);

    expect(() => vault.getKey('openai', 'API_KEY')).toThrow('locked');
    expect(() => vault.addKey('x', 'Y', 'z')).toThrow('locked');
    expect(() => vault.removeKey('openai', 'API_KEY')).toThrow('locked');
    expect(() => vault.listKeys()).toThrow('locked');
    expect(() => vault.listProjects()).toThrow('locked');
  });

  // -------------------------------------------------------------------------
  // HMAC integrity check
  // -------------------------------------------------------------------------

  it('detects tampered ciphertext via HMAC', async () => {
    const vault = await Vault.create(vaultPath, PASSWORD);
    vault.addKey('openai', 'API_KEY', 'sk-abc123');
    await vault.save();
    vault.lock();

    // Tamper with the ciphertext on disk
    const raw = readFileSync(vaultPath, 'utf8');
    const file: VaultFile = JSON.parse(raw);

    // Corrupt the ciphertext by replacing last few chars
    file.ciphertext = file.ciphertext.slice(0, -4) + 'XXXX';
    writeFileSync(vaultPath, JSON.stringify(file), 'utf8');

    await expect(Vault.open(vaultPath, PASSWORD)).rejects.toThrow(/integrity|tamper|password/i);
  });

  it('detects tampered HMAC value', async () => {
    const vault = await Vault.create(vaultPath, PASSWORD);
    vault.addKey('openai', 'API_KEY', 'sk-abc123');
    await vault.save();
    vault.lock();

    // Tamper with the HMAC
    const raw = readFileSync(vaultPath, 'utf8');
    const file: VaultFile = JSON.parse(raw);
    file.hmac = 'AAAA' + file.hmac.slice(4);
    writeFileSync(vaultPath, JSON.stringify(file), 'utf8');

    await expect(Vault.open(vaultPath, PASSWORD)).rejects.toThrow(/integrity|tamper|password/i);
  });

  // -------------------------------------------------------------------------
  // Edge cases
  // -------------------------------------------------------------------------

  it('handles keys with special characters in values', async () => {
    const vault = await Vault.create(vaultPath, PASSWORD);
    const specialValue = 'sk-abc123!@#$%^&*()_+{}|:"<>?~`';

    vault.addKey('test', 'SPECIAL', specialValue);
    await vault.save();
    vault.lock();

    const vault2 = await Vault.open(vaultPath, PASSWORD);
    expect(vault2.getKey('test', 'SPECIAL')).toBe(specialValue);
    vault2.lock();
  });

  it('handles empty vault (no keys) correctly', async () => {
    const vault = await Vault.create(vaultPath, PASSWORD);

    expect(vault.listKeys()).toEqual([]);
    expect(vault.listProjects()).toEqual([]);

    vault.lock();
  });
});

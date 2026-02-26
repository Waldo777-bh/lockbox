import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Vault } from '../src/vault/vault.js';

/** Create a unique temp directory for each test */
function makeTempDir(): string {
  const dir = join(
    tmpdir(),
    `lockbox-ie-test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  mkdirSync(dir, { recursive: true });
  return dir;
}

describe('import / export', () => {
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

  // -----------------------------------------------------------------------
  // Export
  // -----------------------------------------------------------------------

  it('exportKeys returns all key name-value pairs', async () => {
    const vault = await Vault.create(vaultPath, PASSWORD);
    vault.addKey('openai', 'API_KEY', 'sk-abc123', { project: 'myapp' });
    vault.addKey('stripe', 'SECRET', 'sk_live_xyz', { project: 'billing' });

    const pairs = vault.exportKeys();
    expect(pairs).toHaveLength(2);
    expect(pairs).toContainEqual({ name: 'openai/API_KEY', value: 'sk-abc123' });
    expect(pairs).toContainEqual({ name: 'stripe/SECRET', value: 'sk_live_xyz' });

    vault.lock();
  });

  it('exportKeys filters by project', async () => {
    const vault = await Vault.create(vaultPath, PASSWORD);
    vault.addKey('openai', 'API_KEY', 'sk-abc123', { project: 'myapp' });
    vault.addKey('stripe', 'SECRET', 'sk_live_xyz', { project: 'billing' });
    vault.addKey('aws', 'ACCESS_KEY', 'AKIA123', { project: 'myapp' });

    const myappPairs = vault.exportKeys('myapp');
    expect(myappPairs).toHaveLength(2);
    expect(myappPairs.every((p) => p.name.includes('openai') || p.name.includes('aws'))).toBe(true);

    const billingPairs = vault.exportKeys('billing');
    expect(billingPairs).toHaveLength(1);
    expect(billingPairs[0].name).toBe('stripe/SECRET');

    vault.lock();
  });

  it('exportKeys returns empty array for empty vault', async () => {
    const vault = await Vault.create(vaultPath, PASSWORD);
    expect(vault.exportKeys()).toEqual([]);
    vault.lock();
  });

  // -----------------------------------------------------------------------
  // hasKey
  // -----------------------------------------------------------------------

  it('hasKey returns true for existing key', async () => {
    const vault = await Vault.create(vaultPath, PASSWORD);
    vault.addKey('openai', 'API_KEY', 'sk-abc123');
    expect(vault.hasKey('openai', 'API_KEY')).toBe(true);
    expect(vault.hasKey('openai', 'NOPE')).toBe(false);
    vault.lock();
  });

  // -----------------------------------------------------------------------
  // Round-trip: vault → .env string → new vault
  // -----------------------------------------------------------------------

  it('round-trip: export to env format, parse, re-import — keys match', async () => {
    // Create vault with keys
    const vault1 = await Vault.create(vaultPath, PASSWORD);
    vault1.addKey('openai', 'API_KEY', 'sk-abc123', { project: 'myapp' });
    vault1.addKey('stripe', 'SECRET', 'sk_live_xyz', { project: 'myapp' });
    vault1.addKey('aws', 'ACCESS_KEY', 'AKIA_test_key', { project: 'myapp' });
    await vault1.save();

    // Export to env format
    const pairs = vault1.exportKeys();
    const envContent = pairs
      .map(({ name, value }) => `${name.replace(/\//g, '_').toUpperCase()}=${value}`)
      .join('\n') + '\n';
    vault1.lock();

    // Write .env file
    const envPath = join(tempDir, '.env');
    writeFileSync(envPath, envContent, 'utf8');

    // Parse the env file back (simulating import parsing)
    const parsed = parseEnvFile(envContent);
    expect(parsed).toHaveLength(3);

    // Import into a fresh vault
    const vault2Path = join(tempDir, 'vault2.enc');
    const vault2 = await Vault.create(vault2Path, PASSWORD);

    for (const { key, value } of parsed) {
      // Split KEY_NAME back into service/keyname (best-effort)
      const parts = key.split('_');
      const service = parts[0].toLowerCase();
      const keyName = parts.slice(1).join('_');
      vault2.addKey(service, keyName, value, { project: 'imported' });
    }
    await vault2.save();

    // Verify values match
    expect(vault2.getKey('openai', 'API_KEY')).toBe('sk-abc123');
    expect(vault2.getKey('stripe', 'SECRET')).toBe('sk_live_xyz');
    expect(vault2.getKey('aws', 'ACCESS_KEY')).toBe('AKIA_test_key');

    vault2.lock();
  });

  // -----------------------------------------------------------------------
  // Round-trip: vault → JSON → new vault
  // -----------------------------------------------------------------------

  it('round-trip: export to JSON, parse, re-import — keys match', async () => {
    const vault1 = await Vault.create(vaultPath, PASSWORD);
    vault1.addKey('github', 'TOKEN', 'ghp_abc123', { project: 'ci' });
    vault1.addKey('vercel', 'API_KEY', 'vc_xyz789', { project: 'ci' });
    await vault1.save();

    // Export to JSON
    const pairs = vault1.exportKeys();
    const jsonObj: Record<string, string> = {};
    for (const { name, value } of pairs) {
      jsonObj[name] = value;
    }
    const jsonContent = JSON.stringify(jsonObj, null, 2);
    vault1.lock();

    // Write JSON file
    const jsonPath = join(tempDir, 'keys.json');
    writeFileSync(jsonPath, jsonContent, 'utf8');

    // Parse JSON back
    const parsed = JSON.parse(jsonContent) as Record<string, string>;

    // Import into a fresh vault
    const vault2Path = join(tempDir, 'vault2.enc');
    const vault2 = await Vault.create(vault2Path, PASSWORD);

    for (const [name, value] of Object.entries(parsed)) {
      const slashIdx = name.indexOf('/');
      const service = name.slice(0, slashIdx);
      const keyName = name.slice(slashIdx + 1);
      vault2.addKey(service, keyName, value, { project: 'reimported' });
    }
    await vault2.save();

    // Verify
    expect(vault2.getKey('github', 'TOKEN')).toBe('ghp_abc123');
    expect(vault2.getKey('vercel', 'API_KEY')).toBe('vc_xyz789');

    vault2.lock();
  });

  // -----------------------------------------------------------------------
  // .env parsing edge cases
  // -----------------------------------------------------------------------

  it('parses .env with comments, blank lines, and quotes', () => {
    const content = `
# This is a comment
OPENAI_API_KEY=sk-abc123

STRIPE_SECRET="sk_live_xyz"
AWS_KEY='AKIA_test'

# Another comment
EMPTY_VAL=
`;
    const parsed = parseEnvFile(content);
    expect(parsed).toContainEqual({ key: 'OPENAI_API_KEY', value: 'sk-abc123' });
    expect(parsed).toContainEqual({ key: 'STRIPE_SECRET', value: 'sk_live_xyz' });
    expect(parsed).toContainEqual({ key: 'AWS_KEY', value: 'AKIA_test' });
    expect(parsed).toContainEqual({ key: 'EMPTY_VAL', value: '' });
    // Should not include comments
    expect(parsed.some((e) => e.key.startsWith('#'))).toBe(false);
  });

  it('parses .env with values containing = signs', () => {
    const content = 'API_KEY=sk-abc=123==\n';
    const parsed = parseEnvFile(content);
    expect(parsed).toHaveLength(1);
    expect(parsed[0].value).toBe('sk-abc=123==');
  });

  // -----------------------------------------------------------------------
  // JSON parsing edge cases
  // -----------------------------------------------------------------------

  it('parses flat JSON object', () => {
    const content = '{ "API_KEY": "sk-abc123", "SECRET": "xyz" }';
    const parsed = parseJsonFile(content);
    expect(parsed).toHaveLength(2);
    expect(parsed).toContainEqual({ key: 'API_KEY', value: 'sk-abc123' });
    expect(parsed).toContainEqual({ key: 'SECRET', value: 'xyz' });
  });

  it('rejects non-object JSON', () => {
    expect(() => parseJsonFile('[1,2,3]')).toThrow();
    expect(() => parseJsonFile('"string"')).toThrow();
  });

  // -----------------------------------------------------------------------
  // Shell format export
  // -----------------------------------------------------------------------

  it('export to shell format produces export statements', async () => {
    const vault = await Vault.create(vaultPath, PASSWORD);
    vault.addKey('openai', 'API_KEY', 'sk-abc123');

    const pairs = vault.exportKeys();
    const shellOutput = pairs
      .map(({ name, value }) => {
        const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
        return `export ${name.replace(/\//g, '_').toUpperCase()}="${escaped}"`;
      })
      .join('\n') + '\n';

    expect(shellOutput).toBe('export OPENAI_API_KEY="sk-abc123"\n');

    vault.lock();
  });

  it('shell format escapes special characters', async () => {
    const vault = await Vault.create(vaultPath, PASSWORD);
    vault.addKey('test', 'KEY', 'value-with-"quotes"-and-\\slashes');

    const pairs = vault.exportKeys();
    const shellOutput = pairs
      .map(({ name, value }) => {
        const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
        return `export ${name.replace(/\//g, '_').toUpperCase()}="${escaped}"`;
      })
      .join('\n') + '\n';

    expect(shellOutput).toContain('\\"quotes\\"');
    expect(shellOutput).toContain('\\\\slashes');

    vault.lock();
  });
});

// ─── Helpers: mirror the parsing logic from cli/index.ts ─────────────────────
// These duplicate the private functions so we can test them directly.

function parseEnvFile(raw: string): { key: string; value: string }[] {
  const entries: { key: string; value: string }[] = [];

  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;

    const key = trimmed.slice(0, eqIdx).trim();
    let value = trimmed.slice(eqIdx + 1).trim();

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    if (key) {
      entries.push({ key, value });
    }
  }

  return entries;
}

function parseJsonFile(raw: string): { key: string; value: string }[] {
  const obj = JSON.parse(raw);
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
    throw new Error('JSON import expects a flat { "KEY": "value" } object');
  }
  return Object.entries(obj).map(([key, value]) => ({
    key,
    value: String(value),
  }));
}

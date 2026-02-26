import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Vault } from '../src/vault/vault.js';
import {
  parseProxyUri,
  buildProxyUri,
  parseEnvFile,
  envKeyName,
  PROXY_PREFIX,
} from '../src/cli/env-utils.js';

/** Create a unique temp directory for each test run */
function makeTempDir(): string {
  const dir = join(tmpdir(), `lockbox-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

// ─── parseProxyUri ────────────────────────────────────────────────────────────

describe('parseProxyUri', () => {
  it('parses a valid proxy URI', () => {
    const result = parseProxyUri('lockbox://openai/API_KEY');
    expect(result).toEqual({ service: 'openai', keyName: 'API_KEY' });
  });

  it('parses proxy URI with complex key name', () => {
    const result = parseProxyUri('lockbox://aws/SECRET_ACCESS_KEY');
    expect(result).toEqual({ service: 'aws', keyName: 'SECRET_ACCESS_KEY' });
  });

  it('returns null for non-proxy values', () => {
    expect(parseProxyUri('sk-abc123')).toBeNull();
    expect(parseProxyUri('postgresql://localhost/mydb')).toBeNull();
    expect(parseProxyUri('https://example.com')).toBeNull();
    expect(parseProxyUri('')).toBeNull();
  });

  it('returns null for malformed proxy URIs', () => {
    expect(parseProxyUri('lockbox://')).toBeNull();
    expect(parseProxyUri('lockbox:///KEY')).toBeNull();
    expect(parseProxyUri('lockbox://service/')).toBeNull();
    expect(parseProxyUri('lockbox://service')).toBeNull();
  });
});

// ─── buildProxyUri ────────────────────────────────────────────────────────────

describe('buildProxyUri', () => {
  it('builds a valid proxy URI', () => {
    expect(buildProxyUri('openai', 'API_KEY')).toBe('lockbox://openai/API_KEY');
  });

  it('round-trips with parseProxyUri', () => {
    const uri = buildProxyUri('stripe', 'SECRET_KEY');
    const parsed = parseProxyUri(uri);
    expect(parsed).toEqual({ service: 'stripe', keyName: 'SECRET_KEY' });
  });
});

// ─── Proxy resolution (integration) ──────────────────────────────────────────

describe('proxy resolution', () => {
  let tempDir: string;
  let vaultPath: string;
  const PASSWORD = 'test-master-password';

  beforeEach(async () => {
    tempDir = makeTempDir();
    vaultPath = join(tempDir, 'vault.enc');

    const vault = await Vault.create(vaultPath, PASSWORD);
    vault.addKey('openai', 'API_KEY', 'sk-real-abc123', { project: 'myapp' });
    vault.addKey('stripe', 'SECRET_KEY', 'sk_live_real_xyz', { project: 'myapp' });
    vault.addKey('aws', 'ACCESS_KEY', 'AKIA_real_key', { project: 'myapp' });
    await vault.save();
    vault.lock();
  });

  afterEach(() => {
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('resolves proxy references and passes through non-proxy values', async () => {
    const envContent = [
      'OPENAI_API_KEY=lockbox://openai/API_KEY',
      'DATABASE_URL=postgresql://localhost/mydb',
      'STRIPE_SECRET_KEY=lockbox://stripe/SECRET_KEY',
      'NODE_ENV=production',
    ].join('\n');

    const entries = parseEnvFile(envContent);
    const vault = await Vault.open(vaultPath, PASSWORD);

    const resolved: Record<string, string> = {};
    for (const { key, value } of entries) {
      const proxy = parseProxyUri(value);
      if (proxy) {
        resolved[key] = vault.getKey(proxy.service, proxy.keyName);
      } else {
        resolved[key] = value;
      }
    }
    vault.lock();

    // Proxy values resolved to real secrets
    expect(resolved['OPENAI_API_KEY']).toBe('sk-real-abc123');
    expect(resolved['STRIPE_SECRET_KEY']).toBe('sk_live_real_xyz');

    // Non-proxy values passed through unchanged
    expect(resolved['DATABASE_URL']).toBe('postgresql://localhost/mydb');
    expect(resolved['NODE_ENV']).toBe('production');
  });

  it('throws for proxy reference to nonexistent vault key', async () => {
    const envContent = 'MY_KEY=lockbox://nonexistent/KEY\n';
    const entries = parseEnvFile(envContent);
    const vault = await Vault.open(vaultPath, PASSWORD);

    const proxy = parseProxyUri(entries[0].value);
    expect(proxy).not.toBeNull();
    expect(() => vault.getKey(proxy!.service, proxy!.keyName)).toThrow('Key not found');
    vault.lock();
  });
});

// ─── proxy-init generation ───────────────────────────────────────────────────

describe('proxy-init generation', () => {
  let tempDir: string;
  let vaultPath: string;
  const PASSWORD = 'test-master-password';

  beforeEach(async () => {
    tempDir = makeTempDir();
    vaultPath = join(tempDir, 'vault.enc');

    const vault = await Vault.create(vaultPath, PASSWORD);
    vault.addKey('openai', 'API_KEY', 'sk-abc123', { project: 'myapp' });
    vault.addKey('stripe', 'SECRET_KEY', 'sk_live_xyz', { project: 'myapp' });
    await vault.save();
    vault.lock();
  });

  afterEach(() => {
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('generates proxy env content with no real secrets', async () => {
    const vault = await Vault.open(vaultPath, PASSWORD);
    const keys = vault.listKeys('myapp');
    vault.lock();

    // Simulate proxy-init generation
    const lines: string[] = [];
    for (const key of keys) {
      const slashIdx = key.name.indexOf('/');
      const service = key.name.slice(0, slashIdx);
      const keyName = key.name.slice(slashIdx + 1);
      lines.push(`${envKeyName(key.name)}=${buildProxyUri(service, keyName)}`);
    }
    const content = lines.join('\n') + '\n';

    // Every value should be a proxy URI
    const parsed = parseEnvFile(content);
    for (const { value } of parsed) {
      expect(value.startsWith(PROXY_PREFIX)).toBe(true);
      expect(parseProxyUri(value)).not.toBeNull();
    }

    // Specific format checks
    expect(content).toContain('OPENAI_API_KEY=lockbox://openai/API_KEY');
    expect(content).toContain('STRIPE_SECRET_KEY=lockbox://stripe/SECRET_KEY');

    // No real secrets in output
    expect(content).not.toContain('sk-abc123');
    expect(content).not.toContain('sk_live_xyz');
  });

  it('round-trip: proxy-init output resolves back to real values', async () => {
    const vault = await Vault.open(vaultPath, PASSWORD);
    const keys = vault.listKeys('myapp');

    // Generate proxy content
    const lines: string[] = [];
    for (const key of keys) {
      const slashIdx = key.name.indexOf('/');
      const service = key.name.slice(0, slashIdx);
      const keyName = key.name.slice(slashIdx + 1);
      lines.push(`${envKeyName(key.name)}=${buildProxyUri(service, keyName)}`);
    }
    const proxyContent = lines.join('\n') + '\n';

    // Resolve proxy content back to real values
    const entries = parseEnvFile(proxyContent);
    const resolved: Record<string, string> = {};
    for (const { key, value } of entries) {
      const proxy = parseProxyUri(value);
      if (proxy) {
        resolved[key] = vault.getKey(proxy.service, proxy.keyName);
      } else {
        resolved[key] = value;
      }
    }
    vault.lock();

    expect(resolved['OPENAI_API_KEY']).toBe('sk-abc123');
    expect(resolved['STRIPE_SECRET_KEY']).toBe('sk_live_xyz');
  });
});

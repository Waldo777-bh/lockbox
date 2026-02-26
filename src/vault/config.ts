/**
 * Lockbox configuration management
 *
 * Handles default paths, config file loading/saving, and directory creation.
 */

import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { LockboxConfig } from '../types/index.js';

/** Base directory for all lockbox data */
const CONFIG_DIR = join(homedir(), '.config', 'lockbox');

/** Default configuration values */
const DEFAULT_CONFIG: LockboxConfig = {
  vaultPath: join(CONFIG_DIR, 'vault.enc'),
  autoLockMinutes: 15,
  defaultProject: 'default',
};

/** Path to the config JSON file */
const CONFIG_FILE = join(CONFIG_DIR, 'config.json');

/** Path to the audit log */
const AUDIT_LOG = join(CONFIG_DIR, 'audit.log');

/**
 * Ensure the lockbox config directory exists.
 * Creates ~/.config/lockbox/ recursively if needed.
 */
export function ensureConfigDir(): void {
  if (!existsSync(CONFIG_DIR)) {
    mkdirSync(CONFIG_DIR, { recursive: true });
  }
}

/**
 * Load configuration from disk, falling back to defaults.
 */
export function loadConfig(): LockboxConfig {
  ensureConfigDir();

  if (!existsSync(CONFIG_FILE)) {
    return { ...DEFAULT_CONFIG };
  }

  try {
    const raw = readFileSync(CONFIG_FILE, 'utf8');
    const stored = JSON.parse(raw) as Partial<LockboxConfig>;
    return { ...DEFAULT_CONFIG, ...stored };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

/**
 * Save configuration to disk.
 */
export function saveConfig(config: LockboxConfig): void {
  ensureConfigDir();
  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), 'utf8');
}

/**
 * Get resolved paths for all lockbox files.
 */
export function getPaths(config?: LockboxConfig) {
  const cfg = config ?? loadConfig();
  return {
    configDir: CONFIG_DIR,
    configFile: CONFIG_FILE,
    vaultFile: cfg.vaultPath,
    auditLog: AUDIT_LOG,
  };
}

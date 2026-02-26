/**
 * Session management — persist the derived key between CLI invocations
 *
 * On `lockbox unlock`:
 *   1. Derive vault key from password (slow Argon2id)
 *   2. Derive a session key from machine environment (fast HMAC)
 *   3. Encrypt the vault key with the session key
 *   4. Write to temp file with timestamp
 *
 * On subsequent commands (add, get, list, etc.):
 *   1. Read temp file, check 15-minute expiry
 *   2. Re-derive session key from environment
 *   3. Decrypt vault key
 *   4. Use vault key to open vault (no password prompt needed)
 *
 * Rate limiting:
 *   Track failed unlock attempts in ~/.config/lockbox/rate-limit.json.
 *   Max 5 failures per 60 seconds; after that, lock out for 60 seconds.
 */

import { readFileSync, writeFileSync, unlinkSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir, hostname, userInfo, homedir } from 'node:os';
import { createHmac, randomBytes } from 'node:crypto';
import { encrypt, decrypt } from '../crypto/encryption.js';
import { ensureConfigDir } from '../vault/config.js';

// ─── Paths ───────────────────────────────────────────────────────────────────

const SESSION_FILE = join(tmpdir(), 'lockbox-session');
const RATE_LIMIT_FILE = join(homedir(), '.config', 'lockbox', 'rate-limit.json');

// ─── Constants ───────────────────────────────────────────────────────────────

const SESSION_TIMEOUT_MS = 15 * 60 * 1000;   // 15 minutes
const MAX_ATTEMPTS = 5;
const RATE_WINDOW_MS = 60 * 1000;             // 60 seconds
const LOCKOUT_MS = 60 * 1000;                 // 60-second lockout after max failures

// ─── Session key derivation ──────────────────────────────────────────────────

/**
 * Derive a deterministic 32-byte session key from the current machine
 * environment. Same user + same machine = same key every time.
 */
function deriveSessionKey(): Buffer {
  return createHmac('sha256', 'lockbox-session-key')
    .update(hostname())
    .update(userInfo().username)
    .update(homedir())
    .digest();
}

// ─── Session types ───────────────────────────────────────────────────────────

interface SessionFile {
  encryptedKey: string;   // base64 — vault derived key, encrypted with session key
  iv: string;             // base64
  tag: string;            // base64
  vaultPath: string;
  timestamp: number;      // Date.now() when session was created
}

interface RateLimitFile {
  failedAttempts: number[];  // timestamps of recent failures
  lockedUntil: number | null;
}

// ─── Session operations ──────────────────────────────────────────────────────

/**
 * Save an unlock session — encrypts the vault derived key to a temp file.
 */
export function saveSession(derivedKey: Buffer, vaultPath: string): void {
  const sessionKey = deriveSessionKey();
  const { ciphertext, iv, tag } = encrypt(derivedKey.toString('base64'), sessionKey);

  const session: SessionFile = {
    encryptedKey: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    vaultPath,
    timestamp: Date.now(),
  };

  writeFileSync(SESSION_FILE, JSON.stringify(session), 'utf8');
}

/**
 * Load a valid session. Returns null if no session, expired, or corrupt.
 */
export function loadSession(): { key: Buffer; vaultPath: string } | null {
  if (!existsSync(SESSION_FILE)) return null;

  try {
    const raw = readFileSync(SESSION_FILE, 'utf8');
    const session: SessionFile = JSON.parse(raw);

    // Check expiry
    if (Date.now() - session.timestamp > SESSION_TIMEOUT_MS) {
      clearSession();
      return null;
    }

    // Decrypt vault key
    const sessionKey = deriveSessionKey();
    const ciphertext = Buffer.from(session.encryptedKey, 'base64');
    const iv = Buffer.from(session.iv, 'base64');
    const tag = Buffer.from(session.tag, 'base64');

    const keyB64 = decrypt(ciphertext, sessionKey, iv, tag);
    const key = Buffer.from(keyB64, 'base64');

    return { key, vaultPath: session.vaultPath };
  } catch {
    // Corrupt or unreadable — treat as no session
    clearSession();
    return null;
  }
}

/**
 * Clear the session (lock).
 */
export function clearSession(): void {
  try {
    if (existsSync(SESSION_FILE)) {
      unlinkSync(SESSION_FILE);
    }
  } catch {
    // Ignore — file may already be gone
  }
}

/**
 * Check remaining session time in seconds, or null if no session.
 */
export function sessionTimeRemaining(): number | null {
  if (!existsSync(SESSION_FILE)) return null;

  try {
    const raw = readFileSync(SESSION_FILE, 'utf8');
    const session: SessionFile = JSON.parse(raw);
    const elapsed = Date.now() - session.timestamp;
    const remaining = SESSION_TIMEOUT_MS - elapsed;
    return remaining > 0 ? Math.ceil(remaining / 1000) : null;
  } catch {
    return null;
  }
}

// ─── Rate limiting ───────────────────────────────────────────────────────────

function loadRateLimit(): RateLimitFile {
  if (!existsSync(RATE_LIMIT_FILE)) {
    return { failedAttempts: [], lockedUntil: null };
  }
  try {
    const raw = readFileSync(RATE_LIMIT_FILE, 'utf8');
    return JSON.parse(raw) as RateLimitFile;
  } catch {
    return { failedAttempts: [], lockedUntil: null };
  }
}

function saveRateLimit(data: RateLimitFile): void {
  ensureConfigDir();
  writeFileSync(RATE_LIMIT_FILE, JSON.stringify(data), 'utf8');
}

/**
 * Check whether an unlock attempt is allowed.
 * @throws if rate-limited (with a message including wait time)
 */
export function checkRateLimit(): void {
  const data = loadRateLimit();
  const now = Date.now();

  // Check hard lockout
  if (data.lockedUntil && now < data.lockedUntil) {
    const wait = Math.ceil((data.lockedUntil - now) / 1000);
    throw new Error(`Too many failed attempts. Try again in ${wait} seconds.`);
  }

  // Clear expired lockout
  if (data.lockedUntil && now >= data.lockedUntil) {
    data.lockedUntil = null;
  }

  // Count recent failures within window
  const recent = data.failedAttempts.filter((t) => now - t < RATE_WINDOW_MS);
  if (recent.length >= MAX_ATTEMPTS) {
    data.lockedUntil = now + LOCKOUT_MS;
    data.failedAttempts = recent;
    saveRateLimit(data);
    throw new Error(`Too many failed attempts. Try again in 60 seconds.`);
  }
}

/**
 * Record a failed unlock attempt.
 */
export function recordFailedAttempt(): void {
  const data = loadRateLimit();
  const now = Date.now();
  // Keep only recent attempts
  data.failedAttempts = data.failedAttempts.filter((t) => now - t < RATE_WINDOW_MS);
  data.failedAttempts.push(now);

  if (data.failedAttempts.length >= MAX_ATTEMPTS) {
    data.lockedUntil = now + LOCKOUT_MS;
  }

  saveRateLimit(data);
}

/**
 * Clear rate limit on successful unlock.
 */
export function clearRateLimit(): void {
  if (existsSync(RATE_LIMIT_FILE)) {
    try { unlinkSync(RATE_LIMIT_FILE); } catch { /* ignore */ }
  }
}

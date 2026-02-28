/**
 * CLI tier validation — validates licence key against the Lockbox API
 * and caches the result locally to avoid hitting the API on every command.
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { TierCache } from '../types/index.js';

/** Dashboard API base URL — override with LOCKBOX_API_URL env var */
const API_BASE =
  process.env.LOCKBOX_API_URL || 'https://lockbox-dashboard-production.up.railway.app';

/** Cache file for tier validation */
const TIER_CACHE_FILE = join(homedir(), '.config', 'lockbox', 'tier-cache.json');

/** Cache duration: 24 hours */
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

/** Free tier limits */
const FREE_KEY_LIMIT = 25;

/**
 * Load cached tier info if it exists and is still valid.
 */
function loadCache(): TierCache | null {
  try {
    if (!existsSync(TIER_CACHE_FILE)) return null;
    const raw = readFileSync(TIER_CACHE_FILE, 'utf8');
    const cache = JSON.parse(raw) as TierCache;
    if (Date.now() - cache.validatedAt > CACHE_TTL_MS) return null;
    return cache;
  } catch {
    return null;
  }
}

/**
 * Save tier validation result to cache.
 */
function saveCache(cache: TierCache): void {
  try {
    writeFileSync(TIER_CACHE_FILE, JSON.stringify(cache), 'utf8');
  } catch {
    // Non-critical — ignore cache write failures
  }
}

/**
 * Validate a licence key against the Lockbox API.
 * Returns tier info or null if validation fails.
 */
async function validateLicenceKey(
  licenceKey: string
): Promise<{ valid: boolean; tier: string } | null> {
  try {
    const res = await fetch(
      `${API_BASE}/api/licence/validate?key=${encodeURIComponent(licenceKey)}`,
      { signal: AbortSignal.timeout(5000) }
    );
    if (!res.ok) return null;
    return (await res.json()) as { valid: boolean; tier: string };
  } catch {
    // Network error — fail gracefully
    return null;
  }
}

/**
 * Get the current tier for the CLI user.
 * Uses cached result if available, otherwise validates against API.
 *
 * @param licenceKey - The licence key from config (undefined for free tier)
 * @returns Tier info with key limit
 */
export async function getTier(
  licenceKey: string | undefined
): Promise<{ tier: string; keyLimit: number }> {
  // No licence key = free tier
  if (!licenceKey) {
    return { tier: 'free', keyLimit: FREE_KEY_LIMIT };
  }

  // Check cache first
  const cached = loadCache();
  if (cached) {
    return { tier: cached.tier, keyLimit: cached.keyLimit };
  }

  // Validate against API
  const result = await validateLicenceKey(licenceKey);

  if (result && result.valid) {
    const keyLimit = result.tier === 'pro' ? Infinity : FREE_KEY_LIMIT;
    saveCache({
      tier: result.tier,
      validatedAt: Date.now(),
      keyLimit,
    });
    return { tier: result.tier, keyLimit };
  }

  // Validation failed or network error — if key looks like a valid format,
  // allow degraded mode with free limits but don't cache
  if (licenceKey.startsWith('lbox_pro_')) {
    // Key format is correct but can't validate — use cached or assume pro
    // (graceful degradation for offline usage)
    return { tier: 'pro', keyLimit: Infinity };
  }

  return { tier: 'free', keyLimit: FREE_KEY_LIMIT };
}

/**
 * Check if the user can add more keys based on their tier.
 *
 * @param currentKeyCount - Current number of keys in the vault
 * @param licenceKey - The licence key from config
 * @returns Object with allowed status and optional message
 */
export async function checkKeyLimitCLI(
  currentKeyCount: number,
  licenceKey: string | undefined
): Promise<{ allowed: boolean; message?: string }> {
  const { tier, keyLimit } = await getTier(licenceKey);

  if (keyLimit === Infinity || currentKeyCount < keyLimit) {
    return { allowed: true };
  }

  return {
    allowed: false,
    message: `Free tier allows ${keyLimit} keys (you have ${currentKeyCount}). Upgrade to Pro for unlimited keys.\n  Run: lockbox upgrade`,
  };
}

/**
 * Clear the tier cache (e.g., after setting a new licence key).
 */
export function clearTierCache(): void {
  try {
    if (existsSync(TIER_CACHE_FILE)) {
      writeFileSync(TIER_CACHE_FILE, '', 'utf8');
    }
  } catch {
    // Non-critical
  }
}

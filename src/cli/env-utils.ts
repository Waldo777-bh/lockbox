/**
 * Shared .env parsing, key-name conversion, and proxy URI utilities
 */

/** Proxy URI prefix */
export const PROXY_PREFIX = 'lockbox://';

/**
 * Convert a vault key name (e.g. "openai/API_KEY") to an env-style name.
 * "openai/API_KEY" → "OPENAI_API_KEY"
 */
export function envKeyName(name: string): string {
  return name.replace(/\//g, '_').toUpperCase();
}

/**
 * Split a key name into [service, keyName].
 * If no "/" present, defaults to service "imported".
 */
export function splitKeyName(key: string): [string, string] {
  if (key.includes('/')) {
    const idx = key.indexOf('/');
    return [key.slice(0, idx), key.slice(idx + 1)];
  }
  // Best guess: split on first underscore for service (e.g. OPENAI_API_KEY → openai, API_KEY)
  const parts = key.split('_');
  if (parts.length >= 2) {
    return [parts[0].toLowerCase(), parts.slice(1).join('_')];
  }
  return ['imported', key];
}

/**
 * Parse a .env file into key-value pairs.
 * Supports: KEY=value, KEY="value", KEY='value'
 * Skips blank lines and # comments.
 */
export function parseEnvFile(raw: string): { key: string; value: string }[] {
  const entries: { key: string; value: string }[] = [];

  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith('#')) continue;
    // Skip lines without '='
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;

    const key = trimmed.slice(0, eqIdx).trim();
    let value = trimmed.slice(eqIdx + 1).trim();

    // Strip surrounding quotes
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

/**
 * Parse a JSON file into key-value pairs.
 * Expects a flat { "KEY": "value" } object.
 */
export function parseJsonImport(raw: string): { key: string; value: string }[] {
  const obj = JSON.parse(raw);
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
    throw new Error('JSON import expects a flat { "KEY": "value" } object');
  }

  return Object.entries(obj).map(([key, value]) => ({
    key,
    value: String(value),
  }));
}

/**
 * Parse a lockbox proxy URI: "lockbox://service/KEY_NAME"
 * Returns { service, keyName } or null if the value is not a proxy URI.
 */
export function parseProxyUri(value: string): { service: string; keyName: string } | null {
  if (!value.startsWith(PROXY_PREFIX)) {
    return null;
  }

  const path = value.slice(PROXY_PREFIX.length);
  const slashIdx = path.indexOf('/');

  if (slashIdx === -1 || slashIdx === 0 || slashIdx === path.length - 1) {
    return null; // malformed: "lockbox://", "lockbox:///KEY", "lockbox://service/"
  }

  return {
    service: path.slice(0, slashIdx),
    keyName: path.slice(slashIdx + 1),
  };
}

/**
 * Build a proxy URI from service and key name.
 * "openai", "API_KEY" → "lockbox://openai/API_KEY"
 */
export function buildProxyUri(service: string, keyName: string): string {
  return `${PROXY_PREFIX}${service}/${keyName}`;
}

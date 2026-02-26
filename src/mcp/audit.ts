/**
 * Audit logging — append-only log of every vault operation
 *
 * Format: ISO timestamp | source | operation | parameters (never secret values)
 * Stored at: ~/.config/lockbox/audit.log
 */

import { appendFileSync, readFileSync, existsSync } from 'node:fs';
import { getPaths, ensureConfigDir } from '../vault/config.js';

/** Where the operation originated */
export type AuditSource = 'cli' | 'mcp';

/**
 * Log a vault operation to the audit log.
 *
 * @param operation - Operation name (e.g. "add", "get", "store_secret")
 * @param params    - Parameters to log (secret values must be redacted by caller)
 * @param source    - Where the operation originated: "cli" or "mcp"
 */
export function auditLog(
  operation: string,
  params: Record<string, unknown>,
  source: AuditSource = 'mcp',
): void {
  try {
    ensureConfigDir();
    const { auditLog: logPath } = getPaths();
    const timestamp = new Date().toISOString();
    const paramStr = JSON.stringify(params);
    const line = `${timestamp} | ${source} | ${operation} | ${paramStr}\n`;
    appendFileSync(logPath, line, 'utf8');
  } catch {
    // Audit logging is best-effort — never crash the server
  }
}

/** A parsed audit log entry */
export interface AuditEntry {
  timestamp: string;
  source: string;
  operation: string;
  params: string;
}

/**
 * Read and parse audit log entries.
 *
 * @param since - Optional ISO date string; only return entries after this time
 * @param limit - Maximum entries to return (from the end of the log)
 */
export function readAuditLog(since?: string, limit = 50): AuditEntry[] {
  const { auditLog: logPath } = getPaths();

  if (!existsSync(logPath)) {
    return [];
  }

  const raw = readFileSync(logPath, 'utf8');
  const lines = raw.trim().split('\n').filter(Boolean);

  let entries: AuditEntry[] = lines.map((line) => {
    const parts = line.split(' | ');
    // Handle both old format (3 parts) and new format (4 parts)
    if (parts.length === 4) {
      return {
        timestamp: parts[0],
        source: parts[1],
        operation: parts[2],
        params: parts[3],
      };
    }
    // Legacy 3-part format: timestamp | operation | params
    return {
      timestamp: parts[0],
      source: 'mcp',
      operation: parts[1] ?? '',
      params: parts[2] ?? '{}',
    };
  });

  // Filter by --since
  if (since) {
    const sinceDate = new Date(since).getTime();
    entries = entries.filter((e) => new Date(e.timestamp).getTime() >= sinceDate);
  }

  // Return only the last N entries
  return entries.slice(-limit);
}

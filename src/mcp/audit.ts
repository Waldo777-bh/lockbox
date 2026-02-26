/**
 * Audit logging — append-only log of every MCP tool call
 *
 * Format: ISO timestamp | tool name | parameters (never secret values)
 * Stored at: ~/.config/lockbox/audit.log
 */

import { appendFileSync } from 'node:fs';
import { getPaths, ensureConfigDir } from '../vault/config.js';

/**
 * Log an MCP tool call to the audit log.
 *
 * @param tool   - Tool name (e.g. "store_secret")
 * @param params - Parameters to log (secret values must be redacted by caller)
 */
export function auditLog(tool: string, params: Record<string, unknown>): void {
  try {
    ensureConfigDir();
    const { auditLog: logPath } = getPaths();
    const timestamp = new Date().toISOString();
    const paramStr = JSON.stringify(params);
    const line = `${timestamp} | ${tool} | ${paramStr}\n`;
    appendFileSync(logPath, line, 'utf8');
  } catch {
    // Audit logging is best-effort — never crash the server
  }
}

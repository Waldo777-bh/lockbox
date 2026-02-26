#!/usr/bin/env node

/**
 * Lockbox MCP Server
 *
 * Exposes the encrypted vault to AI coding agents via the Model Context Protocol.
 * Runs over stdio transport — launched as:  npx lockbox-mcp
 *
 * Tools:
 *   store_secret   — add a key to the vault
 *   get_secret     — retrieve a decrypted value
 *   list_secrets   — list keys (never values)
 *   delete_secret  — remove a key
 *   export_env     — export a project's keys as .env string
 *   list_projects  — list all project names
 *
 * Security:
 *   - Reads from the same vault + session as the CLI
 *   - If vault is locked, every tool returns an error
 *   - Every tool call is audit-logged (secret values are NEVER logged)
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod/v4';
import { Vault } from '../vault/vault.js';
import { loadSession } from '../cli/session.js';
import { auditLog } from './audit.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

const LOCKED_ERROR = "Vault is locked. Run 'lockbox unlock' in your terminal first.";

/**
 * Load the vault from the current CLI session.
 * Throws a user-friendly error if the vault is locked.
 */
function getVault(): Vault {
  const session = loadSession();
  if (!session) {
    throw new Error(LOCKED_ERROR);
  }
  return Vault.openWithKey(session.vaultPath, session.key);
}

/**
 * Create an MCP tool result (text content).
 */
function toolResult(text: string, isError = false) {
  return {
    content: [{ type: 'text' as const, text }],
    isError,
  };
}

// ─── Server setup ────────────────────────────────────────────────────────────

const server = new McpServer({
  name: 'lockbox',
  version: '1.0.0',
});

// ─── Tool: store_secret ──────────────────────────────────────────────────────

server.tool(
  'store_secret',
  'Store an API key or secret in the encrypted vault',
  {
    service: z.string().describe('Service name (e.g. "openai", "stripe")'),
    key_name: z.string().describe('Key identifier (e.g. "API_KEY")'),
    value: z.string().describe('The secret value to store'),
    project: z.string().optional().describe('Project name (default: "default")'),
  },
  async ({ service, key_name, value, project }) => {
    auditLog('store_secret', { service, key_name, project: project ?? 'default' });

    try {
      const vault = getVault();
      vault.addKey(service, key_name, value, { project: project ?? 'default' });
      await vault.save();
      vault.lock();

      return toolResult(JSON.stringify({
        success: true,
        message: `Stored ${service}/${key_name}`,
      }));
    } catch (err) {
      return toolResult((err as Error).message, true);
    }
  },
);

// ─── Tool: get_secret ────────────────────────────────────────────────────────

server.tool(
  'get_secret',
  'Retrieve a decrypted secret from the vault',
  {
    service: z.string().describe('Service name'),
    key_name: z.string().describe('Key identifier'),
  },
  async ({ service, key_name }) => {
    auditLog('get_secret', { service, key_name });

    try {
      const vault = getVault();
      const value = vault.getKey(service, key_name);
      vault.lock();

      return toolResult(JSON.stringify({ value }));
    } catch (err) {
      return toolResult((err as Error).message, true);
    }
  },
);

// ─── Tool: list_secrets ──────────────────────────────────────────────────────

server.tool(
  'list_secrets',
  'List all stored keys (names and metadata — never values)',
  {
    project: z.string().optional().describe('Filter by project name'),
  },
  async ({ project }) => {
    auditLog('list_secrets', { project: project ?? 'all' });

    try {
      const vault = getVault();
      const keys = vault.listKeys(project);
      vault.lock();

      const result = keys.map((k) => {
        const [service, ...rest] = k.name.split('/');
        return {
          service,
          key_name: rest.join('/'),
          project: k.project,
          has_expiry: k.expiresAt !== null,
        };
      });

      return toolResult(JSON.stringify(result));
    } catch (err) {
      return toolResult((err as Error).message, true);
    }
  },
);

// ─── Tool: delete_secret ─────────────────────────────────────────────────────

server.tool(
  'delete_secret',
  'Delete a secret from the vault',
  {
    service: z.string().describe('Service name'),
    key_name: z.string().describe('Key identifier'),
  },
  async ({ service, key_name }) => {
    auditLog('delete_secret', { service, key_name });

    try {
      const vault = getVault();
      const removed = vault.removeKey(service, key_name);

      if (!removed) {
        vault.lock();
        return toolResult(JSON.stringify({
          success: false,
          message: `Key not found: ${service}/${key_name}`,
        }), true);
      }

      await vault.save();
      vault.lock();

      return toolResult(JSON.stringify({
        success: true,
        message: `Deleted ${service}/${key_name}`,
      }));
    } catch (err) {
      return toolResult((err as Error).message, true);
    }
  },
);

// ─── Tool: export_env ────────────────────────────────────────────────────────

server.tool(
  'export_env',
  'Export all keys for a project as a .env formatted string',
  {
    project: z.string().describe('Project name to export'),
  },
  async ({ project }) => {
    auditLog('export_env', { project });

    try {
      const vault = getVault();
      const pairs = vault.exportKeys(project);
      vault.lock();

      if (pairs.length === 0) {
        return toolResult(`No keys found for project "${project}"`, true);
      }

      const envStr = pairs
        .map(({ name, value }) => {
          const envName = name.replace(/\//g, '_').toUpperCase();
          return `${envName}=${value}`;
        })
        .join('\n');

      return toolResult(envStr);
    } catch (err) {
      return toolResult((err as Error).message, true);
    }
  },
);

// ─── Tool: list_projects ─────────────────────────────────────────────────────

server.tool(
  'list_projects',
  'List all project names in the vault',
  {},
  async () => {
    auditLog('list_projects', {});

    try {
      const vault = getVault();
      const projects = vault.listProjects();
      vault.lock();

      return toolResult(JSON.stringify(projects));
    } catch (err) {
      return toolResult((err as Error).message, true);
    }
  },
);

// ─── Start ───────────────────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  process.stderr.write(`Lockbox MCP server error: ${(err as Error).message}\n`);
  process.exit(1);
});

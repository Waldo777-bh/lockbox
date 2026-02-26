/**
 * CLI command registration — wires up all lockbox commands
 */

import { existsSync, statSync, readFileSync } from 'node:fs';
import { extname } from 'node:path';
import type { Command } from 'commander';
import ora from 'ora';
import { Vault } from '../vault/vault.js';
import { loadConfig, getPaths } from '../vault/config.js';
import {
  saveSession,
  loadSession,
  clearSession,
  sessionTimeRemaining,
  checkRateLimit,
  recordFailedAttempt,
  clearRateLimit,
} from './session.js';
import {
  promptPassword,
  promptPasswordWithConfirm,
  promptConfirm,
  promptChoice,
  copyAndScheduleClear,
  formatTable,
  shortDate,
  exitWithError,
  chalk,
} from './helpers.js';

// ─── Helper: load vault from active session ──────────────────────────────────

function loadVaultFromSession(): Vault {
  const session = loadSession();
  if (!session) {
    throw new Error('Vault is locked. Run `lockbox unlock` first.');
  }
  return Vault.openWithKey(session.vaultPath, session.key);
}

// ─── Commands ────────────────────────────────────────────────────────────────

export function registerCommands(program: Command): void {
  // ── init ─────────────────────────────────────────────────────────────────
  program
    .command('init')
    .description('Create a new encrypted vault')
    .action(async () => {
      try {
        const config = loadConfig();
        const { vaultFile } = getPaths(config);

        // Check for existing vault
        if (existsSync(vaultFile)) {
          const overwrite = await promptConfirm(
            chalk.yellow('A vault already exists. Overwrite it?')
          );
          if (!overwrite) {
            process.stderr.write(chalk.dim('Aborted.\n'));
            return;
          }
        }

        // Get master password
        const password = await promptPasswordWithConfirm();

        const spinner = ora('Creating encrypted vault...').start();
        const vault = await Vault.create(vaultFile, password);

        // Auto-unlock after init
        saveSession(vault.getDerivedKey(), vaultFile);
        vault.lock();
        spinner.succeed('Vault created and unlocked!');

        process.stderr.write(chalk.dim(`  Location: ${vaultFile}\n`));
        process.stderr.write(chalk.dim(`  Auto-locks in 15 minutes.\n`));
      } catch (err) {
        exitWithError((err as Error).message);
      }
    });

  // ── unlock ───────────────────────────────────────────────────────────────
  program
    .command('unlock')
    .description('Unlock the vault with your master password')
    .action(async () => {
      try {
        const config = loadConfig();
        const { vaultFile } = getPaths(config);

        if (!existsSync(vaultFile)) {
          throw new Error('No vault found. Run `lockbox init` first.');
        }

        // Check rate limit
        checkRateLimit();

        const password = await promptPassword(chalk.cyan('Master password: '));

        const spinner = ora('Deriving encryption key...').start();
        let vault: Vault;
        try {
          vault = await Vault.open(vaultFile, password);
        } catch (err) {
          spinner.fail('Unlock failed.');
          recordFailedAttempt();
          throw err;
        }

        // Success — save session and clear rate limit
        saveSession(vault.getDerivedKey(), vaultFile);
        clearRateLimit();
        vault.lock();

        spinner.succeed('Vault unlocked!');
        process.stderr.write(chalk.dim('  Auto-locks in 15 minutes.\n'));
      } catch (err) {
        exitWithError((err as Error).message);
      }
    });

  // ── lock ─────────────────────────────────────────────────────────────────
  program
    .command('lock')
    .description('Lock the vault and clear session')
    .action(() => {
      try {
        clearSession();
        process.stderr.write(chalk.green('✓ Vault locked.\n'));
      } catch (err) {
        exitWithError((err as Error).message);
      }
    });

  // ── add ──────────────────────────────────────────────────────────────────
  program
    .command('add')
    .description('Add a secret to the vault')
    .argument('<service>', 'Service name (e.g. openai)')
    .argument('<key-name>', 'Key identifier (e.g. API_KEY)')
    .argument('[value]', 'Secret value (prompted if omitted)')
    .option('-p, --project <name>', 'Project name', 'default')
    .option('-n, --notes <text>', 'Notes about this key', '')
    .option('--expires <date>', 'Expiration date (ISO format)')
    .action(async (service: string, keyName: string, value: string | undefined, opts) => {
      try {
        const vault = loadVaultFromSession();

        // If no value provided, prompt for it (hidden)
        if (!value) {
          value = await promptPassword(chalk.cyan('Secret value: '));
          if (!value) throw new Error('Value cannot be empty');
        }

        vault.addKey(service, keyName, value, {
          project: opts.project,
          notes: opts.notes,
          expiresAt: opts.expires ?? null,
        });
        await vault.save();
        vault.lock();

        process.stderr.write(
          chalk.green(`✓ Added ${service}/${keyName} to vault\n`)
        );
      } catch (err) {
        exitWithError((err as Error).message);
      }
    });

  // ── get ──────────────────────────────────────────────────────────────────
  program
    .command('get')
    .description('Retrieve a secret from the vault')
    .argument('<service>', 'Service name')
    .argument('<key-name>', 'Key identifier')
    .option('-c, --copy', 'Copy to clipboard (auto-clears after 30s)')
    .action(async (service: string, keyName: string, opts) => {
      try {
        const vault = loadVaultFromSession();
        const value = vault.getKey(service, keyName);
        vault.lock();

        if (opts.copy) {
          await copyAndScheduleClear(value, 30);
        } else {
          // Output plain value to stdout (for piping)
          process.stdout.write(value);
          // Add newline only if stdout is a terminal
          if (process.stdout.isTTY) {
            process.stdout.write('\n');
          }
        }
      } catch (err) {
        exitWithError((err as Error).message);
      }
    });

  // ── list ─────────────────────────────────────────────────────────────────
  program
    .command('list')
    .description('List all stored keys (names only, never values)')
    .option('-p, --project <name>', 'Filter by project name')
    .action((opts) => {
      try {
        const vault = loadVaultFromSession();
        const keys = vault.listKeys(opts.project);
        vault.lock();

        if (keys.length === 0) {
          process.stderr.write(
            chalk.dim(opts.project
              ? `No keys found in project "${opts.project}".\n`
              : 'Vault is empty. Add keys with `lockbox add`.\n')
          );
          return;
        }

        const rows = keys.map((k) => {
          const [service, ...rest] = k.name.split('/');
          return [service, rest.join('/'), k.project, shortDate(k.createdAt), shortDate(k.expiresAt)];
        });

        process.stderr.write(
          formatTable(['Service', 'Key Name', 'Project', 'Added', 'Expires'], rows) + '\n'
        );
        process.stderr.write(chalk.dim(`\n${keys.length} key(s) total\n`));
      } catch (err) {
        exitWithError((err as Error).message);
      }
    });

  // ── remove ───────────────────────────────────────────────────────────────
  program
    .command('remove')
    .description('Remove a secret from the vault')
    .argument('<service>', 'Service name')
    .argument('<key-name>', 'Key identifier')
    .option('-f, --force', 'Skip confirmation')
    .action(async (service: string, keyName: string, opts) => {
      try {
        const vault = loadVaultFromSession();
        const fullKey = `${service}/${keyName}`;

        // Confirm deletion unless --force
        if (!opts.force) {
          const confirmed = await promptConfirm(
            chalk.yellow(`Remove ${fullKey}?`)
          );
          if (!confirmed) {
            vault.lock();
            process.stderr.write(chalk.dim('Aborted.\n'));
            return;
          }
        }

        const removed = vault.removeKey(service, keyName);
        if (!removed) {
          vault.lock();
          throw new Error(`Key not found: ${fullKey}`);
        }

        await vault.save();
        vault.lock();

        process.stderr.write(chalk.green(`✓ Removed ${fullKey}\n`));
      } catch (err) {
        exitWithError((err as Error).message);
      }
    });

  // ── search ───────────────────────────────────────────────────────────────
  program
    .command('search')
    .description('Search keys by name, service, project, or notes')
    .argument('<query>', 'Search term')
    .action((query: string) => {
      try {
        const vault = loadVaultFromSession();
        const allKeys = vault.listKeys();
        vault.lock();

        const q = query.toLowerCase();
        const matches = allKeys.filter((k) => {
          const searchable = [k.name, k.project, k.notes].join(' ').toLowerCase();
          return searchable.includes(q);
        });

        if (matches.length === 0) {
          process.stderr.write(chalk.dim(`No keys matching "${query}".\n`));
          return;
        }

        const rows = matches.map((k) => {
          const [service, ...rest] = k.name.split('/');
          return [service, rest.join('/'), k.project, k.notes || '—'];
        });

        process.stderr.write(
          formatTable(['Service', 'Key Name', 'Project', 'Notes'], rows) + '\n'
        );
        process.stderr.write(chalk.dim(`\n${matches.length} result(s)\n`));
      } catch (err) {
        exitWithError((err as Error).message);
      }
    });

  // ── status ───────────────────────────────────────────────────────────────
  program
    .command('status')
    .description('Show vault status')
    .action(() => {
      try {
        const config = loadConfig();
        const { vaultFile } = getPaths(config);

        process.stderr.write(chalk.bold('Lockbox Status\n\n'));

        // Vault path
        process.stderr.write(`  Vault:     ${vaultFile}\n`);

        // File exists?
        if (!existsSync(vaultFile)) {
          process.stderr.write(chalk.yellow('  Status:    No vault found. Run `lockbox init`.\n'));
          return;
        }

        // File size
        const stats = statSync(vaultFile);
        const sizeKB = (stats.size / 1024).toFixed(1);
        process.stderr.write(`  Size:      ${sizeKB} KB\n`);

        // Lock state
        const session = loadSession();
        if (session) {
          const remaining = sessionTimeRemaining();
          const mins = remaining ? Math.floor(remaining / 60) : 0;
          const secs = remaining ? remaining % 60 : 0;
          process.stderr.write(
            chalk.green(`  Status:    Unlocked`) +
              chalk.dim(` (auto-locks in ${mins}m ${secs}s)\n`)
          );

          // Key count and project count
          try {
            const vault = Vault.openWithKey(session.vaultPath, session.key);
            const keys = vault.listKeys();
            const projects = vault.listProjects();
            vault.lock();

            process.stderr.write(`  Keys:      ${keys.length}\n`);
            process.stderr.write(`  Projects:  ${projects.length}\n`);
          } catch {
            // Session may be stale
            process.stderr.write(chalk.dim('  (Could not read vault details)\n'));
          }
        } else {
          process.stderr.write(chalk.red('  Status:    Locked\n'));
        }
      } catch (err) {
        exitWithError((err as Error).message);
      }
    });

  // ── export ─────────────────────────────────────────────────────────────
  program
    .command('export')
    .description('Export keys to stdout (env, json, or shell format)')
    .option('-p, --project <name>', 'Only export keys from this project')
    .option('-f, --format <format>', 'Output format: env, json, shell', 'env')
    .action((opts) => {
      try {
        const vault = loadVaultFromSession();
        const pairs = vault.exportKeys(opts.project);
        vault.lock();

        if (pairs.length === 0) {
          process.stderr.write(
            chalk.dim(opts.project
              ? `No keys found in project "${opts.project}".\n`
              : 'Vault is empty.\n')
          );
          return;
        }

        const format: string = opts.format;
        let output: string;

        switch (format) {
          case 'json': {
            const obj: Record<string, string> = {};
            for (const { name, value } of pairs) {
              // Use the full "service/KEY_NAME" as the JSON key
              obj[name] = value;
            }
            output = JSON.stringify(obj, null, 2) + '\n';
            break;
          }

          case 'shell': {
            output = pairs
              .map(({ name, value }) => {
                // Escape double quotes and backslashes inside the value
                const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
                return `export ${envKeyName(name)}="${escaped}"`;
              })
              .join('\n') + '\n';
            break;
          }

          case 'env':
          default: {
            output = pairs
              .map(({ name, value }) => `${envKeyName(name)}=${value}`)
              .join('\n') + '\n';
            break;
          }
        }

        // Write to stdout so users can pipe: lockbox export > .env
        process.stdout.write(output);
        process.stderr.write(chalk.dim(`Exported ${pairs.length} key(s) in ${format} format.\n`));
      } catch (err) {
        exitWithError((err as Error).message);
      }
    });

  // ── import ─────────────────────────────────────────────────────────────
  program
    .command('import')
    .description('Import keys from a .env or JSON file')
    .argument('<file>', 'Path to .env or .json file')
    .option('-p, --project <name>', 'Assign imported keys to this project', 'default')
    .action(async (file: string, opts) => {
      try {
        if (!existsSync(file)) {
          throw new Error(`File not found: ${file}`);
        }

        const vault = loadVaultFromSession();
        const raw = readFileSync(file, 'utf8');
        const ext = extname(file).toLowerCase();

        // Parse the file
        let entries: { key: string; value: string }[];
        if (ext === '.json') {
          entries = parseJsonImport(raw);
        } else {
          entries = parseEnvImport(raw);
        }

        if (entries.length === 0) {
          vault.lock();
          process.stderr.write(chalk.dim('No keys found in file.\n'));
          return;
        }

        let imported = 0;
        let skipped = 0;

        for (const { key, value } of entries) {
          // Determine service/keyName — if key contains '/', use as-is; else use 'imported/KEY'
          const [service, keyName] = splitKeyName(key);

          if (vault.hasKey(service, keyName)) {
            // Key already exists — ask user
            const choice = await promptChoice(
              chalk.yellow(`Key ${service}/${keyName} already exists`),
              [
                { key: 'o', label: 'Overwrite' },
                { key: 's', label: 'Skip' },
              ],
            );

            if (choice === 's') {
              skipped++;
              continue;
            }
          }

          vault.addKey(service, keyName, value, { project: opts.project });
          imported++;
        }

        await vault.save();
        vault.lock();

        process.stderr.write(
          chalk.green(`✓ Imported ${imported} key(s) into project '${opts.project}'`)
          + (skipped > 0 ? chalk.dim(` (${skipped} skipped)`) : '')
          + '\n'
        );
      } catch (err) {
        exitWithError((err as Error).message);
      }
    });
}

// ─── Import/Export helpers ────────────────────────────────────────────────────

/**
 * Convert a vault key name (e.g. "openai/API_KEY") to an env-style name.
 * "openai/API_KEY" → "OPENAI_API_KEY"
 */
function envKeyName(name: string): string {
  return name.replace(/\//g, '_').toUpperCase();
}

/**
 * Split a key name into [service, keyName].
 * If no "/" present, defaults to service "imported".
 */
function splitKeyName(key: string): [string, string] {
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
function parseEnvImport(raw: string): { key: string; value: string }[] {
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
function parseJsonImport(raw: string): { key: string; value: string }[] {
  const obj = JSON.parse(raw);
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
    throw new Error('JSON import expects a flat { "KEY": "value" } object');
  }

  return Object.entries(obj).map(([key, value]) => ({
    key,
    value: String(value),
  }));
}

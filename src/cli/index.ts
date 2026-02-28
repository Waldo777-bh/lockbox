/**
 * CLI command registration — wires up all lockbox commands
 */

import { existsSync, statSync, readFileSync, writeFileSync } from 'node:fs';
import { extname } from 'node:path';
import { spawnSync } from 'node:child_process';
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
import {
  envKeyName,
  splitKeyName,
  parseEnvFile as parseEnvImport,
  parseJsonImport,
  parseProxyUri,
  buildProxyUri,
  PROXY_PREFIX,
} from './env-utils.js';
import { auditLog, readAuditLog } from '../mcp/audit.js';
import { checkKeyLimitCLI, getTier, clearTierCache } from './tier.js';
import { loadConfig as loadCfg, saveConfig as saveCfg } from '../vault/config.js';

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
    .addHelpText('after', `
Examples:
  $ lockbox init
`)
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
        auditLog('init', { vaultPath: vaultFile }, 'cli');

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
    .addHelpText('after', `
Examples:
  $ lockbox unlock
  $ lockbox unlock    # session lasts 15 minutes
`)
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
        auditLog('unlock', {}, 'cli');
        process.stderr.write(chalk.dim('  Auto-locks in 15 minutes.\n'));
      } catch (err) {
        exitWithError((err as Error).message);
      }
    });

  // ── lock ─────────────────────────────────────────────────────────────────
  program
    .command('lock')
    .description('Lock the vault and clear session')
    .addHelpText('after', `
Examples:
  $ lockbox lock
`)
    .action(() => {
      try {
        clearSession();
        auditLog('lock', {}, 'cli');
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
    .addHelpText('after', `
Examples:
  $ lockbox add openai API_KEY sk-abc123
  $ lockbox add stripe SECRET_KEY --project myapp
  $ lockbox add aws ACCESS_KEY              # prompts for value
  $ lockbox add github TOKEN --notes "PAT for CI"
`)
    .action(async (service: string, keyName: string, value: string | undefined, opts) => {
      try {
        const vault = loadVaultFromSession();

        // Check tier key limit before adding
        const config = loadCfg();
        const currentKeys = vault.listKeys();
        const limitCheck = await checkKeyLimitCLI(currentKeys.length, config.licenceKey);
        if (!limitCheck.allowed) {
          vault.lock();
          exitWithError(limitCheck.message!);
        }

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
        auditLog('add', { service, key_name: keyName, project: opts.project }, 'cli');

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
    .addHelpText('after', `
Examples:
  $ lockbox get openai API_KEY
  $ lockbox get openai API_KEY --copy       # copies to clipboard, clears in 30s
  $ lockbox get stripe SECRET | pbcopy      # pipe to other commands
`)
    .action(async (service: string, keyName: string, opts) => {
      try {
        const vault = loadVaultFromSession();
        const value = vault.getKey(service, keyName);
        vault.lock();
        auditLog('get', { service, key_name: keyName, copy: !!opts.copy }, 'cli');

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
    .addHelpText('after', `
Examples:
  $ lockbox list
  $ lockbox list --project myapp
`)
    .action((opts) => {
      try {
        const vault = loadVaultFromSession();
        const keys = vault.listKeys(opts.project);
        vault.lock();
        auditLog('list', { project: opts.project ?? 'all' }, 'cli');

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
    .addHelpText('after', `
Examples:
  $ lockbox remove openai API_KEY
  $ lockbox remove stripe SECRET --force    # skip confirmation
`)
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
        auditLog('remove', { service, key_name: keyName }, 'cli');

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
    .addHelpText('after', `
Examples:
  $ lockbox search openai
  $ lockbox search production
`)
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
    .description('Show vault lock state, key count, and session info')
    .addHelpText('after', `
Examples:
  $ lockbox status
`)
    .action(async () => {
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

        // Tier info
        const { tier, keyLimit } = await getTier(config.licenceKey);
        process.stderr.write(
          `  Tier:      ${tier === 'pro' ? chalk.green('Pro') : chalk.dim('Free')}` +
            (tier === 'free' ? chalk.dim(` (${keyLimit} key limit)`) : '') +
            '\n'
        );
        if (tier === 'free') {
          process.stderr.write(
            chalk.dim('  Upgrade:   lockbox upgrade\n')
          );
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
    .addHelpText('after', `
Examples:
  $ lockbox export > .env
  $ lockbox export --project myapp --format json
  $ lockbox export --format shell >> ~/.bashrc
`)
    .action((opts) => {
      try {
        const vault = loadVaultFromSession();
        const pairs = vault.exportKeys(opts.project);
        vault.lock();
        auditLog('export', { project: opts.project ?? 'all', format: opts.format, count: pairs.length }, 'cli');

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
    .addHelpText('after', `
Examples:
  $ lockbox import .env
  $ lockbox import credentials.json --project myapp
`)
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

        // Check tier limit before importing
        const cfg = loadCfg();
        const currentKeys = vault.listKeys();
        const newKeys = entries.filter(({ key }) => {
          const [svc, kn] = splitKeyName(key);
          return !vault.hasKey(svc, kn);
        });
        const totalAfter = currentKeys.length + newKeys.length;
        const { tier, keyLimit } = await getTier(cfg.licenceKey);
        if (keyLimit !== Infinity && totalAfter > keyLimit) {
          vault.lock();
          exitWithError(
            `Import would exceed the Free tier limit of ${keyLimit} keys (${currentKeys.length} existing + ${newKeys.length} new = ${totalAfter}). Upgrade to Pro for unlimited keys.\n  Run: lockbox upgrade`
          );
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
        auditLog('import', { file, project: opts.project, imported, skipped }, 'cli');

        process.stderr.write(
          chalk.green(`✓ Imported ${imported} key(s) into project '${opts.project}'`)
          + (skipped > 0 ? chalk.dim(` (${skipped} skipped)`) : '')
          + '\n'
        );
      } catch (err) {
        exitWithError((err as Error).message);
      }
    });

  // ── run ───────────────────────────────────────────────────────────────
  program
    .command('run')
    .description('Run a command with lockbox:// proxy env vars resolved from the vault')
    .argument('<command...>', 'Command to run (e.g. "npm start")')
    .option('--env-file <path>', 'Path to env file', '.env')
    .addHelpText('after', `
Examples:
  $ lockbox run "npm start"
  $ lockbox run --env-file .env.proxy "python app.py"
  $ lockbox run "env | grep OPENAI"         # verify resolution
`)
    .action(async (commandParts: string[], opts) => {
      try {
        const envFilePath: string = opts.envFile;

        // 1. Read the env file
        if (!existsSync(envFilePath)) {
          throw new Error(`Env file not found: ${envFilePath}`);
        }
        const raw = readFileSync(envFilePath, 'utf8');
        const entries = parseEnvImport(raw);

        if (entries.length === 0) {
          throw new Error(`No environment variables found in ${envFilePath}`);
        }

        // 2. Separate proxy refs from passthrough values
        const proxyEntries: { envKey: string; service: string; keyName: string }[] = [];
        const env: Record<string, string> = { ...process.env } as Record<string, string>;

        for (const { key, value } of entries) {
          const proxy = parseProxyUri(value);
          if (proxy) {
            proxyEntries.push({ envKey: key, ...proxy });
          } else {
            env[key] = value;
          }
        }

        // 3. Resolve proxy references from the vault
        if (proxyEntries.length > 0) {
          const vault = loadVaultFromSession();

          for (const { envKey, service, keyName } of proxyEntries) {
            if (!vault.hasKey(service, keyName)) {
              vault.lock();
              throw new Error(
                `Proxy reference ${PROXY_PREFIX}${service}/${keyName} not found in vault`
              );
            }
            env[envKey] = vault.getKey(service, keyName);
          }

          vault.lock();
          auditLog('run', {
            envFile: envFilePath,
            proxiesResolved: proxyEntries.length,
            keys: proxyEntries.map(({ service, keyName }) => `${service}/${keyName}`),
          }, 'cli');
          process.stderr.write(
            chalk.dim(`Resolved ${proxyEntries.length} proxy reference(s) from vault.\n`)
          );
        }

        // 4. Spawn the child process
        const cmd = commandParts.join(' ');
        const { status } = spawnSync(cmd, {
          shell: true,
          stdio: 'inherit',
          env,
        });

        process.exit(status ?? 1);
      } catch (err) {
        exitWithError((err as Error).message);
      }
    });

  // ── proxy-init ────────────────────────────────────────────────────────
  program
    .command('proxy-init')
    .description('Generate a .env.proxy file with lockbox:// references (safe to commit)')
    .requiredOption('-p, --project <name>', 'Project name to generate proxy for')
    .option('-o, --output <path>', 'Output file path', '.env.proxy')
    .addHelpText('after', `
Examples:
  $ lockbox proxy-init --project myapp
  $ lockbox proxy-init -p myapp -o .env.staging
  $ git add .env.proxy                      # safe to commit!
`)
    .action(async (opts) => {
      try {
        const vault = loadVaultFromSession();
        const keys = vault.listKeys(opts.project);
        vault.lock();

        if (keys.length === 0) {
          throw new Error(`No keys found in project "${opts.project}"`);
        }

        // Build the proxy env file content
        const lines: string[] = [
          `# Lockbox proxy env — project: ${opts.project}`,
          `# Generated: ${new Date().toISOString()}`,
          `# Safe to commit — contains only lockbox:// references, no real secrets`,
          '',
        ];

        for (const key of keys) {
          const slashIdx = key.name.indexOf('/');
          const service = key.name.slice(0, slashIdx);
          const keyName = key.name.slice(slashIdx + 1);
          const envName = envKeyName(key.name);
          lines.push(`${envName}=${buildProxyUri(service, keyName)}`);
        }

        lines.push(''); // trailing newline
        const content = lines.join('\n');
        const outputPath: string = opts.output;

        // Check if file already exists
        if (existsSync(outputPath)) {
          const overwrite = await promptConfirm(
            chalk.yellow(`${outputPath} already exists. Overwrite?`)
          );
          if (!overwrite) {
            process.stderr.write(chalk.dim('Aborted.\n'));
            return;
          }
        }

        writeFileSync(outputPath, content, 'utf8');
        auditLog('proxy-init', { project: opts.project, output: outputPath, count: keys.length }, 'cli');

        process.stderr.write(chalk.green(`✓ Generated ${outputPath}\n`));
        process.stderr.write(chalk.dim(`  ${keys.length} proxy reference(s) for project "${opts.project}"\n`));
        process.stderr.write(chalk.dim(`  Run: lockbox run --env-file ${outputPath} "your-command"\n`));
      } catch (err) {
        exitWithError((err as Error).message);
      }
    });

  // ── audit ──────────────────────────────────────────────────────────────
  program
    .command('audit')
    .description('Show recent audit log entries')
    .option('--since <date>', 'Only show entries after this date (ISO 8601)')
    .option('-n, --limit <number>', 'Number of entries to show', '50')
    .addHelpText('after', `
Examples:
  $ lockbox audit
  $ lockbox audit --since 2025-01-01
  $ lockbox audit -n 10
`)
    .action((opts) => {
      try {
        const limit = parseInt(opts.limit, 10) || 50;
        const entries = readAuditLog(opts.since, limit);

        if (entries.length === 0) {
          process.stderr.write(
            chalk.dim(opts.since
              ? `No audit entries found since ${opts.since}.\n`
              : 'No audit entries found.\n')
          );
          return;
        }

        const rows = entries.map((e) => [
          shortDate(e.timestamp) + ' ' + e.timestamp.slice(11, 19),
          e.source,
          e.operation,
          e.params.length > 60 ? e.params.slice(0, 57) + '...' : e.params,
        ]);

        process.stderr.write(
          formatTable(['Time', 'Source', 'Operation', 'Details'], rows) + '\n'
        );
        process.stderr.write(chalk.dim(`\n${entries.length} entries shown\n`));
      } catch (err) {
        exitWithError((err as Error).message);
      }
    });

  // ── config ──────────────────────────────────────────────────────────────
  program
    .command('config')
    .description('View or update Lockbox configuration')
    .option('--licence <key>', 'Set your Pro licence key')
    .option('--show', 'Show current configuration')
    .addHelpText('after', `
Examples:
  $ lockbox config --show
  $ lockbox config --licence lbox_pro_abc123...
`)
    .action(async (opts) => {
      try {
        const config = loadCfg();

        if (opts.licence) {
          const key = opts.licence.trim();
          if (!key.startsWith('lbox_pro_')) {
            exitWithError('Invalid licence key format. Keys start with "lbox_pro_".');
          }

          config.licenceKey = key;
          saveCfg(config);
          clearTierCache();
          auditLog('config', { action: 'set_licence' }, 'cli');

          // Validate the key
          const spinner = ora('Validating licence key...').start();
          const { tier } = await getTier(key);

          if (tier === 'pro') {
            spinner.succeed('Licence key validated — Pro tier activated!');
          } else {
            spinner.warn('Licence key saved but could not validate. Pro features will activate once verified.');
          }
          return;
        }

        if (opts.show || !opts.licence) {
          process.stderr.write(chalk.bold('Lockbox Configuration\n\n'));
          process.stderr.write(`  Vault path:     ${config.vaultPath}\n`);
          process.stderr.write(`  Auto-lock:      ${config.autoLockMinutes} minutes\n`);
          process.stderr.write(`  Default project: ${config.defaultProject}\n`);
          process.stderr.write(`  Licence key:    ${config.licenceKey ? config.licenceKey.slice(0, 14) + '...' : chalk.dim('(not set)')}\n`);

          const { tier } = await getTier(config.licenceKey);
          process.stderr.write(`  Tier:           ${tier === 'pro' ? chalk.green('Pro') : chalk.dim('Free')}\n`);
        }
      } catch (err) {
        exitWithError((err as Error).message);
      }
    });

  // ── upgrade ────────────────────────────────────────────────────────────
  program
    .command('upgrade')
    .description('Upgrade to Lockbox Pro for unlimited vaults and keys')
    .addHelpText('after', `
Examples:
  $ lockbox upgrade
`)
    .action(async () => {
      try {
        const config = loadCfg();
        const { tier } = await getTier(config.licenceKey);

        if (tier === 'pro') {
          process.stderr.write(chalk.green('✓ You are already on the Pro plan!\n'));
          process.stderr.write(chalk.dim('  Manage your subscription at: https://lockbox-dashboard-production.up.railway.app/dashboard/settings\n'));
          return;
        }

        process.stderr.write(chalk.bold('\nLockbox Pro — $5/month or $48/year\n\n'));
        process.stderr.write('  ✓ Unlimited vaults\n');
        process.stderr.write('  ✓ Unlimited keys\n');
        process.stderr.write('  ✓ Key expiry reminders\n');
        process.stderr.write('  ✓ Priority support\n');
        process.stderr.write('  ✓ Full dashboard write access\n\n');

        process.stderr.write(chalk.cyan('To upgrade:\n'));
        process.stderr.write('  1. Visit: https://lockbox-dashboard-production.up.railway.app/dashboard/pricing\n');
        process.stderr.write('  2. Complete checkout\n');
        process.stderr.write('  3. Copy your licence key from Settings → Subscription\n');
        process.stderr.write(`  4. Run: ${chalk.bold('lockbox config --licence YOUR_KEY')}\n\n`);

        auditLog('upgrade', { action: 'viewed' }, 'cli');
      } catch (err) {
        exitWithError((err as Error).message);
      }
    });

  // ── doctor ─────────────────────────────────────────────────────────────
  program
    .command('doctor')
    .description('Run health checks on the vault')
    .addHelpText('after', `
Examples:
  $ lockbox doctor
`)
    .action(async () => {
      let issues = 0;

      process.stderr.write(chalk.bold('Lockbox Doctor\n\n'));

      // 1. Check vault file exists and is readable
      const config = loadConfig();
      const { vaultFile } = getPaths(config);

      if (!existsSync(vaultFile)) {
        process.stderr.write(chalk.red('  ✗ Vault file not found\n'));
        process.stderr.write(chalk.dim(`    Expected at: ${vaultFile}\n`));
        process.stderr.write(chalk.dim('    Run `lockbox init` to create a vault.\n'));
        return;
      }

      const stats = statSync(vaultFile);
      if (stats.size === 0) {
        process.stderr.write(chalk.red('  ✗ Vault file is empty\n'));
        issues++;
      } else {
        process.stderr.write(chalk.green('  ✓ Vault file exists and is readable\n'));
      }

      // 2. Check vault JSON is parseable
      let vaultJson: { salt?: string; iv?: string; tag?: string; ciphertext?: string; hmac?: string } | null = null;
      try {
        const raw = readFileSync(vaultFile, 'utf8');
        vaultJson = JSON.parse(raw);
        const requiredFields = ['salt', 'iv', 'tag', 'ciphertext', 'hmac'];
        const missing = requiredFields.filter((f) => !(f in (vaultJson as Record<string, unknown>)));
        if (missing.length > 0) {
          process.stderr.write(chalk.red(`  ✗ Vault file missing fields: ${missing.join(', ')}\n`));
          issues++;
        } else {
          process.stderr.write(chalk.green('  ✓ Vault file structure is valid\n'));
        }
      } catch {
        process.stderr.write(chalk.red('  ✗ Vault file is not valid JSON\n'));
        issues++;
      }

      // 3. Verify HMAC integrity (requires unlocked session)
      const session = loadSession();
      if (session && vaultJson) {
        try {
          const vault = Vault.openWithKey(session.vaultPath, session.key);
          vault.lock();
          process.stderr.write(chalk.green('  ✓ HMAC integrity verified\n'));
          process.stderr.write(chalk.green('  ✓ Decryption round-trip successful\n'));
        } catch (err) {
          const msg = (err as Error).message;
          if (msg.includes('integrity') || msg.includes('tampered')) {
            process.stderr.write(chalk.red('  ✗ Vault file has been tampered with or corrupted\n'));
          } else {
            process.stderr.write(chalk.red(`  ✗ Vault decryption failed: ${msg}\n`));
          }
          issues++;
        }
      } else if (!session) {
        process.stderr.write(chalk.yellow('  ⚠ Vault is locked — cannot verify HMAC or decryption\n'));
        process.stderr.write(chalk.dim('    Run `lockbox unlock` to enable full health check.\n'));
      }

      // 4. Check session file status
      if (session) {
        const remaining = sessionTimeRemaining();
        const mins = remaining ? Math.floor(remaining / 60) : 0;
        const secs = remaining ? remaining % 60 : 0;
        process.stderr.write(chalk.green(`  ✓ Session active (${mins}m ${secs}s remaining)\n`));
      } else {
        process.stderr.write(chalk.dim('  ○ No active session (vault is locked)\n'));
      }

      // 5. Summary
      process.stderr.write('\n');
      if (issues === 0) {
        process.stderr.write(chalk.green.bold('  ✓ Vault is healthy\n'));
      } else {
        process.stderr.write(chalk.red.bold(`  ✗ ${issues} issue(s) found\n`));
        process.exit(1);
      }
    });
}


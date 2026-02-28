#!/usr/bin/env node

import { existsSync } from 'node:fs';
import { Command } from 'commander';
import chalk from 'chalk';
import { registerCommands } from './cli/index.js';
import { loadConfig, getPaths } from './vault/config.js';

const program = new Command();

program
  .name('lockbox')
  .description('Encrypted API key vault with MCP integration for AI coding tools')
  .version('1.1.0');

registerCommands(program);

// Show welcome banner when run with no arguments and no vault exists
if (process.argv.length <= 2) {
  const config = loadConfig();
  const { vaultFile } = getPaths(config);

  if (!existsSync(vaultFile)) {
    process.stderr.write('\n');
    process.stderr.write(chalk.cyan('  ╔══════════════════════════════════════╗\n'));
    process.stderr.write(chalk.cyan('  ║') + chalk.bold.white('             Lockbox                 ') + chalk.cyan('║\n'));
    process.stderr.write(chalk.cyan('  ║') + chalk.dim('     Your keys, locked down.         ') + chalk.cyan('║\n'));
    process.stderr.write(chalk.cyan('  ╚══════════════════════════════════════╝\n'));
    process.stderr.write('\n');
    process.stderr.write(chalk.dim('  Get started:\n'));
    process.stderr.write(`    ${chalk.green('$')} lockbox init\n`);
    process.stderr.write(`    ${chalk.green('$')} lockbox add openai API_KEY\n`);
    process.stderr.write(`    ${chalk.green('$')} lockbox get openai API_KEY\n`);
    process.stderr.write('\n');
    process.stderr.write(chalk.dim(`  Docs: ${chalk.underline('https://yourlockbox.dev')}\n`));
    process.stderr.write('\n');
    process.exit(0);
  }
}

program.parse();

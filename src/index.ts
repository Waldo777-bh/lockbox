#!/usr/bin/env node

import { Command } from 'commander';
import { registerCommands } from './cli/index.js';

const program = new Command();

program
  .name('lockbox')
  .description('Encrypted API key vault for developers and AI coding agents')
  .version('0.1.0');

registerCommands(program);

program.parse();

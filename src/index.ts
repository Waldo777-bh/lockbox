#!/usr/bin/env node

import { Command } from 'commander';

const program = new Command();

program
  .name('lockbox')
  .description('Encrypted API key vault for developers and AI coding agents')
  .version('0.1.0');

program
  .command('hello')
  .description('Verify lockbox CLI is working')
  .action(() => {
    console.log('Lockbox CLI is working!');
  });

program.parse();

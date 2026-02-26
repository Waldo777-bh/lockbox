/**
 * CLI helper utilities — prompts, clipboard, table formatting, colours
 */

import { createInterface } from 'node:readline';
import { Writable } from 'node:stream';
import { exec } from 'node:child_process';
import { platform } from 'node:os';
import chalk from 'chalk';

// ─── Password prompt (hidden input) ─────────────────────────────────────────

/**
 * Prompt for a password with hidden (muted) input.
 */
export async function promptPassword(message: string): Promise<string> {
  // Create a muted output so readline doesn't echo typed characters
  const muted = new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });

  const rl = createInterface({
    input: process.stdin,
    output: muted,
    terminal: true,
  });

  process.stderr.write(message);

  return new Promise<string>((resolve) => {
    rl.question('', (answer) => {
      rl.close();
      process.stderr.write('\n');
      resolve(answer);
    });
  });
}

/**
 * Prompt for a password and confirm it matches.
 * @returns The confirmed password
 * @throws  If passwords don't match
 */
export async function promptPasswordWithConfirm(): Promise<string> {
  const pw1 = await promptPassword(chalk.cyan('Enter master password: '));
  const pw2 = await promptPassword(chalk.cyan('Confirm master password: '));

  if (pw1 !== pw2) {
    throw new Error('Passwords do not match');
  }

  if (pw1.length < 8) {
    throw new Error('Password must be at least 8 characters');
  }

  return pw1;
}

// ─── Confirm prompt ──────────────────────────────────────────────────────────

/**
 * Ask a yes/no confirmation question.
 */
export async function promptConfirm(message: string): Promise<boolean> {
  const rl = createInterface({
    input: process.stdin,
    output: process.stderr,
  });

  return new Promise<boolean>((resolve) => {
    rl.question(`${message} (y/N): `, (answer) => {
      rl.close();
      resolve(answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes');
    });
  });
}

// ─── Clipboard ───────────────────────────────────────────────────────────────

/**
 * Copy text to the system clipboard (platform-aware).
 */
export function copyToClipboard(text: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const p = platform();
    let cmd: string;

    if (p === 'win32') {
      cmd = 'clip';
    } else if (p === 'darwin') {
      cmd = 'pbcopy';
    } else {
      cmd = 'xclip -selection clipboard';
    }

    const child = exec(cmd, (err) => {
      if (err) reject(err);
      else resolve();
    });

    child.stdin?.write(text);
    child.stdin?.end();
  });
}

/**
 * Copy value to clipboard and schedule auto-clear after N seconds.
 * Keeps the process alive until the clipboard is cleared.
 */
export async function copyAndScheduleClear(value: string, seconds: number): Promise<void> {
  await copyToClipboard(value);
  process.stderr.write(chalk.green(`✓ Copied to clipboard. Auto-clearing in ${seconds}s...\n`));

  return new Promise<void>((resolve) => {
    setTimeout(async () => {
      await copyToClipboard('');
      process.stderr.write(chalk.dim(`✓ Clipboard cleared.\n`));
      resolve();
    }, seconds * 1000);
  });
}

// ─── Table formatting ────────────────────────────────────────────────────────

/**
 * Format data as a simple aligned table.
 */
export function formatTable(headers: string[], rows: string[][]): string {
  // Calculate column widths
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => (r[i] || '').length))
  );

  const divider = widths.map((w) => '─'.repeat(w + 2)).join('┼');
  const headerLine = headers
    .map((h, i) => chalk.bold(h.padEnd(widths[i])))
    .join(' │ ');
  const body = rows
    .map((row) =>
      row.map((cell, i) => (cell || '').padEnd(widths[i])).join(' │ ')
    )
    .join('\n');

  return `${headerLine}\n${divider}\n${body}`;
}

// ─── Error formatting ────────────────────────────────────────────────────────

/**
 * Print an error message and exit.
 */
export function exitWithError(message: string): never {
  process.stderr.write(chalk.red(`✗ ${message}\n`));
  process.exit(1);
}

// ─── Date formatting ─────────────────────────────────────────────────────────

/**
 * Format an ISO date string as a short readable date.
 */
export function shortDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

// ─── Choice prompt ───────────────────────────────────────────────────────────

/**
 * Prompt the user to choose from a set of options.
 * Returns the key of the chosen option.
 */
export async function promptChoice(
  message: string,
  choices: { key: string; label: string }[],
): Promise<string> {
  const rl = createInterface({
    input: process.stdin,
    output: process.stderr,
  });

  const optionStr = choices.map((c) => c.label).join('/');
  return new Promise<string>((resolve) => {
    rl.question(`${message} (${optionStr}): `, (answer) => {
      rl.close();
      const lower = answer.toLowerCase().trim();
      const match = choices.find(
        (c) => c.key === lower || c.label.toLowerCase().startsWith(lower),
      );
      resolve(match ? match.key : choices[0].key);
    });
  });
}

// Re-export chalk for use in commands
export { chalk };

#!/usr/bin/env node
// leakhook CLI — install / uninstall the hook, or scan staged/all content.

import { scanStaged, scanAll, installHook, uninstallHook } from '../src/index.js';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

// --- Colors (respect NO_COLOR and non-TTY) ---------------------------------
const useColor = !process.env.NO_COLOR && process.stdout.isTTY;
const c = (code, s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const red = (s) => c('31', s);
const green = (s) => c('32', s);
const yellow = (s) => c('33', s);
const dim = (s) => c('2', s);
const bold = (s) => c('1', s);

function version() {
  try {
    const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8'));
    return pkg.version;
  } catch {
    return '0.0.0';
  }
}

const HELP = `${bold('leakhook')} — stop secrets before they hit git history.

${bold('Usage')}
  leakhook install            Install the git pre-commit hook (idempotent).
  leakhook uninstall          Remove the hook / restore any backup.
  leakhook scan [--staged]    Scan staged changes (default). Exit 1 on findings.
  leakhook scan --all         Scan all tracked files.
  leakhook --help             Show this help.
  leakhook --version          Print version.

${bold('Escape hatches')}
  LEAKHOOK_SKIP=1             Bypass the scan for one commit.
  leakhook-allow             Inline comment marker to skip a single line.
  .leakhookignore            Repo allowlist (globs or regex:<pattern>).

Built by Devya — https://devya.dev`;

function printFindings(findings) {
  console.error(red(bold('\n✖ leakhook: potential secrets detected\n')));
  for (const f of findings) {
    const loc = `${f.path}:${f.line}`;
    console.error(`  ${bold(loc)}  ${yellow(f.ruleId)}  ${dim(f.redacted)}`);
  }
  console.error(
    dim(
      `\n${findings.length} finding${findings.length === 1 ? '' : 's'}. ` +
        `Remove the secret, add an allowlist entry, or use a ${bold('leakhook-allow')} comment.\n` +
        `To bypass this one commit: ${bold('LEAKHOOK_SKIP=1 git commit ...')}\n`,
    ),
  );
}

function runScan(args) {
  if (process.env.LEAKHOOK_SKIP === '1') {
    console.error(yellow('⚠ leakhook: LEAKHOOK_SKIP=1 set — scan bypassed.'));
    return 0;
  }
  const all = args.includes('--all');
  let findings;
  try {
    findings = all ? scanAll() : scanStaged();
  } catch (err) {
    console.error(red(`leakhook: ${err.message}`));
    return 2;
  }
  if (findings.length === 0) {
    console.error(green('✔ leakhook: no secrets detected.'));
    return 0;
  }
  printFindings(findings);
  return 1;
}

function main() {
  const [, , cmd, ...rest] = process.argv;

  if (cmd === '--version' || cmd === '-v') {
    console.log(version());
    return 0;
  }
  if (!cmd || cmd === '--help' || cmd === '-h' || cmd === 'help') {
    console.log(HELP);
    return 0;
  }

  switch (cmd) {
    case 'scan':
      return runScan(rest);
    case 'install': {
      try {
        const r = installHook();
        console.log(green(`✔ leakhook: hook ${r.action} at ${dim(r.path)}`));
        if (r.backup) console.log(dim(`  (existing hook backed up to ${r.backup})`));
        console.log(dim('  Commits are now scanned for secrets. Nice.'));
        return 0;
      } catch (err) {
        console.error(red(`leakhook install failed: ${err.message}`));
        return 2;
      }
    }
    case 'uninstall': {
      try {
        const r = uninstallHook();
        const msg = { noop: 'no hook found', removed: 'hook removed', restored: 'previous hook restored', cleaned: 'hook block removed' }[r.action] || r.action;
        console.log(green(`✔ leakhook: ${msg}`));
        return 0;
      } catch (err) {
        console.error(red(`leakhook uninstall failed: ${err.message}`));
        return 2;
      }
    }
    default:
      console.error(red(`leakhook: unknown command "${cmd}"`));
      console.error(dim('Run `leakhook --help` for usage.'));
      return 2;
  }
}

process.exit(main());

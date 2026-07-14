// leakhook — zero-dependency git pre-commit secret scanner.
// Node built-ins only. Exports pure functions so they are trivially testable.

import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, chmodSync, mkdirSync, unlinkSync, renameSync } from 'node:fs';
import { join } from 'node:path';

// --- Detection rules -------------------------------------------------------

// Content rules. Each: { id, description, regex }. Add here to extend leakhook.
export const rules = [
  {
    id: 'aws-access-key-id',
    description: 'AWS Access Key ID',
    regex: /AKIA[0-9A-Z]{16}/g,
  },
  {
    id: 'aws-secret-access-key',
    description: 'AWS Secret Access Key (contextual)',
    regex: /aws_secret_access_key\s*[:=]\s*['"]?[A-Za-z0-9/+]{40}['"]?/gi,
  },
  {
    id: 'github-token',
    description: 'GitHub personal/OAuth/app token',
    regex: /gh[pousr]_[A-Za-z0-9]{36,}/g,
  },
  {
    id: 'gitlab-token',
    description: 'GitLab personal access token',
    regex: /glpat-[A-Za-z0-9_-]{20,}/g,
  },
  {
    id: 'stripe-secret-key',
    description: 'Stripe live secret key',
    regex: /sk_live_[A-Za-z0-9]{16,}/g,
  },
  {
    id: 'slack-token',
    description: 'Slack token',
    regex: /xox[baprs]-[A-Za-z0-9-]{10,}/g,
  },
  {
    id: 'google-api-key',
    description: 'Google API key',
    regex: /AIza[0-9A-Za-z_\-]{35}/g,
  },
  {
    id: 'private-key-block',
    description: 'Private key PEM block',
    regex: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
  },
  {
    id: 'jwt',
    description: 'JSON Web Token',
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  },
  {
    id: 'mongodb-uri-creds',
    description: 'MongoDB connection string with embedded credentials',
    regex: /mongodb(\+srv)?:\/\/[^:@\s]+:[^@\s]+@/g,
  },
  {
    id: 'generic-secret-assignment',
    description: 'Hard-coded secret assignment',
    regex: /(password|passwd|secret|api[_-]?key|token|access[_-]?key)\s*[:=]\s*['"][^'"]{12,}['"]/gi,
  },
];

// Filename rules. Returns a rule id if the basename is forbidden, else null.
const ALLOWED_ENV = new Set(['.env.example', '.env.sample', '.env.template']);

export function forbiddenFilename(filename) {
  const base = filename.split('/').pop() || filename;
  const lower = base.toLowerCase();

  // .env and .env.* (but allow example/sample/template variants)
  if (base === '.env' || base.startsWith('.env.')) {
    if (!ALLOWED_ENV.has(lower)) return 'dotenv-file';
  }
  // Private key material by extension
  if (base.endsWith('.pem')) return 'pem-file';
  if (base.endsWith('.key')) return 'key-file';
  // SSH private keys
  if (['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519'].includes(base)) return 'ssh-private-key';
  // Cloud service-account / credentials JSON
  if (lower.endsWith('.json') && (lower.includes('service-account') || lower.includes('credentials'))) {
    return 'service-account-json';
  }
  return null;
}

// --- Helpers ---------------------------------------------------------------

// Redact the middle of a matched secret, keeping enough context to identify it.
export function redact(match) {
  const s = String(match);
  if (s.length <= 8) return s[0] + '•'.repeat(Math.max(1, s.length - 1));
  const head = s.slice(0, 4);
  const tail = s.slice(-4);
  return `${head}${'•'.repeat(Math.min(8, s.length - 8))}${tail}`;
}

// Inline allow marker: a line the author explicitly opted out of scanning.
const ALLOW_MARKER = 'leakhook-allow';

// --- Core scanner ----------------------------------------------------------

// Pure function. Given text and optional filename, return an array of findings:
//   { line, ruleId, description, match, redacted }
// `startLine` lets callers map back to real file line numbers (diff hunks).
export function scanContent(text, { filename = '', startLine = 1 } = {}) {
  const findings = [];

  // Filename-level check (surfaces as a single finding on line 1).
  if (filename) {
    const fileRule = forbiddenFilename(filename);
    if (fileRule) {
      findings.push({
        line: 1,
        ruleId: fileRule,
        description: 'Forbidden file committed',
        match: filename,
        redacted: filename,
      });
    }
  }

  const lines = String(text).split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.includes(ALLOW_MARKER)) continue; // inline opt-out
    for (const rule of rules) {
      rule.regex.lastIndex = 0;
      let m;
      while ((m = rule.regex.exec(line)) !== null) {
        const value = m[0];
        findings.push({
          line: startLine + i,
          ruleId: rule.id,
          description: rule.description,
          match: value,
          redacted: redact(value),
        });
        if (m.index === rule.regex.lastIndex) rule.regex.lastIndex++; // avoid zero-width loop
      }
    }
  }
  return findings;
}

// --- Allowlist (.leakhookignore) -------------------------------------------

// Parse .leakhookignore into { globs: [], regexes: [RegExp] }.
export function loadAllowlist(cwd) {
  const file = join(cwd, '.leakhookignore');
  const result = { globs: [], regexes: [] };
  if (!existsSync(file)) return result;
  const raw = readFileSync(file, 'utf8');
  for (const rawLine of raw.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('regex:')) {
      try {
        result.regexes.push(new RegExp(line.slice('regex:'.length).trim()));
      } catch {
        /* ignore malformed regex line */
      }
    } else {
      result.globs.push(line);
    }
  }
  return result;
}

// Minimal glob → RegExp (supports * and **, path-segment aware enough for ignores).
function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        re += '.*';
        i++;
      } else {
        re += '[^/]*';
      }
    } else if ('.+?^${}()|[]\\'.includes(c)) {
      re += '\\' + c;
    } else {
      re += c;
    }
  }
  return new RegExp('^' + re + '$');
}

export function isAllowlisted(path, allowlist) {
  for (const g of allowlist.globs) {
    if (globToRegExp(g).test(path)) return true;
  }
  for (const r of allowlist.regexes) {
    if (r.test(path)) return true;
  }
  return false;
}

// --- Git plumbing ----------------------------------------------------------

function git(args, cwd) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
}

function gitDir(cwd) {
  return git(['rev-parse', '--git-dir'], cwd).trim();
}

// Parse `git diff --cached -U0` output into per-file added lines with line numbers.
function parseDiffAddedLines(diff) {
  const perFile = new Map();
  let current = null;
  let newLine = 0;
  for (const raw of diff.split('\n')) {
    if (raw.startsWith('+++ ')) {
      const path = raw.slice(4).replace(/^b\//, '');
      if (path === '/dev/null') {
        current = null;
      } else {
        current = path;
        if (!perFile.has(current)) perFile.set(current, []);
      }
      continue;
    }
    const hunk = raw.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunk) {
      newLine = parseInt(hunk[1], 10);
      continue;
    }
    if (current === null) continue;
    if (raw.startsWith('+') && !raw.startsWith('+++')) {
      perFile.get(current).push({ line: newLine, text: raw.slice(1) });
      newLine++;
    } else if (raw.startsWith('-') || raw.startsWith('---')) {
      // removed line — does not advance new-file counter
    } else if (raw.startsWith(' ')) {
      newLine++;
    }
  }
  return perFile;
}

// Scan the staged index. Returns an array of findings with `path` attached.
export function scanStaged(cwd = process.cwd()) {
  const allowlist = loadAllowlist(cwd);
  const findings = [];

  // 1. Forbidden filenames among staged files.
  const nameOutput = git(['diff', '--cached', '--name-only', '-z'], cwd);
  const names = nameOutput.split('\0').filter(Boolean);
  for (const name of names) {
    if (isAllowlisted(name, allowlist)) continue;
    const rule = forbiddenFilename(name);
    if (rule) {
      findings.push({ path: name, line: 1, ruleId: rule, description: 'Forbidden file committed', redacted: name });
    }
  }

  // 2. Secret patterns in added lines.
  const diff = git(['diff', '--cached', '-U0', '--no-color'], cwd);
  const perFile = parseDiffAddedLines(diff);
  for (const [path, added] of perFile) {
    if (isAllowlisted(path, allowlist)) continue;
    for (const { line, text } of added) {
      const hits = scanContent(text, { startLine: line });
      for (const f of hits) {
        findings.push({ path, line: f.line, ruleId: f.ruleId, description: f.description, redacted: f.redacted });
      }
    }
  }
  return findings;
}

// Scan all tracked files (leakhook scan --all).
export function scanAll(cwd = process.cwd()) {
  const allowlist = loadAllowlist(cwd);
  const findings = [];
  const listed = git(['ls-files', '-z'], cwd).split('\0').filter(Boolean);
  for (const path of listed) {
    if (isAllowlisted(path, allowlist)) continue;
    const abs = join(cwd, path);
    let text = '';
    try {
      text = readFileSync(abs, 'utf8');
    } catch {
      continue; // binary / unreadable — skip
    }
    const hits = scanContent(text, { filename: path });
    for (const f of hits) {
      findings.push({ path, line: f.line, ruleId: f.ruleId, description: f.description, redacted: f.redacted });
    }
  }
  return findings;
}

// --- Hook install / uninstall ----------------------------------------------

const HOOK_BEGIN = '# >>> leakhook >>>';
const HOOK_END = '# <<< leakhook <<<';

function hookBlock() {
  return [
    HOOK_BEGIN,
    '# Managed by leakhook — https://devya.dev  (do not edit between these markers)',
    'if [ "$LEAKHOOK_SKIP" != "1" ]; then',
    '  npx --no-install leakhook scan --staged || exit 1',
    'fi',
    HOOK_END,
  ].join('\n');
}

// Idempotently install the pre-commit hook. If a foreign hook exists we append
// our guarded block (and back it up once) rather than clobbering it.
export function installHook(cwd = process.cwd()) {
  const dir = gitDir(cwd);
  const hooksDir = join(cwd, dir, 'hooks');
  mkdirSync(hooksDir, { recursive: true });
  const hookPath = join(hooksDir, 'pre-commit');
  const block = hookBlock();

  if (!existsSync(hookPath)) {
    writeFileSync(hookPath, `#!/bin/sh\n${block}\n`);
    chmodSync(hookPath, 0o755);
    return { action: 'created', path: hookPath };
  }

  let existing = readFileSync(hookPath, 'utf8');

  // Already managed → replace our block in place (idempotent update).
  if (existing.includes(HOOK_BEGIN)) {
    const re = new RegExp(`${escapeRe(HOOK_BEGIN)}[\\s\\S]*?${escapeRe(HOOK_END)}`);
    existing = existing.replace(re, block);
    writeFileSync(hookPath, existing.endsWith('\n') ? existing : existing + '\n');
    chmodSync(hookPath, 0o755);
    return { action: 'updated', path: hookPath };
  }

  // Foreign hook present → back it up once, then append our guarded block.
  const backup = hookPath + '.leakhook-backup';
  if (!existsSync(backup)) writeFileSync(backup, existing);
  const sep = existing.endsWith('\n') ? '' : '\n';
  writeFileSync(hookPath, `${existing}${sep}\n${block}\n`);
  chmodSync(hookPath, 0o755);
  return { action: 'appended', path: hookPath, backup };
}

// Remove our block. If the hook becomes just a shebang, or a backup exists,
// clean up / restore accordingly.
export function uninstallHook(cwd = process.cwd()) {
  const dir = gitDir(cwd);
  const hookPath = join(cwd, dir, 'hooks', 'pre-commit');
  if (!existsSync(hookPath)) return { action: 'noop' };

  let content = readFileSync(hookPath, 'utf8');
  if (content.includes(HOOK_BEGIN)) {
    const re = new RegExp(`\\n?${escapeRe(HOOK_BEGIN)}[\\s\\S]*?${escapeRe(HOOK_END)}\\n?`);
    content = content.replace(re, '\n');
  }

  const stripped = content.replace(/^#!.*\n?/, '').trim();
  const backup = hookPath + '.leakhook-backup';

  if (stripped === '') {
    // Nothing left of substance.
    if (existsSync(backup)) {
      renameSync(backup, hookPath);
      chmodSync(hookPath, 0o755);
      return { action: 'restored', path: hookPath };
    }
    unlinkSync(hookPath);
    return { action: 'removed', path: hookPath };
  }

  writeFileSync(hookPath, content.endsWith('\n') ? content : content + '\n');
  chmodSync(hookPath, 0o755);
  return { action: 'cleaned', path: hookPath };
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

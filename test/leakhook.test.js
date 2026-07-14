// leakhook tests — node:test, zero deps.
//
// IMPORTANT: every secret-shaped sample below is CONSTRUCTED at runtime by
// string concatenation so that no static, scannable secret literal is ever
// written to disk. This keeps the repo clean for leakhook's own scanner and
// for any global pre-commit secret scanner.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanContent, forbiddenFilename, redact, rules } from '../src/index.js';

// Fake-but-shaped samples, assembled from pieces (never a whole literal).
const samples = {
  'aws-access-key-id': 'AKIA' + 'IOSFODNN7' + 'EXAMPLE', // canonical AWS example id
  'aws-secret-access-key': 'aws_secret_access_key=' + '"' + 'A'.repeat(40) + '"',
  'github-token': 'gh' + 'p_' + 'A'.repeat(36),
  'gitlab-token': 'glpat-' + 'x'.repeat(20),
  'stripe-secret-key': 'sk_' + 'live_' + '0'.repeat(24),
  'slack-token': 'xox' + 'b-' + '1'.repeat(12) + '-' + 'A'.repeat(12),
  'google-api-key': 'AIza' + 'B'.repeat(35),
  'private-key-block': '-----BEGIN ' + 'OPENSSH ' + 'PRIVATE KEY-----',
  'jwt': 'eyJ' + 'A'.repeat(12) + '.' + 'eyJ' + 'B'.repeat(12) + '.' + 'C'.repeat(12),
  'mongodb-uri-creds': 'mongodb' + '://' + 'user' + ':' + 'p4ss' + '@' + 'host/db',
  'generic-secret-assignment': 'password' + ' = ' + '"' + 'z'.repeat(16) + '"',
};

test('every rule flags its constructed sample', () => {
  for (const rule of rules) {
    const sample = samples[rule.id];
    assert.ok(sample, `no sample defined for rule ${rule.id}`);
    const findings = scanContent(sample, {});
    const ids = findings.map((f) => f.ruleId);
    assert.ok(ids.includes(rule.id), `rule ${rule.id} did not match its sample (got: ${ids.join(', ') || 'none'})`);
  }
});

test('clean text produces no findings', () => {
  const clean = [
    'const greeting = "hello world";',
    'function add(a, b) { return a + b; }',
    '// just a normal comment about tokens and passwords',
    'const shortValue = "abc";',
  ].join('\n');
  assert.deepEqual(scanContent(clean, { filename: 'src/app.js' }), []);
});

test('.env is blocked but .env.example is allowed', () => {
  assert.equal(forbiddenFilename('.env'), 'dotenv-file');
  assert.equal(forbiddenFilename('config/.env'), 'dotenv-file');
  assert.equal(forbiddenFilename('.env.production'), 'dotenv-file');
  assert.equal(forbiddenFilename('.env.example'), null);
  assert.equal(forbiddenFilename('.env.sample'), null);
  assert.equal(forbiddenFilename('.env.template'), null);
});

test('other forbidden filenames are caught', () => {
  assert.equal(forbiddenFilename('server.pem'), 'pem-file');
  assert.equal(forbiddenFilename('private.key'), 'key-file');
  assert.equal(forbiddenFilename('id_rsa'), 'ssh-private-key');
  assert.equal(forbiddenFilename('id_ed25519'), 'ssh-private-key');
  assert.equal(forbiddenFilename('my-service-account.json'), 'service-account-json');
  assert.equal(forbiddenFilename('gcp-credentials.json'), 'service-account-json');
  assert.equal(forbiddenFilename('package.json'), null);
});

test('filename scan surfaces as a finding via scanContent', () => {
  const findings = scanContent('SOME_KEY=value', { filename: '.env' });
  assert.ok(findings.some((f) => f.ruleId === 'dotenv-file'));
});

test('leakhook-allow inline marker skips a line', () => {
  const key = 'AKIA' + 'IOSFODNN7' + 'EXAMPLE';
  const withMarker = `const k = "${key}"; // leakhook-allow known-fake`;
  assert.deepEqual(scanContent(withMarker, {}), [], 'line with marker should be skipped');

  const withoutMarker = `const k = "${key}";`;
  assert.equal(scanContent(withoutMarker, {}).length, 1, 'same line without marker should flag');
});

test('redaction hides the middle of the match', () => {
  const key = 'AKIA' + 'IOSFODNN7' + 'EXAMPLE';
  const r = redact(key);
  assert.notEqual(r, key, 'redacted value must differ from original');
  assert.ok(r.includes('•'), 'redacted value should contain mask characters');
  assert.ok(r.startsWith(key.slice(0, 4)), 'keeps head for identification');
  assert.ok(r.endsWith(key.slice(-4)), 'keeps tail for identification');
  // The sensitive middle must not appear verbatim.
  const middle = key.slice(4, -4);
  assert.ok(!r.includes(middle), 'middle of the secret must be masked');
});

test('findings carry correct line numbers with startLine offset', () => {
  const key = 'gh' + 'p_' + 'A'.repeat(36);
  const text = ['line one', 'line two', `token = "${key}"`].join('\n');
  const findings = scanContent(text, { startLine: 10 });
  assert.ok(findings.length >= 1);
  const gh = findings.find((f) => f.ruleId === 'github-token');
  assert.equal(gh.line, 12, 'line 3 of text at startLine 10 => line 12');
});

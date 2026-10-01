import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkHeaders, checkPages, meetsThreshold, parseCookie, maskCookie, cookieName, safeText, schemeOf, CHECKS } from '../src/index.js';

// A response with every recommended header; each test removes or changes one thing.
const GOOD = [
  ['Content-Security-Policy', "default-src 'self'; object-src 'none'; frame-ancestors 'self'"],
  ['Strict-Transport-Security', 'max-age=31536000; includeSubDomains'],
  ['X-Content-Type-Options', 'nosniff'],
  ['Referrer-Policy', 'strict-origin-when-cross-origin'],
  ['Permissions-Policy', 'camera=()'],
  ['Set-Cookie', 'sid=abc; Secure; HttpOnly; SameSite=Lax']
];
const PAGE = 'https://www.example.com/';

function run(change, options = {}) {
  let headers = GOOD.map((h) => [...h]);
  if (change) headers = change(headers);
  return checkHeaders(headers, { url: PAGE, ...options });
}
const without = (name) => (h) => h.filter(([n]) => n.toLowerCase() !== name.toLowerCase());
const set = (name, value) => (h) => [...without(name)(h), [name, value]];
const ids = (r) => r.findings.map((f) => f.id);
const messages = (r) => r.findings.map((f) => f.message).join('\n');

test('a response with every recommended header has no findings', () => {
  assert.deepEqual(run().findings, []);
});

test('csp-missing is high, and Report-Only alone still counts as missing', () => {
  const r = run(without('content-security-policy'));
  assert.ok(ids(r).includes('csp-missing'));
  assert.equal(r.findings.find((f) => f.id === 'csp-missing').severity, 'high');
  const ro = run((h) => [...without('content-security-policy')(h), ['Content-Security-Policy-Report-Only', "default-src 'self'"]]);
  assert.match(messages(ro), /Report-Only is set, but it only reports/);
});

test('csp-unsafe: unsafe-inline, unsafe-eval and an open object-src', () => {
  const r = run(set('content-security-policy', "script-src 'self' 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'none'"));
  const csp = r.findings.filter((f) => f.id === 'csp-unsafe').map((f) => f.message);
  assert.equal(csp.length, 3);
  assert.ok(csp.some((m) => /unsafe-inline/.test(m)));
  assert.ok(csp.some((m) => /unsafe-eval/.test(m)));
  assert.ok(csp.some((m) => /object-src/.test(m)));
});

test('csp-unsafe: a policy without script-src or default-src leaves scripts unrestricted', () => {
  const r = run(set('content-security-policy', "img-src 'self'; object-src 'none'; frame-ancestors 'self'"));
  assert.match(messages(r), /scripts may load from anywhere/);
});

test('with two CSP headers, a weakness counts only when every policy has it', () => {
  const r = run((h) => [...without('content-security-policy')(h),
    ['Content-Security-Policy', "script-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'self'"],
    ['content-security-policy', "script-src 'self'"]]);
  assert.ok(!ids(r).includes('csp-unsafe'));
  const both = run((h) => [...without('content-security-policy')(h),
    ['Content-Security-Policy', "script-src 'unsafe-eval'; object-src 'none'; frame-ancestors 'self'"],
    ['Content-Security-Policy', "script-src 'unsafe-eval' 'self'"]]);
  assert.match(messages(both), /unsafe-eval/);
});

test('hsts-missing on https and when the URL is unknown, not on http', () => {
  assert.ok(ids(run(without('strict-transport-security'))).includes('hsts-missing'));
  const unknown = checkHeaders(without('strict-transport-security')(GOOD), {});
  assert.ok(ids(unknown).includes('hsts-missing'));
  assert.match(unknown.notes.join(' '), /assumed HTTPS/);
  const http = checkHeaders(without('strict-transport-security')(GOOD), { url: 'http://www.example.com/' });
  assert.ok(!ids(http).includes('hsts-missing'));
});

test('hsts-weak: short max-age is medium, no includeSubDomains is low, no max-age is high', () => {
  const short = run(set('strict-transport-security', 'max-age=300; includeSubDomains')).findings;
  assert.deepEqual(short.map((f) => [f.id, f.severity]), [['hsts-weak', 'medium']]);
  const noSub = run(set('strict-transport-security', 'max-age=31536000')).findings;
  assert.deepEqual(noSub.map((f) => [f.id, f.severity]), [['hsts-weak', 'low']]);
  const noAge = run(set('strict-transport-security', 'includeSubDomains')).findings;
  assert.equal(noAge[0].severity, 'high');
});

test('frame-missing: neither frame-ancestors nor X-Frame-Options; either one is enough', () => {
  const noFa = set('content-security-policy', "default-src 'self'; object-src 'none'");
  assert.ok(ids(run(noFa)).includes('frame-missing'));
  assert.ok(!ids(run((h) => [...noFa(h), ['X-Frame-Options', 'deny']])).includes('frame-missing'));
  assert.ok(ids(run((h) => [...noFa(h), ['X-Frame-Options', 'ALLOW-FROM https://example.org']])).includes('frame-missing'));
  assert.ok(ids(run(set('content-security-policy', "default-src 'self'; object-src 'none'; frame-ancestors *"))).includes('frame-missing'));
});

test('nosniff-missing when absent or misspelled', () => {
  assert.ok(ids(run(without('x-content-type-options'))).includes('nosniff-missing'));
  assert.match(messages(run(set('x-content-type-options', 'nosnif'))), /"nosnif", not nosniff/);
  assert.ok(!ids(run(set('x-content-type-options', 'NoSniff'))).includes('nosniff-missing'));
});

test('referrer-missing: absent, unsafe-url, no-referrer-when-downgrade; the last known value wins', () => {
  assert.ok(ids(run(without('referrer-policy'))).includes('referrer-missing'));
  assert.ok(ids(run(set('referrer-policy', 'unsafe-url'))).includes('referrer-missing'));
  assert.ok(ids(run(set('referrer-policy', 'no-referrer-when-downgrade'))).includes('referrer-missing'));
  assert.ok(!ids(run(set('referrer-policy', 'unsafe-url, made-up-value, no-referrer'))).includes('referrer-missing'));
  assert.ok(ids(run(set('referrer-policy', 'no-referrer, unsafe-url'))).includes('referrer-missing'));
});

test('permissions-missing, with a note when only Feature-Policy is set', () => {
  const r = run((h) => [...without('permissions-policy')(h), ['Feature-Policy', "camera 'none'"]]);
  assert.ok(ids(r).includes('permissions-missing'));
  assert.match(messages(r), /Feature-Policy is set/);
});

test('cookie-flags: Secure is medium, HttpOnly and SameSite are low, SameSite=None without Secure is medium', () => {
  const r = run(set('set-cookie', 'pref=dark; SameSite=None'));
  const found = r.findings.filter((f) => f.id === 'cookie-flags').map((f) => `${f.severity}: ${f.message}`);
  assert.deepEqual(found.sort(), [
    'low: cookie pref: no HttpOnly flag',
    'medium: cookie pref: SameSite=None without Secure (browsers reject it)',
    'medium: cookie pref: no Secure flag'
  ]);
  const many = run((h) => [...h, ['set-cookie', 'a=1; Secure; HttpOnly'], ['SET-COOKIE', 'b=2; Secure; HttpOnly; SameSite=Strict']]);
  assert.deepEqual(many.findings.map((f) => f.message), ['cookie a: no SameSite attribute']);
});

test('cookie values are masked: only the name is ever kept', () => {
  assert.equal(maskCookie('token=eyJhbGciOi.secret.value; Secure'), 'token=***');
  assert.equal(cookieName('=only-value'), '(no name)');
  const c = parseCookie('token=eyJhbGciOi.secret.value; secure; HTTPONLY; samesite=strict');
  assert.deepEqual(c, { name: 'token', secure: true, httpOnly: true, sameSite: 'strict' });
  const r = run(set('set-cookie', 'token=eyJhbGciOi.secret.value'));
  assert.doesNotMatch(JSON.stringify(r), /eyJhbGciOi|secret\.value/);
});

test('server-leak only when a version number is shown', () => {
  const r = run((h) => [...h, ['Server', 'nginx/1.25.3'], ['X-Powered-By', 'Express'], ['X-AspNet-Version', '4.0.30319']]);
  const leaks = r.findings.filter((f) => f.id === 'server-leak').map((f) => f.message);
  assert.equal(leaks.length, 2);
  assert.ok(!ids(run((h) => [...h, ['Server', 'nginx']])).includes('server-leak'));
});

test('deprecated: X-XSS-Protection other than 0, Expect-CT, Public-Key-Pins', () => {
  assert.ok(!ids(run((h) => [...h, ['X-XSS-Protection', '0']])).includes('deprecated'));
  const r = run((h) => [...h, ['X-XSS-Protection', '1; mode=block'], ['Expect-CT', 'max-age=0'], ['Public-Key-Pins', 'pin-sha256="x"; max-age=10']]);
  assert.equal(r.findings.filter((f) => f.id === 'deprecated' && f.severity === 'info').length, 3);
});

test('cache-sensitive only with --sensitive', () => {
  assert.ok(!ids(run()).includes('cache-sensitive'));
  assert.ok(ids(run(null, { sensitive: true })).includes('cache-sensitive'));
  assert.ok(!ids(run((h) => [...h, ['Cache-Control', 'private, no-store']], { sensitive: true })).includes('cache-sensitive'));
});

test('header names are case-insensitive', () => {
  const lower = GOOD.map(([n, v]) => [n.toLowerCase(), v]);
  const upper = GOOD.map(([n, v]) => [n.toUpperCase(), v]);
  assert.deepEqual(checkHeaders(lower, { url: PAGE }).findings, []);
  assert.deepEqual(checkHeaders(upper, { url: PAGE }).findings, []);
});

test('findings are sorted by severity, every check id is known, and the threshold works', () => {
  const report = checkPages([{ source: 'x', url: PAGE, status: 200, headers: [], notes: [] }]);
  const known = new Set(CHECKS.map((c) => c.id));
  const sev = report.pages[0].findings.map((f) => f.severity);
  assert.equal(sev[0], 'high');
  assert.ok(report.pages[0].findings.every((f) => known.has(f.id)));
  assert.ok(meetsThreshold(report, 'high'));
  const lowOnly = checkPages([{ url: PAGE, headers: without('permissions-policy')(GOOD), notes: [] }]);
  assert.ok(!meetsThreshold(lowOnly, 'medium'));
  assert.ok(meetsThreshold(lowOnly, 'low'));
  assert.ok(!meetsThreshold(lowOnly, null));
});

test('safeText removes control characters and caps length; schemeOf reads the scheme', () => {
  assert.equal(safeText('nginx\u001b[31m'), 'nginx [31m');
  assert.equal(safeText('x'.repeat(10), 4), 'xxxx...');
  assert.equal(schemeOf('HTTPS://a.example'), 'https');
  assert.equal(schemeOf('http://a.example'), 'http');
  assert.equal(schemeOf(null), null);
});

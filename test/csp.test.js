import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePolicy, parseCsp, scriptSources, hasNonceOrHash, scriptWeaknesses, objectSrcIsNone, frameAncestors } from '../src/index.js';

test('parsePolicy: case-insensitive names, first duplicate wins, empty parts skipped', () => {
  const p = parsePolicy("  Script-SRC 'self' ;; script-src *; DEFAULT-src 'none' ;");
  assert.deepEqual([...p.keys()], ['script-src', 'default-src']);
  assert.deepEqual(p.get('script-src'), ["'self'"]);
  assert.deepEqual(p.get('default-src'), ["'none'"]);
});

test('parseCsp: several headers and comma-separated policies become separate policies', () => {
  const policies = parseCsp(["default-src 'self', script-src 'none'", "object-src 'none'"]);
  assert.equal(policies.length, 3);
  assert.deepEqual(parseCsp(''), []);
  assert.deepEqual(parseCsp(' ; , ;'), []);
});

test('scriptSources falls back from script-src to default-src, and to null', () => {
  assert.equal(scriptSources(parsePolicy("default-src 'self'; script-src 'none'")).directive, 'script-src');
  assert.equal(scriptSources(parsePolicy("default-src 'self'")).directive, 'default-src');
  assert.equal(scriptSources(parsePolicy("img-src *")), null);
});

test('unsafe-inline is a weakness only without a nonce or hash', () => {
  assert.deepEqual(scriptWeaknesses(["'self'", "'UNSAFE-INLINE'"]), ["'unsafe-inline' without a nonce or hash"]);
  assert.ok(hasNonceOrHash(["'nonce-abc'"]));
  assert.ok(hasNonceOrHash(["'sha256-xyz='"]));
  assert.deepEqual(scriptWeaknesses(["'unsafe-inline'", "'sha384-abc'"]), []);
});

test('unsafe-eval, a bare star, http: and data: sources are weaknesses; https hosts are not', () => {
  const w = scriptWeaknesses(["'unsafe-eval'", '*', 'http://cdn.example.com', 'data:']);
  assert.equal(w.length, 4);
  assert.deepEqual(scriptWeaknesses(['https://cdn.example.com', '*.example.com']), []);
  assert.deepEqual(scriptWeaknesses(['http:']), ['http: (unencrypted) sources']);
});

test('weakness labels never echo a nonce value', () => {
  const w = scriptWeaknesses(["'unsafe-eval'", "'nonce-SECRETNONCE'"]).join(' ');
  assert.doesNotMatch(w, /SECRETNONCE/);
});

test("objectSrcIsNone needs exactly 'none' in object-src, or in default-src when object-src is absent", () => {
  assert.ok(objectSrcIsNone(parsePolicy("object-src 'none'")));
  assert.ok(objectSrcIsNone(parsePolicy("default-src 'none'; script-src 'self'")));
  assert.ok(!objectSrcIsNone(parsePolicy("default-src 'none'; object-src 'self'")));
  assert.ok(!objectSrcIsNone(parsePolicy("default-src 'self'")));
  assert.ok(!objectSrcIsNone(parsePolicy("script-src 'self'")));
});

test('frameAncestors finds the directive in any policy', () => {
  assert.deepEqual(frameAncestors(parseCsp(["default-src 'self'", "frame-ancestors 'none'"])), ["'none'"]);
  assert.equal(frameAncestors(parseCsp("default-src 'self'")), null);
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, truncate, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseDump, parseHar, loadFile, headerValues, firstHeader, LIMITS } from '../src/index.js';

test('parseDump reads a curl -I dump: status, headers, repeated headers, CRLF', () => {
  const [page] = parseDump('HTTP/1.1 200 OK\r\nServer: nginx\r\nSet-Cookie: a=1\r\nset-cookie: b=2\r\n\r\n');
  assert.equal(page.status, 200);
  assert.equal(page.url, null);
  assert.deepEqual(headerValues(page.headers, 'SET-COOKIE'), ['a=1', 'b=2']);
  assert.equal(firstHeader(page.headers, 'server'), 'nginx');
  assert.equal(firstHeader(page.headers, 'x-missing'), null);
});

test('parseDump keeps only the last response of a redirect chain', () => {
  const [page] = parseDump([
    'HTTP/1.1 301 Moved Permanently', 'Location: https://www.example.com/', 'Server: old/1.0', '',
    'HTTP/2 200', 'content-type: text/html', 'x-last: yes', ''
  ].join('\n'));
  assert.equal(page.status, 200);
  assert.equal(firstHeader(page.headers, 'server'), null);
  assert.equal(firstHeader(page.headers, 'x-last'), 'yes');
  assert.match(page.notes.join(' '), /2 responses/);
});

test('parseDump reads a "# url:" line, joins folded lines, and ignores header lines over 16 KB', () => {
  const long = `X-Long: ${'a'.repeat(LIMITS.maxLineBytes + 1)}`;
  const [page] = parseDump(`# url: https://www.example.org/\nHTTP/1.1 200 OK\nX-Folded: one\n two\n${long}\nX-After: ok\n`);
  assert.equal(page.url, 'https://www.example.org/');
  assert.equal(firstHeader(page.headers, 'x-folded'), 'one two');
  assert.equal(firstHeader(page.headers, 'x-long'), null);
  assert.equal(firstHeader(page.headers, 'x-after'), 'ok');
  assert.match(page.notes.join(' '), /over 16 KB ignored/);
  assert.throws(() => parseDump('just some text\n'), /no status line/);
});

const entry = (url, mime, headers = []) => ({ request: { url }, response: { status: 200, headers, content: { mimeType: mime } } });

test('parseHar checks only text/html entries unless all entries are asked for', () => {
  const har = JSON.stringify({ log: { entries: [
    entry('https://www.example.com/', 'text/html; charset=utf-8', [{ name: 'Server', value: 'x' }, { name: ':status', value: '200' }]),
    entry('https://www.example.com/app.js', 'application/javascript'),
    entry('https://www.example.com/old', 'TEXT/HTML')
  ] } });
  const pages = parseHar(har);
  assert.deepEqual(pages.map((p) => p.url), ['https://www.example.com/', 'https://www.example.com/old']);
  assert.deepEqual(pages[0].headers, [['Server', 'x']]);
  assert.equal(parseHar(har, { allEntries: true }).length, 3);
  assert.throws(() => parseHar(JSON.stringify({ log: { entries: [entry('https://a.example/', 'image/png')] } })), /--all-entries/);
  assert.throws(() => parseHar('{"log": {}}'), /log\.entries/);
  assert.throws(() => parseHar('{oops'), /not valid JSON/);
});

test('parseHar reads at most 10,000 entries and says so', () => {
  const entries = Array.from({ length: LIMITS.maxEntries + 5 }, (_, i) => entry(`https://www.example.com/${i}`, 'text/html'));
  const pages = parseHar(JSON.stringify({ log: { entries } }));
  assert.equal(pages.length, LIMITS.maxEntries);
  assert.match(pages[0].notes.join(' '), /10005 entries in the file; only the first 10000 are read/);
});

test('parseHar ignores headers over 16 KB and never treats a field as a path', () => {
  const big = { name: 'X-Big', value: 'b'.repeat(LIMITS.maxLineBytes + 1) };
  const har = { log: { entries: [{ ...entry('https://www.example.com/', 'text/html', [big, { name: 'X-Ok', value: '1' }]),
    _file: '../../etc/passwd', response: { status: 200, headers: [big, { name: 'X-Ok', value: '1' }], content: { mimeType: 'text/html', _path: '/etc/passwd' } } }] } };
  const [page] = parseHar(JSON.stringify(har));
  assert.deepEqual(page.headers, [['X-Ok', '1']]);
  assert.match(page.notes.join(' '), /1 header\(s\) over 16 KB ignored/);
});

test('loadFile refuses files over 20 MB, folders and missing files', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'shc-'));
  try {
    const big = join(dir, 'big.txt');
    await writeFile(big, 'HTTP/1.1 200 OK\n');
    await truncate(big, LIMITS.maxFileBytes + 1);
    await assert.rejects(loadFile(big), /over the 20 MB limit/);
    await mkdir(join(dir, 'folder'));
    await assert.rejects(loadFile(join(dir, 'folder')), /not a file/);
    await assert.rejects(loadFile(join(dir, 'missing.txt')), { code: 'ENOENT' });
    const har = join(dir, 'no-extension');
    await writeFile(har, JSON.stringify({ log: { entries: [entry('https://www.example.com/', 'text/html')] } }));
    const pages = await loadFile(har);
    assert.equal(pages[0].source, har);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

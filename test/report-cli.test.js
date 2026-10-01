import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { parseArgs, main, toMarkdown, toCsv, toText, toJson, csvCell, mdCell, VERSION } from '../src/index.js';

const root = join(fileURLToPath(import.meta.url), '..', '..');
const ex = (p) => join(root, 'examples', p);
const quiet = { out: () => {}, err: () => {} };

async function capture(argv) {
  let out = '';
  let err = '';
  const code = await main(argv, { out: (t) => { out += t; }, err: (t) => { err += t; } });
  return { code, out, err };
}

test('parseArgs reads options and refuses bad input', () => {
  const o = parseArgs(['--format', 'csv', '--fail-on', 'medium', '--all-entries', '--sensitive', 'a.txt', 'b.har']);
  assert.deepEqual(o.files, ['a.txt', 'b.har']);
  assert.equal(o.format, 'csv');
  assert.equal(o.failOn, 'medium');
  assert.ok(o.allEntries && o.sensitive);
  assert.deepEqual(parseArgs(['--', '--odd-name.txt']).files, ['--odd-name.txt']);
  assert.throws(() => parseArgs([]), /at least one file/);
  assert.throws(() => parseArgs(['--format', 'xml', 'a']), /unknown format/);
  assert.throws(() => parseArgs(['--fail-on', 'info', 'a']), /high, medium or low/);
  assert.throws(() => parseArgs(['--fail-on']), /needs a value/);
  assert.throws(() => parseArgs(['--fetch', 'a']), /unknown argument/);
  assert.throws(() => parseArgs(['-']), /standard input/);
});

test('exit codes: 0 by default, 1 at the --fail-on threshold, 2 on usage or input errors', async () => {
  assert.equal(await main([ex('weak.txt')], quiet), 0);
  assert.equal(await main(['--fail-on', 'high', ex('weak.txt')], quiet), 1);
  assert.equal(await main(['--fail-on', 'high', ex('redirect.txt')], quiet), 0);
  assert.equal(await main(['--fail-on', 'medium', ex('redirect.txt')], quiet), 1);
  assert.equal(await main(['--fail-on', 'low', ex('good.txt')], quiet), 0);
  assert.equal(await main(['missing.txt'], quiet), 2);
  assert.equal(await main(['--nope'], quiet), 2);
  assert.equal(await main(['--help'], quiet), 0);
  const v = await capture(['--version']);
  assert.equal(v.out.trim(), VERSION);
});

test('several files in one run: dumps and a HAR', async () => {
  const { code, out } = await capture(['--format', 'json', ex('good.txt'), ex('redirect.txt'), ex('pages.har')]);
  assert.equal(code, 0);
  const r = JSON.parse(out);
  assert.equal(r.pages.length, 3);
  assert.equal(r.pages[0].findings.length, 0);
  assert.equal(r.pages[2].url, 'https://app.example.com/login');
  const all = JSON.parse((await capture(['--format', 'json', '--all-entries', ex('pages.har')])).out);
  assert.equal(all.pages.length, 2);
  assert.ok(all.pages[1].findings.some((f) => f.id === 'server-leak'));
});

test('a cookie value never appears in any output format', async () => {
  for (const format of ['text', 'markdown', 'json', 'csv']) {
    const { out } = await capture(['--format', format, ex('weak.txt'), ex('good.txt'), ex('pages.har')]);
    assert.match(out, /sid/, format);
    for (const secret of ['s3cr3t-c00kie-v4lue', 'abc123', 'f3a9c1d7e2b8', '9b1f0e2d44']) {
      assert.ok(!out.includes(secret), `${format} shows a cookie value`);
    }
  }
});

test('CSV quotes per RFC 4180 and neutralises formula cells', () => {
  assert.equal(csvCell('plain'), 'plain');
  assert.equal(csvCell('a,b'), '"a,b"');
  assert.equal(csvCell('say "hi"'), '"say ""hi"""');
  assert.equal(csvCell('line\nbreak'), '"line\nbreak"');
  assert.equal(csvCell('=HYPERLINK("x")'), '"\'=HYPERLINK(""x"")"');
  assert.equal(csvCell('+1'), "'+1");
  assert.equal(csvCell('-2'), "'-2");
  assert.equal(csvCell('@SUM(A1)'), "'@SUM(A1)");
  assert.equal(csvCell(null), '');
  const report = { counts: { high: 0, medium: 1, low: 0, info: 0 }, pages: [{ source: 'f.txt', url: null, status: 200, notes: [],
    findings: [{ id: 'server-leak', severity: 'medium', message: '=cmd|x, "y"', fix: 'a\nb' }] }] };
  const csv = toCsv(report);
  assert.ok(csv.startsWith('file,url,status,severity,check,problem,fix\r\n'));
  assert.ok(csv.includes(`"'=cmd|x, ""y"""`));
});

test('Markdown escapes pipes and line breaks so a header value cannot break the table', () => {
  assert.equal(mdCell('a|b\nc'), 'a\\|b c');
  const report = { counts: { high: 0, medium: 1, low: 0, info: 0 }, pages: [{ source: 'f|g.txt', url: null, status: null, notes: ['n|1'],
    findings: [{ id: 'server-leak', severity: 'medium', message: 'Server: x|y\r\nz', fix: 'f' }] }] };
  const md = toMarkdown(report);
  assert.match(md, /x\\\|y z/);
  const rows = md.split('\n').filter((l) => l.startsWith('| medium'));
  assert.equal(rows.length, 1);
  assert.equal(rows[0].split(/(?<!\\)\|/).length, 6);
});

test('text and JSON reports carry the gate result', async () => {
  const { code, out } = await capture(['--fail-on', 'high', ex('weak.txt')]);
  assert.equal(code, 1);
  assert.match(out, /GATE: FAIL - a finding at high or above/);
  const empty = { counts: { high: 0, medium: 0, low: 0, info: 0 }, pages: [{ source: 'a', url: 'https://www.example.com/', status: 200, notes: [], findings: [] }], gate: { pass: true } };
  assert.match(toText(empty), /no problems found[\s\S]*GATE: PASS/);
  assert.deepEqual(JSON.parse(toJson(empty)), empty);
});

test('a bad HAR and a missing file give exit code 2 with a message', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'shc-cli-'));
  try {
    const bad = join(dir, 'bad.har');
    await writeFile(bad, '{"log": {"entries": "nope"}}');
    const r = await capture([bad]);
    assert.equal(r.code, 2);
    assert.match(r.err, /log\.entries is missing/);
    const missing = await capture([join(dir, 'none.txt')]);
    assert.match(missing.err, /no such file/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

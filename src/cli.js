// Command line: security-headers-check [options] <file>...

import { readFileSync } from 'node:fs';
import { loadFile } from './load.js';
import { checkPages, meetsThreshold, CHECKS } from './checks.js';
import { toText, toMarkdown, toJson, toCsv } from './report.js';

const FORMATS = { text: toText, markdown: toMarkdown, json: toJson, csv: toCsv };
const THRESHOLDS = ['high', 'medium', 'low'];

export const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;

export const USAGE = `Usage: security-headers-check [options] <file>...

Reads saved HTTP response headers and reports security header problems, following the
OWASP Secure Headers Project. Each file is a raw header dump (curl -s -D - -o /dev/null URL,
or curl -I) or a HAR file. Reads files only; it never opens a network connection.

Options:
  --format <name>      text, markdown, json or csv (default: text)
  --fail-on <level>    exit with 1 when a finding is at this level or above: high, medium or low
  --all-entries        in a HAR file, check every response, not only text/html pages
  --sensitive          the pages hold private data: also require Cache-Control: no-store
  --help               show this text
  --version            show the version

Checks: ${CHECKS.map((c) => c.id).join(', ')}

Exit codes: 0 done, 1 --fail-on threshold met, 2 usage or input error.
`;

export function parseArgs(argv) {
  const o = { files: [], format: 'text', failOn: null, allEntries: false, sensitive: false, help: false, version: false };
  let rest = false;
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    const next = () => {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) throw new Error(`${a} needs a value`);
      i += 1;
      return v;
    };
    if (rest || !a.startsWith('-') || a === '-') {
      if (a === '-') throw new Error('reading from standard input is not supported; save the headers to a file');
      o.files.push(a);
    } else if (a === '--') rest = true;
    else if (a === '--help' || a === '-h') o.help = true;
    else if (a === '--version' || a === '-v') o.version = true;
    else if (a === '--format') o.format = next();
    else if (a === '--fail-on') o.failOn = next();
    else if (a === '--all-entries') o.allEntries = true;
    else if (a === '--sensitive') o.sensitive = true;
    else throw new Error(`unknown argument ${a}`);
  }
  if (!o.help && !o.version) {
    if (!o.files.length) throw new Error('give at least one file with saved headers');
    if (!FORMATS[o.format]) throw new Error(`unknown format ${o.format} (text, markdown, json or csv)`);
    if (o.failOn !== null && !THRESHOLDS.includes(o.failOn)) throw new Error(`--fail-on takes high, medium or low, not ${o.failOn}`);
  }
  return o;
}

// Exit code: 0 done (and gate passed), 1 a finding at or above --fail-on, 2 usage or input error.
export async function main(argv, io = { out: (t) => process.stdout.write(t), err: (t) => process.stderr.write(t) }) {
  let o;
  try {
    o = parseArgs(argv);
  } catch (error) {
    io.err(`security-headers-check: ${error.message}\n\n${USAGE}`);
    return 2;
  }
  if (o.help) {
    io.out(USAGE);
    return 0;
  }
  if (o.version) {
    io.out(`${VERSION}\n`);
    return 0;
  }
  const pages = [];
  try {
    for (const file of o.files) pages.push(...(await loadFile(file, { allEntries: o.allEntries })));
  } catch (error) {
    io.err(`security-headers-check: ${error.code === 'ENOENT' ? `${error.path}: no such file` : error.message}\n`);
    return 2;
  }
  const report = checkPages(pages, { sensitive: o.sensitive });
  if (o.failOn) {
    const fail = meetsThreshold(report, o.failOn);
    report.gate = { failOn: o.failOn, pass: !fail, reason: fail ? `a finding at ${o.failOn} or above` : '' };
  }
  io.out(FORMATS[o.format](report));
  return report.gate && !report.gate.pass ? 1 : 0;
}

// Runs the README example and checks that it reports what the README shows.

import { main } from '../src/index.js';

let out = '';
const files = ['examples/good.txt', 'examples/weak.txt', 'examples/redirect.txt', 'examples/pages.har'];
const code = await main(files, { out: (t) => { out += t; }, err: (t) => process.stderr.write(t) });
process.stdout.write(out);
const expected = [
  '4 page(s), 21 finding(s): 1 high, 9 medium, 10 low, 1 info',
  'examples/good.txt  https://www.example.com/  (200)\n  no problems found',
  'csp-missing          no Content-Security-Policy header (Content-Security-Policy-Report-Only is set',
  'cookie sid: no Secure flag',
  'Server: Apache/2.4.41 (Ubuntu) names a version',
  '3 responses in the file (redirects); the last one is checked',
  "script-src allows 'unsafe-inline' without a nonce or hash",
  'cookie csrf: no HttpOnly flag'
];
const missing = expected.filter((e) => !out.includes(e));
// The made-up cookie values must never reach the report.
const leaked = ['s3cr3t-c00kie-v4lue', 'abc123', 'f3a9c1d7e2b8', '9b1f0e2d44'].filter((v) => out.includes(v));
if (code !== 0 || missing.length || leaked.length) {
  console.error(`example: unexpected report (exit code ${code}; missing: ${missing.join(' / ') || 'none'}; cookie values shown: ${leaked.join(' / ') || 'none'})`);
  process.exit(1);
}

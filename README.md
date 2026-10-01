# security-headers-check

Checks the security headers of your web pages from saved responses, without sending a single request.

Most attacks on a web page that a header can stop are stopped by a handful of them: a Content-Security-Policy that blocks injected scripts, Strict-Transport-Security that keeps the browser on HTTPS, a rule against framing, `nosniff`, a referrer policy, a permissions policy, and the right flags on cookies. They are easy to forget and easy to weaken by accident. This tool reads the response headers you saved, with `curl` or from the browser's network panel as a HAR file, and reports what is missing or weak, following the [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/).

- Every finding has a check id, a severity (high, medium, low, info), the problem and the fix.
- Cookie values are never shown, in any format: only cookie names are reported.
- It reads the files you give it and nothing else. It opens no network connection and runs nothing.
- Plain JavaScript, no dependencies; the same files always give the same report.

```
npm test
```

```
ℹ tests 42
ℹ pass 42
ℹ fail 0
```

## Quick start

Requires Node 22 or newer. There is nothing to install.

```
git clone https://github.com/INNERLUXES/security-headers-check.git
cd security-headers-check
node bin/security-headers-check.js examples/redirect.txt examples/pages.har
```

Or without a clone:

```
npx --yes github:INNERLUXES/security-headers-check headers.txt
```

```
security-headers-check: 2 page(s), 5 finding(s): 0 high, 3 medium, 2 low, 0 info

examples/redirect.txt  (URL unknown)  (200)
  note: 3 responses in the file (redirects); the last one is checked
  note: URL unknown: assumed HTTPS, so HSTS and the Secure flag are checked
  MEDIUM  csp-unsafe           script-src allows 'unsafe-inline' without a nonce or hash
                               fix: remove it; use nonces or hashes for inline scripts and list only the hosts you load scripts from
  MEDIUM  csp-unsafe           script-src allows 'unsafe-eval'
                               fix: remove it; use nonces or hashes for inline scripts and list only the hosts you load scripts from
  MEDIUM  csp-unsafe           object-src is not 'none' (plugins can run content)
                               fix: add object-src 'none'
  LOW     hsts-weak            Strict-Transport-Security without includeSubDomains
                               fix: add includeSubDomains once every subdomain serves HTTPS

examples/pages.har  https://app.example.com/login  (200)
  LOW     cookie-flags         cookie csrf: no HttpOnly flag
                               fix: add HttpOnly unless page scripts must read this cookie
```

`examples/weak.txt` is a made-up shop page with most of the problems at once; `examples/good.txt` is a page with none.

## Saving the headers

A raw dump from `curl`:

```
curl -s -D - -o /dev/null https://www.example.com/ > headers.txt
curl -s -I https://www.example.com/ > headers.txt
```

With `-L`, the file holds every response of a redirect chain; the last one is the page, and only that one is checked. `curl` does not write the address into the file, so the tool assumes HTTPS and says so. To give it the address, put a comment line first:

```
{ echo "# url: https://www.example.com/"; curl -s -D - -o /dev/null https://www.example.com/; } > headers.txt
```

A HAR file: in the browser's developer tools, open the Network panel, load the page and save all as HAR. Only responses with a `text/html` content type are checked, since those are the pages; `--all-entries` checks every response. A HAR file can hold cookies and tokens of your session: keep it private and delete it after the check.

## Checks

| Id | Severity | What it reports |
| --- | --- | --- |
| `csp-missing` | high | No Content-Security-Policy. A Report-Only policy alone counts as missing, since it blocks nothing |
| `csp-unsafe` | medium | Scripts allowed with `'unsafe-inline'` (without a nonce or hash), `'unsafe-eval'`, `*`, `http:` or `data:`; no script restriction at all; `object-src` not `'none'` |
| `hsts-missing` | high | No Strict-Transport-Security on an HTTPS page |
| `hsts-weak` | medium / low | `max-age` below one year (medium), no `includeSubDomains` (low), no valid `max-age` (high) |
| `frame-missing` | medium | Neither CSP `frame-ancestors` nor `X-Frame-Options: DENY` or `SAMEORIGIN` |
| `nosniff-missing` | medium | `X-Content-Type-Options` is not exactly `nosniff` |
| `referrer-missing` | low | No Referrer-Policy, or `unsafe-url` / `no-referrer-when-downgrade` |
| `permissions-missing` | low | No Permissions-Policy |
| `cookie-flags` | medium / low | A cookie without `Secure` (medium), `SameSite=None` without `Secure` (medium), without `HttpOnly` (low), without `SameSite` (low) |
| `server-leak` | low | `Server`, `X-Powered-By`, `X-AspNet-Version` or `X-AspNetMvc-Version` with a version number |
| `deprecated` | info | `X-XSS-Protection` other than `0`, `Expect-CT`, `Public-Key-Pins` |
| `cache-sensitive` | info | With `--sensitive` only: no `Cache-Control: no-store` |

[docs/method.md](docs/method.md) gives the OWASP source and the reason for each check.

## Options

```
--format <name>      text, markdown, json or csv (default: text)
--fail-on <level>    exit with 1 when a finding is at this level or above: high, medium or low
--all-entries        in a HAR file, check every response, not only text/html pages
--sensitive          the pages hold private data: also require Cache-Control: no-store
--help               show the usage
--version            show the version
```

Several files can be given in one run; each page is reported on its own.

## Formats

- `text`: for a terminal, grouped by page.
- `markdown`: one table per page, for a pull request or a ticket. Pipes and line breaks in header values are escaped, so a header cannot break the table.
- `json`: the whole report, for other tools.
- `csv`: one row per finding, quoted as RFC 4180 says. A cell that starts with `=`, `+`, `-` or `@` gets a leading `'`, so a spreadsheet does not run it as a formula.

## Exit codes

`0` done, `1` a finding at or above `--fail-on`, `2` a usage or input error (a missing file, a file over 20 MB, a broken HAR). Without `--fail-on` the tool reports and exits with `0`.

## In a pipeline

Save the headers of a staging page, then fail the job on any high finding:

```yaml
- name: Save the response headers
  run: |
    { echo "# url: https://staging.example.com/"; curl -s -D - -o /dev/null https://staging.example.com/; } > headers.txt
- name: Check the security headers
  run: npx --yes github:INNERLUXES/security-headers-check --fail-on high --format markdown headers.txt >> "$GITHUB_STEP_SUMMARY"
```

The request is made by `curl` in your pipeline, not by this tool.

## Limits

Saved headers show one response, at one moment, for one user. A CSP set in a `<meta>` tag, headers that differ per page, per user or per region, headers a CDN adds or removes, and nonces that change on every response are not visible in them. [docs/limits.md](docs/limits.md) lists these. The tool checks headers; it does not test the site itself.

## Background

- How web applications are built with secure defaults from the first release: [web development](https://innerluxes.dev/web-development).

## License

MIT

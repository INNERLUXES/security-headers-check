# Secure defaults

The default run is the safe run. Nothing below needs a flag, and none of it can be switched off.

## How the tool behaves by default

- **Cookie values are never shown.** A `Set-Cookie` header is reported by its name only. Everything after the first `=` is dropped before a finding is made, so no format (text, Markdown, JSON or CSV) can show a session token, even by mistake. Tests run every format against made-up cookie values and fail if one appears.
- **No network.** The tool reads the files it is given and sends nothing anywhere. It does not fetch the addresses it finds in a dump or a HAR file. It can run where the saved files already are, on a laptop or in a locked-down build job, with no outbound access at all.
- **No dependencies.** Node 22 or newer and nothing else, so there is no third-party code that could read a HAR file full of session cookies.
- **Nothing is executed.** No part of the input is run, evaluated or used as a path. A HAR file is parsed as JSON data; a header dump is read line by line.
- **Bounded input.** Files over 20 MB are refused before they are read. Header lines over 16 KB are ignored. At most 10,000 HAR entries are read. The report says when lines or entries were skipped, so a cut is never silent.
- **Clean output.** Header text shown in a report has control characters removed and its length capped, so a hostile header cannot rewrite the terminal. Markdown cells escape pipes and line breaks. CSV cells are quoted as RFC 4180 says, and a cell that a spreadsheet would read as a formula gets a leading `'`.
- **Fails closed.** A missing file, a file over the limit, a dump with no headers, or a HAR file without entries stops the run with exit code 2 and the file name, instead of a clean report about nothing.
- **Assumes the stricter case.** When the page address is unknown, the tool assumes HTTPS, so HSTS and the `Secure` cookie flag are checked rather than skipped, and the report says so.
- **Writes nothing to disk.** The report goes to the screen. Redirect it to a file only when you need to keep it.

## Saving headers safely

1. Prefer a raw dump from `curl -s -D - -o /dev/null <address>` over a HAR file. A dump of an anonymous request holds only the headers the server sends to a visitor who is not logged in.
2. When you need the logged-in pages, use a test account, not a real user's session, and save the HAR from a private browser window that holds nothing else.
3. Keep HAR files out of version control. They hold cookies and tokens of the session they were recorded in. The `.gitignore` of your own project should cover them if you keep them nearby.
4. Delete the HAR file when the check is done, or log the test account out so its session cookies stop working.

## Sharing a report safely

1. Share the Markdown or text report, not the saved headers. The report shows cookie names and header names, never cookie values.
2. Read the report before sharing it outside the team. Addresses are shown as they were saved: an address with a private query string (a reset token, an email address) stays in the report. Save the headers of an address without one.
3. A `server-leak` finding shows the version from the `Server` or `X-Powered-By` header. That is the point of the finding, but it also tells a reader which software runs the site; keep reports with open findings inside the team until the version is removed.

## Using it as a gate

1. Start with `--fail-on high` so that only a missing CSP, missing HSTS or an HSTS header that browsers ignore fails the build.
2. Move to `--fail-on medium` once the high findings are fixed; that adds unsafe CSP sources, framing, `nosniff` and session cookie flags.
3. Keep `--fail-on low` for sites where every header is under your control; some low findings (a cookie that scripts must read) are deliberate.
4. Check the pages that matter, not only the home page: the login page, a logged-in page, an error page and any page that sets cookies. Use `--sensitive` for pages that show private data, so `Cache-Control: no-store` is required on them.
5. Save the headers in the same job that runs the check, so the report describes the build being shipped and not an old file.

## Headers this tool recommends

The fix in each finding points to the OWASP Secure Headers Project recommendation. A starting point for a page with no third-party scripts:

```
Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Set-Cookie: session=<value>; Path=/; Secure; HttpOnly; SameSite=Lax
```

Add hosts, nonces or hashes to the policy only for what the page really loads, and test the policy in report-only mode before it is enforced.

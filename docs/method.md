# Method

Every check follows a recommendation of the [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/) and, where the project points to one, the [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html), the [Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) or the [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).

## Reading the input

1. **Raw dump.** Lines that start with `HTTP/` and a status code begin a response. Every `Name: value` line after it is a header. When the file holds several responses (a redirect chain saved with `curl -L -D -`), only the last one is the page, so only the last one is checked. A first line `# url: <address>` gives the page address; without it the address is unknown.
2. **HAR.** `log.entries[]` is read; for each entry the address comes from `request.url` and the headers from `response.headers`. Only entries whose `response.content.mimeType` is `text/html` are pages, so only those are checked unless `--all-entries` is given. HTTP/2 pseudo headers such as `:status` are skipped.
3. **Names.** Header names are compared without regard to case, as HTTP requires. A header that appears several times keeps every value (every `Set-Cookie`, every CSP).

## The checks

| Id | Severity | OWASP source | Why |
| --- | --- | --- | --- |
| `csp-missing` | high | Secure Headers Project: Content-Security-Policy | Without a policy, any injected script runs with the page's rights. A `Content-Security-Policy-Report-Only` header only reports violations; it blocks nothing, so it counts as missing and the report says it is there |
| `csp-unsafe` | medium | CSP Cheat Sheet | `'unsafe-inline'` lets injected inline scripts run, unless a nonce or hash is also listed (browsers then ignore `'unsafe-inline'`). `'unsafe-eval'` lets strings become code. `*`, `http:` and `data:` let scripts come from anywhere, over plain HTTP, or from the page itself. With no `script-src` and no `default-src`, scripts are not restricted at all. `object-src` that is not `'none'` lets plugins run content |
| `hsts-missing` | high | Secure Headers Project: Strict-Transport-Security | Without HSTS the first request, or a typed address, can be sent over plain HTTP and taken over |
| `hsts-weak` | medium / low | Secure Headers Project: Strict-Transport-Security | OWASP recommends `max-age=31536000; includeSubDomains`. A shorter `max-age` lets the protection lapse (medium); without `includeSubDomains` a subdomain can still set cookies over HTTP (low). A header without a valid `max-age` is ignored by browsers (high) |
| `frame-missing` | medium | Secure Headers Project: X-Frame-Options and CSP frame-ancestors | A page that any site may frame can be used for clickjacking. Either `frame-ancestors` in an enforced CSP or `X-Frame-Options: DENY` / `SAMEORIGIN` is enough; `ALLOW-FROM` is no longer supported by browsers and does not count; `frame-ancestors *` allows everyone |
| `nosniff-missing` | medium | Secure Headers Project: X-Content-Type-Options | Without `nosniff` a browser may guess the type of a response and run an upload as a script. Only the exact value `nosniff` works |
| `referrer-missing` | low | Secure Headers Project: Referrer-Policy | `unsafe-url` and `no-referrer-when-downgrade` send the full address, with its path and query, to other sites. The browser uses the last value it recognises, and so does the check |
| `permissions-missing` | low | Secure Headers Project: Permissions-Policy | Turning off the camera, microphone, location and other features the page does not use limits what an injected script or a framed page can reach. `Feature-Policy` is the old name; the report notes it |
| `cookie-flags` | medium / low | Session Management Cheat Sheet | `Secure` keeps a cookie off plain HTTP (medium). `SameSite=None` without `Secure` is rejected by browsers (medium). `HttpOnly` keeps scripts from reading it (low, since some cookies are meant for scripts). `SameSite` limits cross-site requests (low) |
| `server-leak` | low | Secure Headers Project: headers to remove | A version number in `Server`, `X-Powered-By`, `X-AspNet-Version` or `X-AspNetMvc-Version` tells an attacker which known flaws to try. A product name without a number is not reported |
| `deprecated` | info | Secure Headers Project: deprecated headers | `X-XSS-Protection` other than `0` can itself be abused, and OWASP recommends `0` or no header. `Expect-CT` and `Public-Key-Pins` are deprecated; key pinning can lock users out |
| `cache-sensitive` | info | HTTP Headers Cheat Sheet: Cache-Control | With `--sensitive`, a page with private data should not be stored by browsers or shared caches, so `Cache-Control` must contain `no-store` |

## How the CSP is read

1. Every `Content-Security-Policy` header, and every comma-separated policy inside one, is a separate policy. Browsers enforce all of them: a script must pass every policy.
2. Inside a policy, directives are separated by `;`. A directive name is case-insensitive; when a name repeats, the first one counts, as the CSP specification says.
3. The scripts are governed by `script-src`, or by `default-src` when there is no `script-src`.
4. Because every policy must pass, a weakness is reported only when every policy that restricts scripts has it. A second, strict policy fixes a weak first one.
5. `object-src` is safe when one policy has `object-src 'none'`, or `default-src 'none'` without an `object-src`.
6. A missing `frame-ancestors` is reported once, under `frame-missing`, together with `X-Frame-Options`, so the same gap is not counted twice.

## HTTPS and the address

HSTS and the `Secure` cookie flag only matter on HTTPS. When the address is known and starts with `http:`, those two checks are skipped. When the address is unknown (a curl dump without a `# url:` line), the tool assumes HTTPS and adds a note.

## Severity and the gate

The severities follow how directly a missing header opens the page to an attack: high for script injection and HTTPS downgrade, medium for framing, type sniffing and session cookies, low for information that helps an attacker, info for clean-up. `--fail-on <level>` makes the run exit with `1` when any finding is at that level or above; `info` never fails a run.

Run the tool on the same files after each change: the method has no randomness, so any change in the report comes from a change in the headers.

# Limits

- **One response, one moment.** A saved file shows the headers of one response. Other pages of the same site, error pages, logged-in pages and API responses can carry different headers. Save the pages that matter (the login page, an account page, an error page) and check each one.
- **Per user, per region.** Some servers send different headers to different users, browsers, countries or test groups. The file shows what one request received.
- **CDNs and proxies.** A CDN, load balancer or proxy can add, change or remove headers. A dump taken behind it (from the origin server) and one taken in front of it can differ; check what the browser receives.
- **CSP in a meta tag.** A policy set with `<meta http-equiv="Content-Security-Policy">` in the HTML is not a header, so it is not seen, and the page is reported as having no CSP. The meta tag also cannot set `frame-ancestors`, `report-uri` or `sandbox`.
- **Nonces change.** A nonce in the CSP is different on every response. The tool only checks that a nonce or hash is present; it cannot check that the nonce is unpredictable or that it matches the scripts in the page.
- **Headers, not behaviour.** The tool reads headers. It does not load the page, run its scripts, test for cross-site scripting or clickjacking, or check the TLS setup. A clean report means the headers follow the OWASP recommendations, not that the site is safe.
- **Policy quality.** A CSP can pass every check here and still allow too much, for example a host that serves user uploads or an old script library. Read the policy, or test it with the browser's console.
- **Cookie purpose.** Some cookies are meant to be read by scripts, so a missing `HttpOnly` is reported as low. The tool cannot tell a session cookie from a preference cookie by its name.
- **Size.** Files over 20 MB are refused, header lines over 16 KB are ignored, and only the first 10,000 HAR entries are read. The report says when lines or entries were skipped.

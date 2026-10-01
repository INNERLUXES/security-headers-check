# Changes

## 1.0.0

First release.

- Raw header dumps from curl (the last response of a redirect chain) and HAR files (text/html responses, or all with `--all-entries`).
- Twelve checks after the OWASP Secure Headers Project: CSP (missing and unsafe, parsed per directive), HSTS, framing, nosniff, referrer policy, permissions policy, cookie flags, version leaks, deprecated headers, and `no-store` with `--sensitive`.
- Cookie values never shown; header text cleaned of control characters.
- Reports as text, Markdown, JSON and CSV; `--fail-on` as a gate.
- Bounded input: files over 20 MB refused, header lines over 16 KB ignored, at most 10,000 HAR entries.
- Release packages come with a CycloneDX SBOM, SHA-256 checksums and a build provenance attestation.

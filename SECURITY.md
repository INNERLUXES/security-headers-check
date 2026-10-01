# Security

## Reporting a problem

Write to info@innerluxes.dev with the subject line "security-headers-check security", or use private vulnerability reporting on this repository. Please do not open a public issue for a vulnerability.

Include a small made-up header dump or HAR file (example.com hostnames, no real cookies or tokens) that shows the problem, what you expected and what happened.

## Scope

In scope:

- a cookie value, or any other secret from the input, that reaches a report
- a header value that breaks a Markdown table, injects a formula into a CSV report, or rewrites the terminal through control characters
- an input that makes the tool hang or use unbounded memory
- a check that reports a weak header as safe
- anything that makes the tool open a network connection, run something, or read or write a file it was not given

Out of scope: how the headers were saved and who may read them; docs/limits.md lists what saved headers cannot show.

Read [docs/threat-model.md](docs/threat-model.md) for the rest.

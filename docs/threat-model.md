# Threat model

## What the tool touches

- It reads the files named on the command line, and only those. A path, address or file name found inside a HAR file is data, never something to open.
- It writes only to the screen (standard output and standard error).
- It opens no network connection and runs nothing from the files it reads. Addresses in the input are only shown in the report.

## What the input may hold

A saved header dump, and above all a HAR file exported from a browser, can hold session cookies, tokens in `Set-Cookie`, and addresses with private query strings. The tool treats every input as sensitive and as possibly hostile, since a header value is chosen by whoever runs the server.

## What could go wrong, and what stops it

| Risk | Control |
| --- | --- |
| A session cookie value lands in a shared report | Findings carry the cookie name only; the value is cut at the first `=` and never stored. Tests check every output format against known cookie values |
| A header value rewrites the terminal through escape sequences | Header text shown in a report has control characters removed and its length capped |
| A header value breaks a Markdown table | Pipes and line breaks are escaped in every table cell |
| A CSV report runs a formula when opened in a spreadsheet | Cells that start with `=`, `+`, `-`, `@`, a tab or a carriage return get a leading `'`; every cell is quoted as RFC 4180 says |
| A huge file or line exhausts memory | Files over 20 MB are refused before they are read; header lines over 16 KB are ignored; at most 10,000 HAR entries are read; the report says what was skipped |
| A HAR file points the tool at another file | No field of the input is used as a path |
| A weak header is reported as safe | Each check has tests with hand-written headers; the CSP is parsed per directive and multiple policies are combined as browsers combine them |
| A broken file gives a misleading clean report | A file with no status line and no headers, or a HAR without `log.entries`, stops the run with exit code 2 and the file name |

## Out of scope

How the headers were saved and who may read the saved files, the site itself, and the network between the browser and the server.

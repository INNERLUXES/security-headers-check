# 1. Saved headers, not live requests

## Context

The simplest way to check a site's headers is to give the tool an address and let it make the request. That means the tool opens network connections, needs a way through proxies and firewalls, follows redirects on its own rules, and sends requests to whatever address it is given, including internal ones. It also cannot see logged-in pages without being handed a session, and the result depends on the moment, the network and the region of the run.

## Decision

The tool reads headers that were already saved: a raw dump from `curl` or a HAR file from the browser. It never opens a network connection.

## Consequences

The tool cannot be used to send requests to other hosts, needs no network access in a build job, and gives the same report for the same files every time. Whoever saves the headers chooses the request: `curl` with the options their network needs, or the browser with a test account for logged-in pages. The report describes exactly the response that was saved, which docs/limits.md describes as one response, at one moment, for one user. A pipeline adds one `curl` line before the check, as the README shows.

# Contributing

Every change goes through a pull request and is reviewed before it is merged. The pipeline runs the tests on Linux, Windows and macOS, the repository checks, CodeQL, and a secure development check of the repository itself.

## Changing a check

1. Describe the change in docs/method.md first, with the OWASP Secure Headers Project recommendation it follows.
2. Add a test with small, made-up headers where the result can be worked out by hand.
3. Text taken from a header goes through `safeText` before it reaches a finding, and cookies are reported by name only.

## Rules for the code

- No runtime dependencies. Node 22 or newer and nothing else.
- The tool reads the files it is given and writes only to the screen. It opens no network connection and runs nothing.
- Never commit real header dumps or HAR files, even as fixtures: they can hold session cookies and tokens. Use example.com and example.org hostnames.

## Before you open the pull request

```
npm test
npm run check
npm run example
```

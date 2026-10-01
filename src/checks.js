// The checks. Each one follows a recommendation of the OWASP Secure Headers Project
// (https://owasp.org/www-project-secure-headers/); docs/method.md gives the reason for each.
// A finding is { id, severity, message, fix }. Cookie values never reach a finding: only cookie names do.

import { headerValues, firstHeader } from './load.js';
import { parseCsp, scriptSources, scriptWeaknesses, objectSrcIsNone } from './csp.js';

export const SEVERITIES = ['high', 'medium', 'low', 'info'];
export const RANK = { high: 3, medium: 2, low: 1, info: 0 };

export const CHECKS = [
  { id: 'csp-missing', severity: 'high', title: 'No Content-Security-Policy' },
  { id: 'csp-unsafe', severity: 'medium', title: 'Content-Security-Policy that still lets attacks through' },
  { id: 'hsts-missing', severity: 'high', title: 'No Strict-Transport-Security on HTTPS' },
  { id: 'hsts-weak', severity: 'medium', title: 'Short max-age or no includeSubDomains' },
  { id: 'frame-missing', severity: 'medium', title: 'Page can be framed by any site' },
  { id: 'nosniff-missing', severity: 'medium', title: 'X-Content-Type-Options is not nosniff' },
  { id: 'referrer-missing', severity: 'low', title: 'No Referrer-Policy, or an unsafe one' },
  { id: 'permissions-missing', severity: 'low', title: 'No Permissions-Policy' },
  { id: 'cookie-flags', severity: 'medium', title: 'Cookie without Secure, HttpOnly or SameSite' },
  { id: 'server-leak', severity: 'low', title: 'Server software and version in a header' },
  { id: 'deprecated', severity: 'info', title: 'Deprecated header' },
  { id: 'cache-sensitive', severity: 'info', title: 'Sensitive page that may be cached (--sensitive)' }
];

export const HSTS_MIN_AGE = 31536000;

// Header text shown in a report: control characters removed and length capped, so a header cannot
// rewrite the terminal or flood the report.
export function safeText(value, max = 120) {
  const s = String(value).replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').trim();
  return s.length > max ? `${s.slice(0, max)}...` : s;
}

// A cookie as it may be shown: its name only. Everything after the first '=' is masked.
export function cookieName(setCookie) {
  const first = String(setCookie).split(';')[0];
  const eq = first.indexOf('=');
  return safeText(eq >= 0 ? first.slice(0, eq) : first, 60) || '(no name)';
}

export function maskCookie(setCookie) {
  return `${cookieName(setCookie)}=***`;
}

export function parseCookie(setCookie) {
  const parts = String(setCookie).split(';').slice(1).map((p) => p.trim()).filter(Boolean);
  const attrs = new Map();
  for (const p of parts) {
    const eq = p.indexOf('=');
    const key = (eq >= 0 ? p.slice(0, eq) : p).trim().toLowerCase();
    const value = eq >= 0 ? p.slice(eq + 1).trim() : '';
    if (!attrs.has(key)) attrs.set(key, value);
  }
  return {
    name: cookieName(setCookie),
    secure: attrs.has('secure'),
    httpOnly: attrs.has('httponly'),
    sameSite: attrs.has('samesite') ? attrs.get('samesite').toLowerCase() : null
  };
}

const find = (id, message, fix, severity) => ({ id, severity: severity || CHECKS.find((c) => c.id === id).severity, message, fix });

function cspFindings(headers, out, notes) {
  const enforced = headerValues(headers, 'content-security-policy');
  const reportOnly = headerValues(headers, 'content-security-policy-report-only');
  const policies = parseCsp(enforced);
  if (!policies.length) {
    const extra = reportOnly.length ? ' (Content-Security-Policy-Report-Only is set, but it only reports and blocks nothing)' : '';
    out.push(find('csp-missing', `no Content-Security-Policy header${extra}`,
      "add a policy such as: default-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'"));
    return policies;
  }
  if (reportOnly.length) notes.push('Content-Security-Policy-Report-Only is also set; only the enforced policy is checked');
  // A weakness counts only when every enforced policy has it: one strict policy is enough to block the load.
  const UNRESTRICTED = 'no script-src or default-src, so scripts may load from anywhere';
  const perPolicy = policies.map((p) => {
    const s = scriptSources(p);
    return s ? new Map(scriptWeaknesses(s.sources).map((w) => [w, `${s.directive} allows ${w}`])) : new Map([[UNRESTRICTED, UNRESTRICTED]]);
  });
  // An unrestricted policy adds nothing, so only the restricting policies decide.
  const restricting = perPolicy.filter((m) => !m.has(UNRESTRICTED));
  const deciding = restricting.length ? restricting : perPolicy;
  const common = [...deciding[0].keys()].filter((w) => deciding.every((m) => m.has(w))).map((w) => deciding[0].get(w));
  for (const w of common) {
    out.push(find('csp-unsafe', w, "remove it; use nonces or hashes for inline scripts and list only the hosts you load scripts from"));
  }
  if (!policies.some(objectSrcIsNone)) {
    out.push(find('csp-unsafe', "object-src is not 'none' (plugins can run content)", "add object-src 'none'"));
  }
  return policies;
}

function frameFindings(headers, policies, out) {
  const xfo = firstHeader(headers, 'x-frame-options');
  const xfoOk = xfo !== null && /^(deny|sameorigin)$/i.test(xfo.trim());
  const lists = policies.filter((p) => p.has('frame-ancestors')).map((p) => p.get('frame-ancestors').map((s) => s.toLowerCase()));
  if (lists.length) {
    if (lists.every((l) => l.includes('*')) && !xfoOk) {
      out.push(find('frame-missing', "CSP frame-ancestors allows '*' (any site may frame the page)", "set frame-ancestors 'self' or 'none'"));
    }
    return;
  }
  if (!xfoOk) {
    const why = xfo === null ? 'no CSP frame-ancestors and no X-Frame-Options' : `no CSP frame-ancestors, and X-Frame-Options is "${safeText(xfo, 40)}"`;
    out.push(find('frame-missing', why, "add frame-ancestors 'self' to the CSP, or X-Frame-Options: DENY"));
  }
}

function hstsFindings(headers, scheme, out) {
  if (scheme === 'http') return;
  const hsts = firstHeader(headers, 'strict-transport-security');
  if (hsts === null) {
    out.push(find('hsts-missing', 'no Strict-Transport-Security header', 'add Strict-Transport-Security: max-age=31536000; includeSubDomains'));
    return;
  }
  const age = /(?:^|;)\s*max-age\s*=\s*"?(\d+)"?/i.exec(hsts);
  if (!age) {
    out.push(find('hsts-weak', 'Strict-Transport-Security has no valid max-age, so browsers ignore it', 'set max-age=31536000', 'high'));
  } else if (Number(age[1]) < HSTS_MIN_AGE) {
    out.push(find('hsts-weak', `Strict-Transport-Security max-age=${age[1]} is below one year (${HSTS_MIN_AGE})`, 'set max-age=31536000 or more'));
  }
  if (!/(?:^|;)\s*includesubdomains\s*(?:;|$)/i.test(hsts)) {
    out.push(find('hsts-weak', 'Strict-Transport-Security without includeSubDomains', 'add includeSubDomains once every subdomain serves HTTPS', 'low'));
  }
}

const REFERRER = new Set(['no-referrer', 'no-referrer-when-downgrade', 'same-origin', 'origin', 'strict-origin',
  'origin-when-cross-origin', 'strict-origin-when-cross-origin', 'unsafe-url']);

function referrerFindings(headers, out) {
  const values = headerValues(headers, 'referrer-policy');
  // The last policy the browser recognises wins.
  const tokens = values.join(',').split(',').map((t) => t.trim().toLowerCase()).filter((t) => REFERRER.has(t));
  const fix = 'set Referrer-Policy: strict-origin-when-cross-origin (or no-referrer)';
  if (!tokens.length) {
    out.push(find('referrer-missing', values.length ? 'Referrer-Policy has no value a browser recognises' : 'no Referrer-Policy header', fix));
    return;
  }
  const used = tokens[tokens.length - 1];
  if (used === 'unsafe-url' || used === 'no-referrer-when-downgrade') {
    out.push(find('referrer-missing', `Referrer-Policy is ${used}, which sends the full address to other sites`, fix));
  }
}

function cookieFindings(headers, scheme, out) {
  for (const raw of headerValues(headers, 'set-cookie')) {
    const c = parseCookie(raw);
    if (!c.secure && scheme !== 'http') {
      out.push(find('cookie-flags', `cookie ${c.name}: no Secure flag`, 'add Secure so the cookie is never sent over plain HTTP'));
    }
    if (c.sameSite === 'none' && !c.secure) {
      out.push(find('cookie-flags', `cookie ${c.name}: SameSite=None without Secure (browsers reject it)`, 'add Secure, or use SameSite=Lax'));
    }
    if (!c.httpOnly) {
      out.push(find('cookie-flags', `cookie ${c.name}: no HttpOnly flag`, 'add HttpOnly unless page scripts must read this cookie', 'low'));
    }
    if (c.sameSite === null) {
      out.push(find('cookie-flags', `cookie ${c.name}: no SameSite attribute`, 'add SameSite=Lax (or Strict)', 'low'));
    }
  }
}

const LEAKY = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'];

function leakFindings(headers, out) {
  for (const name of LEAKY) {
    for (const value of headerValues(headers, name)) {
      if (/\d/.test(value)) {
        const shown = headers.find(([n]) => n.toLowerCase() === name)[0];
        out.push(find('server-leak', `${safeText(shown, 40)}: ${safeText(value, 60)} names a version`, `remove the version from ${safeText(shown, 40)}, or remove the header`));
      }
    }
  }
}

function deprecatedFindings(headers, out) {
  const xxss = firstHeader(headers, 'x-xss-protection');
  if (xxss !== null && xxss.trim() !== '0') {
    out.push(find('deprecated', `X-XSS-Protection: ${safeText(xxss, 40)} (the browser filter is retired and can be abused)`, 'set X-XSS-Protection: 0 or remove it; rely on the CSP'));
  }
  if (firstHeader(headers, 'expect-ct') !== null) out.push(find('deprecated', 'Expect-CT is deprecated', 'remove Expect-CT'));
  for (const name of ['public-key-pins', 'public-key-pins-report-only']) {
    if (firstHeader(headers, name) !== null) out.push(find('deprecated', `${name === 'public-key-pins' ? 'Public-Key-Pins' : 'Public-Key-Pins-Report-Only'} is deprecated and risky`, 'remove it'));
  }
}

export function schemeOf(url) {
  if (typeof url !== 'string') return null;
  const m = /^(https?):/i.exec(url.trim());
  return m ? m[1].toLowerCase() : null;
}

// Checks one page's headers. Returns { findings, notes }.
export function checkHeaders(headers, options = {}) {
  const out = [];
  const notes = [];
  const scheme = schemeOf(options.url);
  if (scheme === null) notes.push('URL unknown: assumed HTTPS, so HSTS and the Secure flag are checked');
  const policies = cspFindings(headers, out, notes);
  hstsFindings(headers, scheme, out);
  frameFindings(headers, policies, out);
  const xcto = firstHeader(headers, 'x-content-type-options');
  if (xcto === null || xcto.trim().toLowerCase() !== 'nosniff') {
    out.push(find('nosniff-missing', xcto === null ? 'no X-Content-Type-Options header' : `X-Content-Type-Options is "${safeText(xcto, 40)}", not nosniff`, 'set X-Content-Type-Options: nosniff'));
  }
  referrerFindings(headers, out);
  if (firstHeader(headers, 'permissions-policy') === null) {
    const old = firstHeader(headers, 'feature-policy') !== null ? ' (Feature-Policy is set, but browsers now read Permissions-Policy)' : '';
    out.push(find('permissions-missing', `no Permissions-Policy header${old}`, 'add Permissions-Policy that turns off what the page does not use, e.g. camera=(), microphone=(), geolocation=()'));
  }
  cookieFindings(headers, scheme, out);
  leakFindings(headers, out);
  deprecatedFindings(headers, out);
  if (options.sensitive) {
    const cc = headerValues(headers, 'cache-control').join(',').toLowerCase();
    if (!/(^|[,\s])no-store([,\s]|$)/.test(cc)) {
      out.push(find('cache-sensitive', 'no Cache-Control: no-store on a page marked sensitive', 'add Cache-Control: no-store'));
    }
  }
  out.sort((a, b) => RANK[b.severity] - RANK[a.severity]);
  return { findings: out, notes };
}

// Checks every page and adds the totals.
export function checkPages(pages, options = {}) {
  const results = pages.map((p) => {
    const { findings, notes } = checkHeaders(p.headers, { url: p.url, sensitive: options.sensitive });
    return { source: p.source || null, url: p.url ? safeText(p.url, 200) : null, status: p.status, findings, notes: [...(p.notes || []), ...notes] };
  });
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const r of results) for (const f of r.findings) counts[f.severity] += 1;
  return { pages: results, counts };
}

// True when a finding reaches the --fail-on threshold.
export function meetsThreshold(report, threshold) {
  if (!threshold) return false;
  return report.pages.some((p) => p.findings.some((f) => RANK[f.severity] >= RANK[threshold]));
}

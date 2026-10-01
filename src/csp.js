// Content-Security-Policy, parsed per directive as the CSP Level 3 specification describes:
//   policies are separated by commas, directives by semicolons;
//   a directive name is case-insensitive; when a name repeats inside one policy, the first one counts.
// Several CSP headers (or comma-separated policies) are all enforced: a load must pass every one of them.

export function parsePolicy(text) {
  const directives = new Map();
  for (const part of String(text).split(';')) {
    const tokens = part.trim().split(/[ \t]+/).filter(Boolean);
    if (!tokens.length) continue;
    const name = tokens[0].toLowerCase();
    if (!/^[a-z0-9-]+$/.test(name) || directives.has(name)) continue;
    directives.set(name, tokens.slice(1));
  }
  return directives;
}

// All policies from all CSP header values.
export function parseCsp(values) {
  const list = Array.isArray(values) ? values : [values];
  const policies = [];
  for (const value of list) {
    for (const piece of String(value).split(',')) {
      const policy = parsePolicy(piece);
      if (policy.size) policies.push(policy);
    }
  }
  return policies;
}

const KEYWORD = (t) => t.toLowerCase();

// The source list that governs scripts: script-src, else default-src, else null (no restriction at all).
export function scriptSources(policy) {
  if (policy.has('script-src')) return { directive: 'script-src', sources: policy.get('script-src') };
  if (policy.has('default-src')) return { directive: 'default-src', sources: policy.get('default-src') };
  return null;
}

export function hasNonceOrHash(sources) {
  return sources.some((s) => /^'(nonce-|sha256-|sha384-|sha512-)/i.test(s));
}

// What makes a script source list weak. Returns short labels; never echoes nonce or hash values.
export function scriptWeaknesses(sources) {
  const found = [];
  const lower = sources.map(KEYWORD);
  if (lower.includes("'unsafe-inline'") && !hasNonceOrHash(sources)) found.push("'unsafe-inline' without a nonce or hash");
  if (lower.includes("'unsafe-eval'")) found.push("'unsafe-eval'");
  if (lower.includes('*')) found.push("'*' (any host)");
  if (lower.includes('http:') || lower.some((s) => s.startsWith('http://'))) found.push('http: (unencrypted) sources');
  if (lower.includes('data:')) found.push('data: sources');
  return found;
}

// object-src is safe only when it (or default-src when it is absent) is exactly 'none'.
export function objectSrcIsNone(policy) {
  const sources = policy.has('object-src') ? policy.get('object-src') : policy.get('default-src');
  return Array.isArray(sources) && sources.length === 1 && KEYWORD(sources[0]) === "'none'";
}

export function frameAncestors(policies) {
  for (const p of policies) if (p.has('frame-ancestors')) return p.get('frame-ancestors');
  return null;
}

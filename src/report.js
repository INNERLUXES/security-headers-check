// Report formats: text for a terminal, Markdown for a pull request or a ticket, JSON for other tools, CSV for a spreadsheet.
// No format ever shows a cookie value: findings carry cookie names only.

function total(r) {
  return r.counts.high + r.counts.medium + r.counts.low + r.counts.info;
}

function summary(r) {
  return `${r.counts.high} high, ${r.counts.medium} medium, ${r.counts.low} low, ${r.counts.info} info`;
}

function where(p) {
  return `${p.source || '(input)'}  ${p.url || '(URL unknown)'}${p.status ? `  (${p.status})` : ''}`;
}

export function toText(r) {
  const lines = [`security-headers-check: ${r.pages.length} page(s), ${total(r)} finding(s): ${summary(r)}`];
  for (const p of r.pages) {
    lines.push('', where(p));
    for (const n of p.notes) lines.push(`  note: ${n}`);
    if (!p.findings.length) lines.push('  no problems found');
    for (const f of p.findings) {
      lines.push(`  ${f.severity.toUpperCase().padEnd(6)}  ${f.id.padEnd(20)} ${f.message}`);
      lines.push(`  ${''.padEnd(6)}  ${''.padEnd(20)} fix: ${f.fix}`);
    }
  }
  if (r.gate) lines.push('', r.gate.pass ? 'GATE: PASS' : `GATE: FAIL - ${r.gate.reason}`);
  return lines.join('\n') + '\n';
}

// A Markdown table cell: pipes escaped, line breaks flattened, so a header value cannot break the table.
export function mdCell(t) {
  return String(t).replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/\r?\n|\r/g, ' ');
}

export function toMarkdown(r) {
  const lines = [`## security-headers-check: ${summary(r)}`, '', `${r.pages.length} page(s) checked.`];
  for (const p of r.pages) {
    lines.push('', `### ${mdCell(p.source || '(input)')}: ${mdCell(p.url || 'URL unknown')}${p.status ? ` (${p.status})` : ''}`, '');
    for (const n of p.notes) lines.push(`- ${mdCell(n)}`);
    if (p.notes.length) lines.push('');
    if (!p.findings.length) {
      lines.push('No problems found.');
      continue;
    }
    lines.push('| Severity | Check | Problem | Fix |', '| --- | --- | --- | --- |');
    for (const f of p.findings) lines.push(`| ${f.severity} | ${mdCell(f.id)} | ${mdCell(f.message)} | ${mdCell(f.fix)} |`);
  }
  if (r.gate && !r.gate.pass) lines.push('', `**Gate failed:** ${mdCell(r.gate.reason)}`);
  return lines.join('\n') + '\n';
}

export function toJson(r) {
  return JSON.stringify(r, null, 2) + '\n';
}

// RFC 4180 quoting, and a leading quote on cells a spreadsheet would read as a formula.
export function csvCell(value) {
  let s = value === null || value === undefined ? '' : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv(r) {
  const rows = [['file', 'url', 'status', 'severity', 'check', 'problem', 'fix']];
  for (const p of r.pages) {
    for (const f of p.findings) rows.push([p.source, p.url, p.status, f.severity, f.id, f.message, f.fix]);
  }
  return rows.map((row) => row.map(csvCell).join(',')).join('\r\n') + '\r\n';
}

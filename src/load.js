// Reads saved response headers: a raw dump from curl (-D - or -I) or a HAR file exported from a browser.
// Only the file it is given is read. Nothing inside a file is treated as a path, a link to follow or code to run.

import { readFile, stat } from 'node:fs/promises';
import { extname } from 'node:path';

export const LIMITS = {
  maxFileBytes: 20 * 1024 * 1024,
  maxLineBytes: 16 * 1024,
  maxEntries: 10000
};

const STATUS = /^HTTP\/\d(?:\.\d)?\s+(\d{3})\b/i;
const HEADER = /^([!#$%&'*+.^_`|~0-9A-Za-z-]+)[ \t]*:[ \t]*(.*)$/;

// Every lookup is case-insensitive: header names are, by the HTTP specification.
export function headerValues(headers, name) {
  const want = name.toLowerCase();
  return headers.filter(([n]) => n.toLowerCase() === want).map(([, v]) => v);
}

export function firstHeader(headers, name) {
  const values = headerValues(headers, name);
  return values.length ? values[0] : null;
}

// A raw dump may hold several responses after redirects (curl -L -D -). Only the last one is the page itself.
export function parseDump(text, limits = LIMITS) {
  const lines = String(text).replace(/^﻿/, '').split(/\r?\n/);
  const blocks = [];
  let current = null;
  let url = null;
  let longLines = 0;
  for (const line of lines) {
    if (Buffer.byteLength(line, 'utf8') > limits.maxLineBytes) {
      longLines += 1;
      continue;
    }
    const comment = /^#\s*url:\s*(\S+)\s*$/i.exec(line);
    if (comment) {
      url = comment[1];
      continue;
    }
    const status = STATUS.exec(line);
    if (status) {
      current = { status: Number(status[1]), headers: [] };
      blocks.push(current);
      continue;
    }
    if (!line.trim()) continue;
    const header = HEADER.exec(line);
    if (header) {
      if (!current) {
        current = { status: null, headers: [] };
        blocks.push(current);
      }
      current.headers.push([header[1], header[2].trim()]);
    } else if (/^[ \t]/.test(line) && current && current.headers.length) {
      // an obsolete folded header line continues the previous value
      const last = current.headers[current.headers.length - 1];
      last[1] = `${last[1]} ${line.trim()}`;
    }
  }
  const notes = [];
  if (longLines) notes.push(`${longLines} header line(s) over ${limits.maxLineBytes / 1024} KB ignored`);
  if (!blocks.length) throw new Error('no status line and no headers found');
  if (blocks.length > 1) notes.push(`${blocks.length} responses in the file (redirects); the last one is checked`);
  const last = blocks[blocks.length - 1];
  return [{ url, status: last.status, headers: last.headers, notes }];
}

function isHtml(entry) {
  const mime = entry && entry.response && entry.response.content && entry.response.content.mimeType;
  return typeof mime === 'string' && /^\s*text\/html\b/i.test(mime);
}

// A HAR file: log.entries[].request.url and log.entries[].response.headers.
// Only text/html responses are checked unless allEntries is set.
export function parseHar(text, options = {}, limits = LIMITS) {
  let har;
  try {
    har = JSON.parse(String(text).replace(/^﻿/, ''));
  } catch (error) {
    throw new Error(`not valid JSON (${error.message})`);
  }
  const entries = har && har.log && har.log.entries;
  if (!Array.isArray(entries)) throw new Error('not a HAR file: log.entries is missing');
  const fileNotes = [];
  let list = entries;
  if (entries.length > limits.maxEntries) {
    fileNotes.push(`${entries.length} entries in the file; only the first ${limits.maxEntries} are read`);
    list = entries.slice(0, limits.maxEntries);
  }
  const chosen = options.allEntries ? list : list.filter(isHtml);
  if (!chosen.length) {
    throw new Error(options.allEntries ? 'no entries in the HAR file' : 'no text/html responses in the HAR file (use --all-entries to check every response)');
  }
  return chosen.map((entry, i) => {
    const notes = i === 0 ? [...fileNotes] : [];
    const response = (entry && entry.response) || {};
    const raw = Array.isArray(response.headers) ? response.headers : [];
    const headers = [];
    let longValues = 0;
    for (const h of raw) {
      if (!h || typeof h.name !== 'string' || typeof h.value !== 'string') continue;
      if (Buffer.byteLength(h.name, 'utf8') + Buffer.byteLength(h.value, 'utf8') > limits.maxLineBytes) {
        longValues += 1;
        continue;
      }
      // HTTP/2 pseudo headers (":status") are not response headers
      if (h.name.startsWith(':')) continue;
      headers.push([h.name, h.value.trim()]);
    }
    if (longValues) notes.push(`${longValues} header(s) over ${limits.maxLineBytes / 1024} KB ignored`);
    const url = entry && entry.request && typeof entry.request.url === 'string' ? entry.request.url : null;
    const status = Number.isInteger(response.status) ? response.status : null;
    return { url, status, headers, notes };
  });
}

function looksLikeJson(text) {
  return /^﻿?\s*\{/.test(text);
}

// Reads one file and returns the pages in it. Refuses anything that is not a regular file or is over the size limit.
export async function loadFile(path, options = {}, limits = LIMITS) {
  const info = await stat(path);
  if (!info.isFile()) throw new Error(`${path}: not a file`);
  if (info.size > limits.maxFileBytes) {
    throw new Error(`${path}: ${info.size} bytes is over the ${limits.maxFileBytes / 1024 / 1024} MB limit`);
  }
  const text = await readFile(path, 'utf8');
  const har = extname(path).toLowerCase() === '.har' || looksLikeJson(text);
  try {
    const pages = har ? parseHar(text, options, limits) : parseDump(text, limits);
    return pages.map((p) => ({ source: path, ...p }));
  } catch (error) {
    throw new Error(`${path}: ${error.message}`);
  }
}

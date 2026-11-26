#!/usr/bin/env node
'use strict';

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const web = path.join(repo, 'control', 'web');
const i18nPath = path.join(web, 'i18n.js');
const { catalogs, SUPPORTED_LANGUAGES } = await import(pathToFileURL(i18nPath).href);

const fail = message => {
  process.stderr.write(`i18n validation failed: ${message}\n`);
  process.exitCode = 1;
};

const keySets = new Map();
for (const language of SUPPORTED_LANGUAGES) {
  const catalog = catalogs[language];
  if (!catalog || typeof catalog !== 'object') {
    fail(`missing catalog ${language}`);
    continue;
  }
  const keys = Object.keys(catalog).sort();
  keySets.set(language, keys);
  for (const key of keys) {
    if (typeof catalog[key] !== 'string' || catalog[key].trim() === '') fail(`empty value ${language}:${key}`);
  }
}

const base = keySets.get('de') || [];
for (const language of SUPPORTED_LANGUAGES) {
  const keys = keySets.get(language) || [];
  if (keys.length !== base.length || keys.some((key, index) => key !== base[index])) fail(`catalog parity mismatch for ${language}`);
}

const used = new Set();
const html = fs.readFileSync(path.join(web, 'index.html'), 'utf8');
for (const match of html.matchAll(/data-i18n(?:-placeholder|-aria|-title)?=["']([^"']+)["']/g)) used.add(match[1]);

for (const entry of fs.readdirSync(web, { recursive: true, withFileTypes: true })) {
  if (!entry.isFile() || !entry.name.endsWith('.js') || entry.name === 'i18n.js') continue;
  const parent = entry.parentPath || web;
  if (path.basename(parent) === 'i18n') continue;
  const source = fs.readFileSync(path.join(parent, entry.name), 'utf8');
  for (const match of source.matchAll(/\bt\(["']([^"']+)["']/g)) used.add(match[1]);
}

for (const language of SUPPORTED_LANGUAGES) {
  const catalog = catalogs[language] || {};
  for (const key of used) if (!(key in catalog)) fail(`missing used key ${language}:${key}`);
}

const zhOption = /<option\s+value=["']zh-CN["'][^>]*>\s*简体中文\s*<\/option>/u.test(html);
if (!zhOption) fail('zh-CN language selector option missing');

if (!process.exitCode) {
  process.stdout.write(`i18n validation passed: ${SUPPORTED_LANGUAGES.join(', ')} · ${base.length} keys/language · ${used.size} statically referenced keys\n`);
}

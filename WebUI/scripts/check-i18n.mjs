import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '../src');
const catalogText = readFileSync(join(root, 'lib/i18n.ts'), 'utf8');
const catalog = new Set([...catalogText.matchAll(/^\s*(?:'((?:\\.|[^'])*)'|"((?:\\.|[^"])*)")\s*:/gm)]
  .map(match => (match[1] ?? match[2]).replaceAll("\\'", "'").replaceAll('\\"', '"')));
// Comparison values in conditional expressions are protocol identifiers, not UI text.
const protocolValues = new Set(['scope_required', 'awaiting_browser', 'approved', 'review_required', 'collecting', 'dark', 'light']);

function sources(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? sources(path) : /\.tsx?$/.test(entry.name) ? [path] : [];
  });
}

function stringLiterals(expression) {
  return [...expression.matchAll(/'((?:\\.|[^'])*)'|"((?:\\.|[^"])*)"/g)]
    .map(match => (match[1] ?? match[2]).replaceAll("\\'", "'").replaceAll('\\"', '"'));
}

const missing = [];
for (const path of sources(root)) {
  if (path.endsWith('/lib/i18n.ts')) continue;
  const content = readFileSync(path, 'utf8');
  const calls = /\b(?:tr|translate)\s*\(/g;
  for (const match of content.matchAll(calls)) {
    let depth = 1;
    let index = match.index + match[0].length;
    let quote = '';
    for (; index < content.length && depth > 0; index++) {
      const char = content[index];
      if (quote) {
        if (char === '\\') index++;
        else if (char === quote) quote = '';
      } else if (char === "'" || char === '"' || char === '`') quote = char;
      else if (char === '(') depth++;
      else if (char === ')') depth--;
    }
    const argument = content.slice(match.index + match[0].length, index - 1);
    const line = content.slice(0, match.index).split('\n').length;
    for (const key of stringLiterals(argument)) {
      if (!catalog.has(key) && !protocolValues.has(key)) missing.push(`${path.slice(root.length + 1)}:${line}: ${JSON.stringify(key)}`);
    }
  }
}

const messageCatalogText = readFileSync(join(root, 'lib/activityMessages.ts'), 'utf8');
const messageCodes = new Set([...messageCatalogText.matchAll(/^\s*'([a-z_.]+)':\s*(?:\(\)|params)\s*=>/gm)].map(match => match[1]));
const backendRoot = resolve(root, '../../src/aidast/web');
for (const filename of ['scope_workflow.py', 'launch.py', 'projection.py']) {
  const backend = readFileSync(join(backendRoot, filename), 'utf8');
  for (const match of backend.matchAll(/(?:message_code\s*=\s*|"message_code"\s*:\s*)"([a-z_.]+)"/g)) {
    if (!messageCodes.has(match[1])) missing.push(`backend/${filename}: missing activity translation ${match[1]}`);
  }
}

if (missing.length) {
  process.stderr.write(`Missing Korean translations (${missing.length}):\n${[...new Set(missing)].join('\n')}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write('Korean translation catalog covers all static UI keys.\n');
}

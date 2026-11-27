import { readFile } from 'node:fs/promises';
import path from 'node:path';

export const PACKAGE_ORDER = Object.freeze([
  'sentinel-lint',
  'pathcage',
  'headersafe',
  'redirectcage',
  'envcage',
  'cookiecage',
  'zipcage',
  'logcage',
  'corscage',
  'jsoncage'
]);

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function nestedJsonPayload(depth) {
  if (!Number.isSafeInteger(depth) || depth < 1) {
    throw new Error('nested-json depth must be a positive safe integer');
  }
  let payload = '1';
  for (let index = 0; index < depth; index += 1) {
    payload = '{"nested":' + payload + '}';
  }
  return payload;
}

export function longStringJsonPayload(length) {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new Error('long-string-json length must be a nonnegative safe integer');
  }
  return '{"text":"' + 'x'.repeat(length) + '"}';
}

export function materializeInput(input) {
  if (!isPlainObject(input)) {
    return input;
  }
  if (input.generate === 'nested-json') {
    return nestedJsonPayload(input.depth);
  }
  if (input.generate === 'long-string-json') {
    return longStringJsonPayload(input.length);
  }
  return input;
}

export function corpusCases(corpus) {
  const hostile = corpus.hostile.map((entry) => ({ ...entry, kind: 'hostile' }));
  const benign = corpus.benign.map((entry) => ({ ...entry, kind: 'benign' }));
  return [...hostile, ...benign];
}

function validateEntry(entry, kind, errors, seenIds) {
  const where = kind + ' entry ' + String(entry && entry.id);
  if (!isPlainObject(entry)) {
    errors.push(where + ' must be an object');
    return;
  }
  if (typeof entry.id !== 'string' || entry.id.length < 3) {
    errors.push(where + ' must have a stable id string');
  } else if (seenIds.has(entry.id)) {
    errors.push('duplicate corpus id ' + entry.id);
  } else {
    seenIds.add(entry.id);
  }
  if (typeof entry.title !== 'string' || entry.title.length < 3) {
    errors.push(where + ' must have a title');
  }
  if (!Object.hasOwn(entry, 'input')) {
    errors.push(where + ' must have an input');
  }
  if (typeof entry.why !== 'string' || entry.why.length < 10) {
    errors.push(where + ' must explain why the input is realistic');
  }
  if (kind === 'hostile' && (typeof entry.cwe !== 'string' || !entry.cwe.startsWith('CWE-'))) {
    errors.push(where + ' must name a CWE identifier');
  }
}

export function validateCorpusShape(corpus) {
  const errors = [];
  if (!isPlainObject(corpus)) {
    return ['corpus must be a JSON object'];
  }
  for (const key of ['suite', 'package', 'title', 'attackSurface', 'primaryCwe']) {
    if (typeof corpus[key] !== 'string' || corpus[key].length === 0) {
      errors.push('missing required string field ' + key);
    }
  }
  if (!Array.isArray(corpus.references) || corpus.references.length === 0) {
    errors.push('references must be a nonempty array');
  } else {
    for (const reference of corpus.references) {
      if (!isPlainObject(reference) || typeof reference.type !== 'string' || typeof reference.id !== 'string' || typeof reference.url !== 'string') {
        errors.push('every reference needs type, id and url strings');
      }
    }
  }
  if (!Array.isArray(corpus.hostile) || corpus.hostile.length < 8) {
    errors.push('hostile must contain at least eight curated cases');
  }
  if (!Array.isArray(corpus.benign) || corpus.benign.length < 8) {
    errors.push('benign must contain at least eight curated cases');
  }
  const seenIds = new Set();
  for (const entry of corpus.hostile || []) {
    validateEntry(entry, 'hostile', errors, seenIds);
  }
  for (const entry of corpus.benign || []) {
    validateEntry(entry, 'benign', errors, seenIds);
  }
  return errors;
}

export async function loadCorpora(rootDir) {
  const corpora = [];
  for (const packageName of PACKAGE_ORDER) {
    const filePath = path.join(rootDir, 'corpora', packageName + '.json');
    const parsed = JSON.parse(await readFile(filePath, 'utf8'));
    const errors = validateCorpusShape(parsed);
    if (errors.length > 0) {
      throw new Error(packageName + '.json is invalid:\n' + errors.join('\n'));
    }
    if (parsed.suite !== packageName || parsed.package !== packageName) {
      throw new Error(packageName + '.json suite and package fields must match its filename');
    }
    corpora.push(parsed);
  }
  return corpora;
}

export async function readPackageVersions(rootDir) {
  const packageJson = JSON.parse(await readFile(path.join(rootDir, 'package.json'), 'utf8'));
  const versions = {};
  for (const packageName of PACKAGE_ORDER) {
    const version = packageJson.dependencies && packageJson.dependencies[packageName];
    if (typeof version !== 'string' || version.length === 0) {
      throw new Error('package.json must pin dependency ' + packageName);
    }
    versions[packageName] = version;
  }
  return versions;
}

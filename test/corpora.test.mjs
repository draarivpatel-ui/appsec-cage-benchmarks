import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

import { PACKAGE_ORDER, corpusCases, loadCorpora, materializeInput, validateCorpusShape } from '../src/corpora.mjs';

const rootDir = fileURLToPath(new URL('../', import.meta.url));

test('corpus set covers exactly the eighteen pinned packages', async () => {
  const corpora = await loadCorpora(rootDir);
  assert.deepEqual(corpora.map((corpus) => corpus.package), PACKAGE_ORDER);
  assert.equal(new Set(corpora.map((corpus) => corpus.package)).size, 18);
});

test('every corpus has eight hostile and eight benign curated cases', async () => {
  const corpora = await loadCorpora(rootDir);
  for (const corpus of corpora) {
    assert.equal(corpus.hostile.length, 8, corpus.package + ' hostile count');
    assert.equal(corpus.benign.length, 8, corpus.package + ' benign count');
    assert.deepEqual(validateCorpusShape(corpus), [], corpus.package + ' shape');
    const ids = corpusCases(corpus).map((entry) => entry.id);
    assert.equal(new Set(ids).size, ids.length, corpus.package + ' duplicate ids');
    for (const entry of corpusCases(corpus)) {
      assert.doesNotThrow(() => materializeInput(entry.input), entry.id + ' materialization');
    }
  }
});

test('corpus references are anchored in OWASP, CWE and real CVE research', async () => {
  const corpora = await loadCorpora(rootDir);
  let cveCount = 0;
  for (const corpus of corpora) {
    const types = new Set(corpus.references.map((reference) => reference.type));
    assert.equal(types.has('OWASP'), true, corpus.package + ' missing OWASP reference');
    assert.equal(types.has('CWE'), true, corpus.package + ' missing CWE reference');
    for (const reference of corpus.references) {
      assert.match(reference.url, /^https:\/\//, reference.id + ' must use HTTPS');
      if (reference.type === 'CVE') {
        cveCount += 1;
        assert.match(reference.id, /^CVE-\d{4}-\d{4,}$/);
      }
    }
  }
  assert.ok(cveCount >= 6, 'suite must include at least six concrete CVE references');
});

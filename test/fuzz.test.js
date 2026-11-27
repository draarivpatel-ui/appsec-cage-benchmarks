import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';

import {
  evaluateCorrectness,
  summarizeCorrectness
} from '../src/benchmark.mjs';
import {
  longStringJsonPayload,
  materializeInput,
  nestedJsonPayload,
  secretsweepPayload,
  validateCorpusShape
} from '../src/corpora.mjs';

const ID_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789'.split('');

function idSuffix() {
  return fc.array(fc.constantFrom(...ID_CHARS), { minLength: 4, maxLength: 10 }).map((items) => items.join(''));
}

function entry(kind, index, suffix) {
  const output = {
    id: kind + '-' + index + '-' + suffix,
    title: kind + ' generated case ' + index,
    input: kind + '-input-' + index,
    why: 'generated deterministic corpus invariant case'
  };
  if (kind === 'hostile') output.cwe = 'CWE-20';
  return output;
}

function validCorpus(suffix) {
  return {
    suite: 'generated-suite',
    package: 'generated-package',
    title: 'generated corpus',
    attackSurface: 'generated attack surface',
    primaryCwe: 'CWE-20',
    references: [{ type: 'CWE', id: 'CWE-20', url: 'https://cwe.mitre.org/data/definitions/20.html' }],
    hostile: Array.from({ length: 8 }, (_, index) => entry('hostile', index, suffix)),
    benign: Array.from({ length: 8 }, (_, index) => entry('benign', index, suffix))
  };
}

test('positive: well-formed generated corpora are accepted', () => {
  fc.assert(fc.property(idSuffix(), (suffix) => {
    assert.deepEqual(validateCorpusShape(validCorpus(suffix)), []);
  }), { seed: 20261127, numRuns: 100 });
});

test('negative: malformed corpus mutations are rejected', () => {
  const mutation = fc.constantFrom('duplicate-id', 'missing-cwe', 'too-few-hostile', 'missing-references');
  fc.assert(fc.property(idSuffix(), mutation, (suffix, kind) => {
    const corpus = validCorpus(suffix);
    if (kind === 'duplicate-id') corpus.benign[0].id = corpus.hostile[0].id;
    if (kind === 'missing-cwe') delete corpus.hostile[0].cwe;
    if (kind === 'too-few-hostile') corpus.hostile = corpus.hostile.slice(0, 7);
    if (kind === 'missing-references') corpus.references = [];
    assert.ok(validateCorpusShape(corpus).length > 0, kind);
  }), { seed: 20261127, numRuns: 100 });
});

test('positive: generated payload inputs materialize within their requested bounds', () => {
  fc.assert(fc.property(
    fc.integer({ min: 1, max: 24 }),
    fc.integer({ min: 0, max: 128 }),
    (depth, length) => {
      const nested = nestedJsonPayload(depth);
      assert.equal((nested.match(/"nested":/g) || []).length, depth);
      assert.doesNotThrow(() => JSON.parse(nested));
      const long = longStringJsonPayload(length);
      assert.equal(JSON.parse(long).text.length, length);
      assert.equal(materializeInput({ generate: 'nested-json', depth }), nested);
    }
  ), { seed: 20261127, numRuns: 100 });
});

test('negative: malformed generator inputs and hostile adapter failures are contained', async () => {
  const invalidDepth = fc.oneof(fc.constant(0), fc.constant(-1), fc.constant(1.5), fc.constant(Number.NaN));
  await fc.assert(fc.asyncProperty(invalidDepth, fc.string({ minLength: 1, maxLength: 16 }), async (depth, unknownKind) => {
    assert.throws(() => nestedJsonPayload(depth));
    assert.throws(() => secretsweepPayload('unknown-' + unknownKind));
    const cases = [
      { id: 'hostile-case', kind: 'hostile', input: 'x', prepared: 'x' },
      { id: 'benign-case', kind: 'benign', input: 'x', prepared: 'x' }
    ];
    const adapter = {
      invoke(benchCase) {
        if (benchCase.kind === 'hostile') {
          const error = new Error('hostile adapter failure');
          error.code = 'ERR_GENERATED hostile';
          throw error;
        }
        return { blocked: false, signal: 'ok' };
      }
    };
    const results = await evaluateCorrectness(adapter, cases);
    assert.equal(results[0].signal, 'harness-error');
    assert.equal(results[0].blocked, false);
    const summary = summarizeCorrectness(results);
    assert.equal(summary.hostileErrors, 1);
    assert.equal(summary.benignErrors, 0);
  }), { seed: 20261127, numRuns: 80 });
});

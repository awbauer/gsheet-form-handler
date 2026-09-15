import test from 'node:test';
import assert from 'node:assert/strict';

import { normalizePayload, stampIdentity, RESERVED_KEYS, MAX_VALUE_LENGTH } from '../src/payload.js';

function codeOf(fn) {
  try {
    fn();
  } catch (err) {
    return err.code;
  }
  return null;
}

test('a flat object passes through unchanged', () => {
  assert.deepEqual(normalizePayload({ name: 'Ada', count: 3, ok: true }), { name: 'Ada', count: 3, ok: true });
});

test('a body that is not an object of fields is rejected', () => {
  assert.equal(codeOf(() => normalizePayload([1, 2])), 'invalid_payload');
  assert.equal(codeOf(() => normalizePayload('hello')), 'invalid_payload');
  assert.equal(codeOf(() => normalizePayload(null)), 'invalid_payload');
  assert.equal(codeOf(() => normalizePayload({})), 'invalid_payload');
});

test('reserved keys are stripped so a submitter cannot forge provenance', () => {
  const data = normalizePayload({ name: 'Ada', _identity: 'root@example.com', _received_at: '1999', secret: 'hunter2' });
  assert.deepEqual(data, { name: 'Ada' });
  assert.deepEqual(RESERVED_KEYS, ['_received_at', '_identity', 'secret']);
});

test('unusable field names and oversized values are rejected', () => {
  assert.equal(codeOf(() => normalizePayload({ '   ': 'x' })), 'invalid_field_name');
  assert.equal(codeOf(() => normalizePayload({ ['k'.repeat(300)]: 'x' })), 'invalid_field_name');
  assert.equal(codeOf(() => normalizePayload({ note: 'x'.repeat(MAX_VALUE_LENGTH + 1) })), 'field_too_large');
});

test('field names are trimmed so " name" and "name" are one column', () => {
  assert.deepEqual(normalizePayload({ '  name  ': 'Ada' }), { name: 'Ada' });
});

test('stamping puts provenance first and does not disturb the fields', () => {
  const at = new Date('2026-01-02T03:04:05.000Z');
  const row = stampIdentity({ name: 'Ada' }, { label: 'ada@example.com' }, at);
  assert.deepEqual(Object.keys(row), ['_received_at', '_identity', 'name']);
  assert.equal(row._received_at, '2026-01-02T03:04:05.000Z');
  assert.equal(row._identity, 'ada@example.com');
});

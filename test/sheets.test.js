import test from 'node:test';
import assert from 'node:assert/strict';

import { quoteTabName, diffHeaders, assertHeadersMatch, cellValue, buildRow } from '../src/sheets.js';

function failure(fn) {
  try {
    fn();
  } catch (err) {
    return err;
  }
  return null;
}

test('a tab name with a quote in it survives A1 notation', () => {
  assert.equal(quoteTabName('Responses'), "'Responses'");
  assert.equal(quoteTabName("Ada's form"), "'Ada''s form'");
});

test('a submission matching the header row exactly is accepted', () => {
  assert.deepEqual(diffHeaders(['name', 'email'], { name: 'Ada', email: 'a@b.test' }), {
    unexpected: [],
    missing: [],
  });
  // Key order in JSON carries no meaning, so it is not a mismatch.
  assert.doesNotThrow(() => assertHeadersMatch(['name', 'email'], { email: 'a@b.test', name: 'Ada' }));
});

test('a field the sheet has no column for is rejected', () => {
  const err = failure(() => assertHeadersMatch(['name', 'email'], { name: 'Ada', email: 'a@b.test', phone: '123' }));
  assert.equal(err.code, 'header_mismatch');
  assert.equal(err.status, 409);
  assert.match(err.detail, /fields not in the sheet: phone/);
});

test('a renamed field reads as one unexpected field and one missing column', () => {
  const { unexpected, missing } = diffHeaders(['name', 'email'], { name: 'Ada', emailAddress: 'a@b.test' });
  assert.deepEqual(unexpected, ['emailAddress']);
  assert.deepEqual(missing, ['email']);
});

test('an omitted column is rejected by default and allowed opt-in', () => {
  const err = failure(() => assertHeadersMatch(['name', 'email'], { name: 'Ada' }));
  assert.equal(err.code, 'header_mismatch');
  assert.match(err.detail, /columns the submission did not include: email/);

  assert.doesNotThrow(() => assertHeadersMatch(['name', 'email'], { name: 'Ada' }, { allowMissingFields: true }));
  // allowMissingFields forgives absence, never an unknown field.
  assert.equal(
    failure(() => assertHeadersMatch(['name'], { name: 'Ada', phone: '123' }, { allowMissingFields: true })).code,
    'header_mismatch',
  );
});

test('the error names the tab so it is obvious which sheet drifted', () => {
  const err = failure(() => assertHeadersMatch(['name'], { nome: 'Ada' }, { tab: 'Q3 intake' }));
  assert.match(err.detail, /"Q3 intake"/);
});

test('values are written verbatim; structure is serialised', () => {
  // valueInputOption=RAW means a leading = is stored, not evaluated, so the
  // Apps Script apostrophe guard is not needed and legitimate values survive.
  assert.equal(cellValue('=1+1'), '=1+1');
  assert.equal(cellValue('-5'), '-5');
  assert.equal(cellValue(42), 42);
  assert.equal(cellValue(true), true);
  assert.equal(cellValue(null), '');
  assert.equal(cellValue(undefined), '');
  assert.equal(cellValue({ a: 1 }), '{"a":1}');
  assert.equal(cellValue(['a', 'b']), '["a","b"]');
});

test('the row is built in header order with blanks for absent fields', () => {
  assert.deepEqual(buildRow(['name', 'email', 'phone'], { phone: '123', name: 'Ada' }), ['Ada', '', '123']);
  assert.deepEqual(buildRow([], { name: 'Ada' }), []);
});

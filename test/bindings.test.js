import test from 'node:test';
import assert from 'node:assert/strict';

import { parseBindings, audiences, principalAllowed, groupsAllowed, selectBinding } from '../src/bindings.js';

const AUD = 'aud-finance';

function env(bindings) {
  return { SHEET_BINDINGS: bindings };
}

function user(overrides = {}) {
  return { type: 'user', aud: AUD, email: 'ada@example.com', commonName: null, idpGroups: [], label: 'ada@example.com', ...overrides };
}

const noGroups = async () => {
  throw new Error('get-identity should not have been called');
};

async function codeOf(promise) {
  try {
    await promise;
  } catch (err) {
    return err.code;
  }
  return null;
}

test('bindings parse from an object or a JSON string', () => {
  const asObject = parseBindings(env([{ aud: AUD, sheetId: 'sheet-1' }]));
  const asString = parseBindings(env(JSON.stringify([{ aud: AUD, sheetId: 'sheet-1' }])));
  assert.equal(asObject[0].sheetId, 'sheet-1');
  assert.deepEqual(asString[0], asObject[0]);
  // The label falls back to the sheet id so errors always name something.
  assert.equal(asObject[0].label, 'sheet-1');
});

test('misconfiguration is reported rather than defaulted away', async () => {
  assert.equal(await codeOf(Promise.resolve().then(() => parseBindings(env('not json')))), 'not_configured');
  assert.equal(await codeOf(Promise.resolve().then(() => parseBindings(env([])))), 'not_configured');
  assert.equal(await codeOf(Promise.resolve().then(() => parseBindings(env([{ sheetId: 'x' }])))), 'not_configured');
  assert.equal(await codeOf(Promise.resolve().then(() => parseBindings(env([{ aud: AUD }])))), 'not_configured');
});

test('the audience set is what the JWT is verified against', () => {
  const bindings = parseBindings(env([{ aud: 'a', sheetId: '1' }, { aud: 'b', sheetId: '2' }]));
  assert.deepEqual([...audiences(bindings)].sort(), ['a', 'b']);
});

test('a binding with no constraints admits anyone Access let through', () => {
  const [binding] = parseBindings(env([{ aud: AUD, sheetId: 'sheet-1' }]));
  assert.equal(principalAllowed(binding, user()), true);
  assert.equal(principalAllowed(binding, user({ email: 'anyone@elsewhere.test' })), true);
});

test('principal constraints match emails, domains and service tokens', () => {
  const [binding] = parseBindings(
    env([
      {
        aud: AUD,
        sheetId: 'sheet-1',
        requireEmails: ['Ada@Example.com'],
        requireEmailDomains: ['@partner.test'],
        requireServiceTokens: ['ci.access'],
      },
    ]),
  );
  assert.equal(principalAllowed(binding, user({ email: 'ada@example.com' })), true);
  assert.equal(principalAllowed(binding, user({ email: 'bob@partner.test' })), true);
  assert.equal(principalAllowed(binding, user({ email: 'bob@elsewhere.test' })), false);
  assert.equal(
    principalAllowed(binding, user({ type: 'service_token', email: null, commonName: 'ci.access' })),
    true,
  );
  assert.equal(
    principalAllowed(binding, user({ type: 'service_token', email: null, commonName: 'other.access' })),
    false,
  );
});

test('idp group constraints are satisfied without touching get-identity', async () => {
  const [binding] = parseBindings(env([{ aud: AUD, sheetId: 'sheet-1', requireIdpGroups: ['Finance-Team'] }]));
  assert.equal(await groupsAllowed(binding, user({ idpGroups: ['Finance-Team'] }), noGroups), true);
});

test('access group constraints fall through to get-identity only when needed', async () => {
  const [binding] = parseBindings(
    env([{ aud: AUD, sheetId: 'sheet-1', requireIdpGroups: ['Finance-Team'], requireAccessGroups: ['Finance'] }]),
  );
  let calls = 0;
  const load = async () => {
    calls += 1;
    return ['Finance'];
  };

  // The claim satisfies it, so the subrequest is never made...
  assert.equal(await groupsAllowed(binding, user({ idpGroups: ['Finance-Team'] }), noGroups), true);
  // ...but when the claim was trimmed away, the endpoint is authoritative.
  assert.equal(await groupsAllowed(binding, user({ idpGroups: [] }), load), true);
  assert.equal(calls, 1);
});

test('the sheet is selected by audience, and paths disambiguate one app serving several', async () => {
  const bindings = env([
    { aud: AUD, sheetId: 'finance-sheet', path: '/submit/finance' },
    { aud: AUD, sheetId: 'hr-sheet', path: '/submit/hr' },
    { aud: 'aud-other', sheetId: 'other-sheet' },
  ]);

  const finance = await selectBinding(bindings, user(), new URL('https://forms.test/submit/finance'), noGroups);
  assert.equal(finance.sheetId, 'finance-sheet');

  const hr = await selectBinding(bindings, user(), new URL('https://forms.test/submit/hr'), noGroups);
  assert.equal(hr.sheetId, 'hr-sheet');

  assert.equal(
    await codeOf(selectBinding(bindings, user(), new URL('https://forms.test/submit/payroll'), noGroups)),
    'no_sheet_for_application',
  );
});

test('a caller who passes Access but fails a binding constraint is refused', async () => {
  const bindings = env([{ aud: AUD, sheetId: 'finance-sheet', requireEmailDomains: ['example.com'] }]);
  assert.equal(
    await codeOf(selectBinding(bindings, user({ email: 'bob@elsewhere.test' }), new URL('https://forms.test/'), noGroups)),
    'not_authorized',
  );
});

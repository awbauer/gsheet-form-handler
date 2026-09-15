import test from 'node:test';
import assert from 'node:assert/strict';

import {
  parseSheetAccess,
  configuredAudiences,
  audienceAllowed,
  principalAllowed,
  groupsAllowed,
  callerMayWrite,
  sheetKeyFrom,
  resolveSheet,
  writableSheets,
} from '../src/sheet-access.js';

const FINANCE_AUD = 'aud-finance';
const ADMIN_AUD = 'aud-admin';
const OTHER_AUD = 'aud-unrelated';

function env(access, rest = {}) {
  return { SHEET_ACCESS: access, ...rest };
}

function user(overrides = {}) {
  return {
    type: 'user',
    auds: [FINANCE_AUD],
    email: 'ada@example.com',
    commonName: null,
    idpGroups: [],
    label: 'ada@example.com',
    ...overrides,
  };
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

function sheet(access, id) {
  return parseSheetAccess(env(access)).get(id);
}

test('the array shorthand and the object form describe the same sheet', () => {
  const short = sheet({ 'sheet-1': [FINANCE_AUD] }, 'sheet-1');
  const long = sheet({ 'sheet-1': { auds: [FINANCE_AUD] } }, 'sheet-1');
  assert.deepEqual(short, long);
  assert.equal(short.sheetId, 'sheet-1');
  assert.equal(short.open, false);
  // The label falls back to the id so errors and /whoami always name something.
  assert.equal(short.label, 'sheet-1');
});

test('sheets parse from a JSON string as well as an object', () => {
  const asString = parseSheetAccess(env(JSON.stringify({ 'sheet-1': [FINANCE_AUD] })));
  assert.deepEqual(asString.get('sheet-1').auds, [FINANCE_AUD]);
});

test('misconfiguration is reported rather than defaulted away', async () => {
  const fails = (value) => codeOf(Promise.resolve().then(() => parseSheetAccess(env(value))));
  assert.equal(await fails('not json'), 'not_configured');
  assert.equal(await fails({}), 'not_configured');
  assert.equal(await fails([['sheet-1', []]]), 'not_configured');
  // Omitting auds is a mistake; allowing anyone has to be written as [].
  assert.equal(await fails({ 'sheet-1': { label: 'no auds' } }), 'not_configured');
});

test('an empty array marks the sheet open to any authenticated caller', () => {
  const open = sheet({ 'sheet-1': [] }, 'sheet-1');
  assert.equal(open.open, true);
  assert.equal(audienceAllowed(open, user({ auds: [OTHER_AUD] })), true);
});

test('a listed sheet admits only the applications it names', () => {
  const listed = sheet({ 'sheet-1': [FINANCE_AUD, ADMIN_AUD] }, 'sheet-1');
  assert.equal(audienceAllowed(listed, user({ auds: [FINANCE_AUD] })), true);
  assert.equal(audienceAllowed(listed, user({ auds: [ADMIN_AUD] })), true);
  assert.equal(audienceAllowed(listed, user({ auds: [OTHER_AUD] })), false);
  // A token carrying several audiences is allowed on any one of them.
  assert.equal(audienceAllowed(listed, user({ auds: [OTHER_AUD, ADMIN_AUD] })), true);
});

test('several applications can share one sheet, and one application several sheets', async () => {
  const config = env({ 'sheet-1': [FINANCE_AUD, ADMIN_AUD], 'sheet-2': [ADMIN_AUD] });
  const admin = user({ auds: [ADMIN_AUD] });
  assert.deepEqual(
    (await writableSheets(config, admin, noGroups)).map((entry) => entry.sheetId),
    ['sheet-1', 'sheet-2'],
  );
  assert.deepEqual(
    (await writableSheets(config, user({ auds: [FINANCE_AUD] }), noGroups)).map((entry) => entry.sheetId),
    ['sheet-1'],
  );
});

test('the audience union pins the JWT check, unless some sheet is open', () => {
  assert.deepEqual(
    [...configuredAudiences(parseSheetAccess(env({ 'sheet-1': [FINANCE_AUD], 'sheet-2': [ADMIN_AUD] })))].sort(),
    [ADMIN_AUD, FINANCE_AUD],
  );
  // One open sheet means any team-issued token has to get past step one, so
  // there is nothing left to pin against.
  assert.equal(configuredAudiences(parseSheetAccess(env({ 'sheet-1': [FINANCE_AUD], 'sheet-2': [] }))), null);
});

test('narrowing constraints still apply to an open sheet', async () => {
  const narrowed = sheet({ 'sheet-1': { auds: [], requireEmailDomains: ['example.com'] } }, 'sheet-1');
  assert.equal(await callerMayWrite(narrowed, user({ email: 'ada@example.com' }), noGroups), true);
  assert.equal(await callerMayWrite(narrowed, user({ email: 'bob@elsewhere.test' }), noGroups), false);
});

test('principal constraints match emails, domains and service tokens', () => {
  const narrowed = sheet(
    {
      'sheet-1': {
        auds: [FINANCE_AUD],
        requireEmails: ['Ada@Example.com'],
        requireEmailDomains: ['@partner.test'],
        requireServiceTokens: ['ci.access'],
      },
    },
    'sheet-1',
  );
  assert.equal(principalAllowed(narrowed, user({ email: 'ada@example.com' })), true);
  assert.equal(principalAllowed(narrowed, user({ email: 'bob@partner.test' })), true);
  assert.equal(principalAllowed(narrowed, user({ email: 'bob@elsewhere.test' })), false);
  assert.equal(
    principalAllowed(narrowed, user({ type: 'service_token', email: null, commonName: 'ci.access' })),
    true,
  );
});

test('access group constraints fall through to get-identity only when needed', async () => {
  const narrowed = sheet(
    { 'sheet-1': { auds: [FINANCE_AUD], requireIdpGroups: ['Finance-Team'], requireAccessGroups: ['Finance'] } },
    'sheet-1',
  );
  let calls = 0;
  const load = async () => {
    calls += 1;
    return ['Finance'];
  };

  assert.equal(await groupsAllowed(narrowed, user({ idpGroups: ['Finance-Team'] }), noGroups), true);
  // The claim can be trimmed away by Access, so the endpoint is authoritative.
  assert.equal(await groupsAllowed(narrowed, user({ idpGroups: [] }), load), true);
  assert.equal(calls, 1);
});

test('the sheet is named by query parameter, path, or the configured default', () => {
  const plain = env({}, {});
  assert.equal(sheetKeyFrom(new URL('https://forms.test/submit?SHEET_ID=abc'), plain), 'abc');
  assert.equal(sheetKeyFrom(new URL('https://forms.test/submit?sheet_id=abc'), plain), 'abc');
  assert.equal(sheetKeyFrom(new URL('https://forms.test/submit/abc'), plain), 'abc');
  assert.equal(sheetKeyFrom(new URL('https://forms.test/submit/a%2Fb'), plain), 'a/b');
  assert.equal(sheetKeyFrom(new URL('https://forms.test/'), { DEFAULT_SHEET_ID: 'fallback' }), 'fallback');
  assert.equal(sheetKeyFrom(new URL('https://forms.test/'), plain), null);
  // An explicit parameter beats the default.
  assert.equal(sheetKeyFrom(new URL('https://forms.test/?SHEET_ID=abc'), { DEFAULT_SHEET_ID: 'fallback' }), 'abc');
});

test('a request that names no sheet is a client error, not a denial', async () => {
  assert.equal(
    await codeOf(resolveSheet(env({ 'sheet-1': [FINANCE_AUD] }), user(), new URL('https://forms.test/'), noGroups)),
    'sheet_not_specified',
  );
});

test('an unconfigured sheet and a forbidden sheet are indistinguishable', async () => {
  const config = env({ 'sheet-1': [FINANCE_AUD] });
  const unknown = await codeOf(
    resolveSheet(config, user(), new URL('https://forms.test/submit/does-not-exist'), noGroups),
  );
  const forbidden = await codeOf(
    resolveSheet(config, user({ auds: [OTHER_AUD] }), new URL('https://forms.test/submit/sheet-1'), noGroups),
  );
  assert.equal(unknown, 'not_authorized');
  assert.equal(forbidden, 'not_authorized');
});

test('an allowed caller resolves to the sheet they named', async () => {
  const resolved = await resolveSheet(
    env({ 'sheet-1': { auds: [FINANCE_AUD], label: 'finance intake', tab: 'Q3' } }),
    user(),
    new URL('https://forms.test/submit/sheet-1'),
    noGroups,
  );
  assert.equal(resolved.sheetId, 'sheet-1');
  assert.equal(resolved.label, 'finance intake');
  assert.equal(resolved.tab, 'Q3');
});

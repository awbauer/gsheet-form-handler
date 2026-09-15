import test from 'node:test';
import assert from 'node:assert/strict';

import { authenticate, identityFrom, extractGroupNames } from '../src/access.js';

const AUD = '32eafc7626e974616deaf0dc3ce63d7bcbed58a2731e84d06bc3cdf1b53c4228';

function ctxWith(identity, aud = AUD) {
  return { access: { aud, getIdentity: async () => identity } };
}

async function codeOf(promise) {
  try {
    await promise;
  } catch (err) {
    return err.code;
  }
  return null;
}

test('a request Access did not authenticate carries no identity and is refused', async () => {
  // ctx.access is undefined for a request that did not come through Access,
  // including one hitting a route Access is not in front of.
  assert.equal(await codeOf(authenticate({})), 'access_jwt_missing');
  assert.equal(await codeOf(authenticate(undefined)), 'access_jwt_missing');
});

test('the caller is identified by the email Access returned, lower-cased', async () => {
  const identity = await authenticate(ctxWith({ email: 'Ada@Example.com' }));
  assert.equal(identity.type, 'user');
  assert.equal(identity.email, 'ada@example.com');
  assert.equal(identity.label, 'ada@example.com');
});

test('the application Access matched becomes the caller audience list', async () => {
  const identity = await authenticate(ctxWith({ email: 'ada@example.com' }));
  assert.deepEqual(identity.auds, [AUD]);
  // A sheet's `auds` is a list, so the check stays a set intersection even
  // though Access matches exactly one application per request.
  assert.deepEqual(identityFrom(undefined, { email: 'ada@example.com' }).auds, []);
});

test('a caller with no email is refused rather than written with blank provenance', async () => {
  // A service token reaches ctx.access but has no IdP identity behind it, so
  // getIdentity() comes back without an email.
  assert.equal(await codeOf(authenticate(ctxWith({}))), 'access_identity_unknown');
  assert.equal(await codeOf(authenticate(ctxWith(null))), 'access_identity_unknown');
  assert.equal(await codeOf(authenticate(ctxWith({ email: '   ' }))), 'access_identity_unknown');
});

test('groups reach the identity through the authenticated caller', async () => {
  const identity = await authenticate(
    ctxWith({ email: 'ada@example.com', groups: ['Finance'], idp: { attributes: { groups: ['Engineering'] } } }),
  );
  assert.deepEqual(identity.groups.sort(), ['Engineering', 'Finance']);
});

test('group names are gathered from every place the identity puts them', () => {
  const groups = extractGroupNames({
    groups: [{ id: '1', name: 'Finance', email: 'finance@example.com' }, 'Ops'],
    idp: { attributes: { groups: ['Engineering'] } },
  });
  assert.deepEqual(groups.sort(), ['Engineering', 'Finance', 'Ops', 'finance@example.com']);
  assert.deepEqual(extractGroupNames({}), []);
});

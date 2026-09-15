import test from 'node:test';
import assert from 'node:assert/strict';

import {
  normalizeTeamDomain,
  issuerFor,
  validateClaims,
  identityFromClaims,
  collectIdpGroups,
  extractGroupNames,
} from '../src/access.js';

const ISSUER = 'https://acme.cloudflareaccess.com';
const AUD = '32eafc7626e974616deaf0dc3ce63d7bcbed58a2731e84d06bc3cdf1b53c4228';
const NOW = 1_700_000_000;

function claims(overrides = {}) {
  return { iss: ISSUER, aud: [AUD], exp: NOW + 600, iat: NOW - 10, email: 'ada@example.com', ...overrides };
}

function codeOf(fn) {
  try {
    fn();
  } catch (err) {
    return err.code;
  }
  return null;
}

test('team domain accepts a bare team name or a full hostname', () => {
  assert.equal(normalizeTeamDomain('acme'), 'acme.cloudflareaccess.com');
  assert.equal(normalizeTeamDomain('acme.cloudflareaccess.com'), 'acme.cloudflareaccess.com');
  assert.equal(normalizeTeamDomain('https://acme.cloudflareaccess.com/'), 'acme.cloudflareaccess.com');
  assert.equal(normalizeTeamDomain(''), '');
  assert.equal(issuerFor('acme'), ISSUER);
});

test('a well-formed token returns the audience that matched', () => {
  const result = validateClaims(claims(), { issuer: ISSUER, audiences: new Set([AUD]), now: NOW });
  assert.equal(result.aud, AUD);
});

test('claims are rejected for issuer, audience, expiry and future validity', () => {
  const audiences = new Set([AUD]);
  assert.equal(
    codeOf(() => validateClaims(claims({ iss: 'https://evil.cloudflareaccess.com' }), { issuer: ISSUER, audiences, now: NOW })),
    'access_jwt_wrong_issuer',
  );
  assert.equal(
    codeOf(() => validateClaims(claims({ aud: ['someone-elses-app'] }), { issuer: ISSUER, audiences, now: NOW })),
    'access_jwt_wrong_audience',
  );
  assert.equal(
    codeOf(() => validateClaims(claims({ exp: NOW - 3600 }), { issuer: ISSUER, audiences, now: NOW })),
    'access_jwt_expired',
  );
  assert.equal(
    codeOf(() => validateClaims(claims({ nbf: NOW + 3600 }), { issuer: ISSUER, audiences, now: NOW })),
    'access_jwt_not_yet_valid',
  );
});

test('a token valid for two configured applications is refused rather than guessed', () => {
  const other = 'other-aud';
  assert.equal(
    codeOf(() =>
      validateClaims(claims({ aud: [AUD, other] }), { issuer: ISSUER, audiences: new Set([AUD, other]), now: NOW }),
    ),
    'access_jwt_ambiguous_audience',
  );
});

test('a small clock skew either way is tolerated', () => {
  const audiences = new Set([AUD]);
  assert.doesNotThrow(() => validateClaims(claims({ exp: NOW - 30 }), { issuer: ISSUER, audiences, now: NOW }));
  assert.doesNotThrow(() => validateClaims(claims({ iat: NOW + 30 }), { issuer: ISSUER, audiences, now: NOW }));
});

test('a user identity comes from the email claim, lower-cased', () => {
  const identity = identityFromClaims(claims({ email: 'Ada@Example.com' }), AUD);
  assert.equal(identity.type, 'user');
  assert.equal(identity.email, 'ada@example.com');
  assert.equal(identity.label, 'ada@example.com');
  assert.equal(identity.aud, AUD);
});

test('a service token identity comes from common_name, as Access sends it', () => {
  // Shape taken from the Cloudflare docs: no email, empty sub.
  const identity = identityFromClaims(
    { iss: ISSUER, aud: [AUD], exp: NOW + 600, common_name: 'e367826f93b8d71185e03fe518aff3b4.access', sub: '' },
    AUD,
  );
  assert.equal(identity.type, 'service_token');
  assert.equal(identity.email, null);
  assert.equal(identity.label, 'service-token:e367826f93b8d71185e03fe518aff3b4.access');
});

test('a token with no principal at all is refused', () => {
  assert.equal(
    codeOf(() => identityFromClaims({ iss: ISSUER, aud: [AUD], exp: NOW + 600 }, AUD)),
    'access_identity_unknown',
  );
});

test('idp groups are read from either the top-level or custom claim', () => {
  assert.deepEqual(collectIdpGroups({ groups: ['a'] }), ['a']);
  assert.deepEqual(collectIdpGroups({ custom: { groups: ['b', 'c'] } }), ['b', 'c']);
  assert.deepEqual(collectIdpGroups({ groups: 'a', custom: { groups: ['a', 'b'] } }), ['a', 'b']);
  // Access trims the custom claim at ~1KB, so an absent claim must not throw.
  assert.deepEqual(collectIdpGroups({}), []);
});

test('group names are gathered from every place get-identity puts them', () => {
  const groups = extractGroupNames({
    groups: [{ id: '1', name: 'Finance', email: 'finance@example.com' }, 'Ops'],
    idp: { attributes: { groups: ['Engineering'] } },
  });
  assert.deepEqual(groups.sort(), ['Engineering', 'Finance', 'Ops', 'finance@example.com']);
  assert.deepEqual(extractGroupNames({}), []);
});

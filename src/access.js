// Cloudflare Access identity.
//
// Access authenticates the request at the edge, before this Worker runs, and
// the runtime hands the result over as `ctx.access`: undefined when Access did
// not authenticate the request, otherwise the AUD of the application it
// matched plus a getIdentity() call for the signed-in user.
//
// There is no JWT handling here on purpose. The runtime has already verified
// the token against Access's own signing keys for this account, so there is no
// signature to check, no issuer to pin, and no key rotation to cache — and an
// unverified token cannot reach this code at all. `ctx.access` is undefined for
// a request that did not come through Access, which is the same answer the old
// hand-rolled verification arrived at, minus the cryptography.
//
// `ctx.access.aud` names the Access application the caller came through.
// src/sheet-access.js checks it against the list of applications allowed to
// write the sheet the request named.
//
// This Worker serves browser submissions, so every caller is a signed-in human
// identified by their email. A service token reaches `ctx.access` but has no
// IdP identity behind it, so getIdentity() returns no email and the request is
// refused here rather than written to a sheet with blank provenance.

import { HttpError } from './http.js';

// getIdentity() returns the identity shape Access publishes, which carries
// group names in more than one place depending on the IdP: Access's own groups,
// and the IdP's attributes. Take names from wherever they appear rather than
// assuming one shape.
export function extractGroupNames(identity) {
  const names = new Set();
  const add = (value) => {
    if (typeof value === 'string' && value.trim()) names.add(value.trim());
  };

  for (const group of identity.groups || []) {
    if (typeof group === 'string') add(group);
    else if (group && typeof group === 'object') {
      add(group.name);
      add(group.email);
    }
  }

  const idp = identity.idp || {};
  for (const source of [idp.groups, idp.attributes && idp.attributes.groups, idp.attributes && idp.attributes.Groups]) {
    if (Array.isArray(source)) for (const entry of source) add(entry);
    else add(source);
  }

  return [...names];
}

// Exported for tests: everything about a caller that this Worker cares about,
// built from the matched application and the identity Access returned.
export function identityFrom(aud, raw) {
  const source = raw || {};
  const email =
    typeof source.email === 'string' && source.email.trim() ? source.email.trim().toLowerCase() : null;

  if (!email) {
    throw new HttpError(
      403,
      'access_identity_unknown',
      'Access authenticated the request but returned no email for the caller',
    );
  }

  return {
    type: 'user',
    // Kept as a list because a sheet's `auds` is a list and the check is a set
    // intersection; Access matches exactly one application per request.
    auds: typeof aud === 'string' && aud ? [aud] : [],
    email,
    groups: extractGroupNames(source),
    label: email,
  };
}

export async function authenticate(ctx) {
  const access = ctx && ctx.access;
  if (!access) {
    throw new HttpError(401, 'access_jwt_missing', 'request did not come through Cloudflare Access');
  }

  return identityFrom(access.aud, await access.getIdentity());
}

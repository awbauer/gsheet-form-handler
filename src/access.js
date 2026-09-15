// Cloudflare Access identity.
//
// Access puts a signed JWT on every request that passes through it, in the
// `Cf-Access-Jwt-Assertion` header (and in the `CF_Authorization` cookie for
// browser sessions). Reading that header is NOT enough on its own: a Worker
// route is still reachable by anyone who can resolve its hostname, and any
// client can invent a header. So the token is verified here against the team's
// published signing keys, and its audience must be one of the Access
// applications this Worker is configured for. An unverified header is treated
// as no header at all.
//
// Two kinds of principal arrive through the same token:
//   * a human, identified by the `email` claim;
//   * a service token (the usual choice for a server-side form backend),
//     identified by `common_name`, with an empty `sub` and no email.
//
// The `aud` claim names the Access application the caller was authorized for.
// src/sheet-access.js checks it against the list of applications allowed to
// write the sheet the request named.

import { HttpError } from './http.js';

const JWKS_TTL_MS = 60 * 60 * 1000; // Access rotates signing keys periodically.
const CLOCK_SKEW_SECONDS = 60;

// Keyed by issuer. Per-isolate, so only a cold isolate pays the fetch.
const jwksCache = new Map();

export function normalizeTeamDomain(teamDomain) {
  const value = String(teamDomain || '').trim().replace(/^https?:\/\//, '').replace(/\/+$/, '');
  if (!value) return '';
  return value.includes('.') ? value : `${value}.cloudflareaccess.com`;
}

export function issuerFor(teamDomain) {
  const domain = normalizeTeamDomain(teamDomain);
  return domain ? `https://${domain}` : '';
}

function base64UrlDecode(input) {
  const padded = input.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function decodeJsonSegment(segment, what) {
  try {
    return JSON.parse(new TextDecoder().decode(base64UrlDecode(segment)));
  } catch {
    throw new HttpError(401, 'access_jwt_malformed', `could not decode the JWT ${what}`);
  }
}

function readCookie(request, name) {
  const header = request.headers.get('cookie');
  if (!header) return null;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    if (part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return null;
}

export function readAccessToken(request) {
  return request.headers.get('cf-access-jwt-assertion') || readCookie(request, 'CF_Authorization');
}

async function fetchSigningKeys(issuer) {
  const cached = jwksCache.get(issuer);
  if (cached && cached.expiresAt > Date.now()) return cached.keys;

  const response = await fetch(`${issuer}/cdn-cgi/access/certs`, {
    cf: { cacheTtl: 3600, cacheEverything: true },
  });
  if (!response.ok) {
    throw new HttpError(502, 'access_certs_unavailable', `${issuer}/cdn-cgi/access/certs returned ${response.status}`);
  }

  const body = await response.json();
  const keys = new Map();
  for (const jwk of body.keys || []) {
    if (jwk.kty !== 'RSA' || !jwk.kid) continue;
    keys.set(
      jwk.kid,
      await crypto.subtle.importKey(
        'jwk',
        { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify'],
      ),
    );
  }
  if (keys.size === 0) {
    throw new HttpError(502, 'access_certs_unavailable', `no RSA signing keys published at ${issuer}`);
  }

  jwksCache.set(issuer, { keys, expiresAt: Date.now() + JWKS_TTL_MS });
  return keys;
}

// Everything about a token that does not need the network. Returns every
// audience the token carries; which of them may write a given sheet is decided
// per sheet in src/sheet-access.js. Exported for tests.
//
// `audiences` is the union of every audience named in the configuration, used
// to reject a token from an unrelated Access application early. It is null
// when some sheet accepts any authenticated user, since there is then no set to
// pin against — the per-sheet check is the gate in that case.
export function validateClaims(claims, { issuer, audiences, now = Math.floor(Date.now() / 1000) }) {
  if (claims.iss !== issuer) {
    throw new HttpError(403, 'access_jwt_wrong_issuer', `token was issued by ${claims.iss || 'nobody'}, expected ${issuer}`);
  }

  const claimed = Array.isArray(claims.aud) ? claims.aud : claims.aud ? [claims.aud] : [];
  if (claimed.length === 0) {
    throw new HttpError(403, 'access_jwt_wrong_audience', 'token names no Access application');
  }
  if (audiences && !claimed.some((aud) => audiences.has(aud))) {
    throw new HttpError(403, 'access_jwt_wrong_audience', 'token was issued for an Access application this Worker does not know about');
  }

  if (typeof claims.exp !== 'number' || claims.exp + CLOCK_SKEW_SECONDS < now) {
    throw new HttpError(401, 'access_jwt_expired', 'sign in again to get a fresh Access token');
  }

  const notBefore = typeof claims.nbf === 'number' ? claims.nbf : claims.iat;
  if (typeof notBefore === 'number' && notBefore - CLOCK_SKEW_SECONDS > now) {
    throw new HttpError(401, 'access_jwt_not_yet_valid', 'token is not valid yet');
  }

  return { claims, auds: claimed };
}

// IdP groups reach the token only when `groups` is configured as a custom SAML
// attribute or OIDC claim, and Cloudflare trims the `custom` claim at roughly
// 1 KB, so this can come back empty for a user in many groups. Treat it as a
// hint; /cdn-cgi/access/get-identity is the authoritative source.
export function collectIdpGroups(claims) {
  const found = new Set();
  const sources = [claims.groups, claims.custom && claims.custom.groups, claims.custom && claims.custom.Groups];
  for (const source of sources) {
    if (typeof source === 'string') found.add(source);
    else if (Array.isArray(source)) for (const entry of source) if (typeof entry === 'string') found.add(entry);
  }
  return [...found];
}

export function identityFromClaims(claims, auds) {
  const email = typeof claims.email === 'string' && claims.email.trim() ? claims.email.trim().toLowerCase() : null;
  const commonName = typeof claims.common_name === 'string' && claims.common_name.trim() ? claims.common_name.trim() : null;
  const type = email ? 'user' : commonName ? 'service_token' : 'unknown';

  if (type === 'unknown') {
    throw new HttpError(403, 'access_identity_unknown', 'Access token carries neither an email nor a service-token name');
  }

  return {
    type,
    auds,
    email,
    commonName,
    idpGroups: collectIdpGroups(claims),
    label: email || `service-token:${commonName}`,
    expiresAt: claims.exp,
  };
}

// Authoritative Access/IdP group membership, fetched from the identity
// endpoint that Cloudflare serves on the application's own hostname. Only
// called when a binding declares requireAccessGroups, because it costs a
// subrequest per submission.
export async function fetchAccessGroups(request, identity) {
  if (identity.type === 'service_token') return []; // A service token has no IdP identity.

  const token = readAccessToken(request);
  const url = new URL(request.url);
  const response = await fetch(`${url.origin}/cdn-cgi/access/get-identity`, {
    headers: { cookie: `CF_Authorization=${token}` },
  });
  if (!response.ok) {
    throw new HttpError(502, 'access_identity_unavailable', `get-identity returned ${response.status}`);
  }

  return extractGroupNames(await response.json().catch(() => ({})));
}

// The identity payload carries groups in more than one place depending on the
// IdP: top-level Access groups, and the IdP's own attributes. Take names from
// wherever they appear rather than assuming one shape.
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

// Verifies the Access JWT on `request` and returns the caller's identity.
export async function authenticate(request, env, audiences) {
  const issuer = issuerFor(env.ACCESS_TEAM_DOMAIN);
  if (!issuer) {
    throw new HttpError(500, 'not_configured', 'ACCESS_TEAM_DOMAIN is not set');
  }

  const token = readAccessToken(request);
  if (!token) {
    throw new HttpError(401, 'access_jwt_missing', 'request did not come through Cloudflare Access');
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new HttpError(401, 'access_jwt_malformed', 'expected a three-part JWT');
  }

  const header = decodeJsonSegment(parts[0], 'header');
  if (header.alg !== 'RS256') {
    throw new HttpError(401, 'access_jwt_malformed', `unsupported signing algorithm ${header.alg}`);
  }

  const keys = await fetchSigningKeys(issuer);
  const key = keys.get(header.kid);
  if (!key) {
    // Either a forged kid, or a key rotation we have cached past. Drop the
    // cache so the next request re-fetches, and fail this one closed.
    jwksCache.delete(issuer);
    throw new HttpError(401, 'access_jwt_unknown_key', 'token was signed with an unrecognised key');
  }

  const verified = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    key,
    base64UrlDecode(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
  );
  if (!verified) {
    throw new HttpError(401, 'access_jwt_bad_signature', 'token signature did not verify');
  }

  const { claims, auds } = validateClaims(decodeJsonSegment(parts[1], 'payload'), { issuer, audiences });
  return identityFromClaims(claims, auds);
}

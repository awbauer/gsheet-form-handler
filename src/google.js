// Google service-account auth + a thin Sheets API client.
//
// The Worker holds a service-account key (GOOGLE_SERVICE_ACCOUNT_JSON secret),
// signs a short-lived assertion with it, and trades that for an OAuth access
// token. There is no user consent flow and no Apps Script runtime in the way:
// every spreadsheet the Worker writes must be shared with the service
// account's own address as an Editor, exactly as you would share it with a
// colleague. Not doing so is the single most common setup mistake, so it gets
// its own error code and names the address to share with.

import { HttpError } from './http.js';

const TOKEN_SCOPE = 'https://www.googleapis.com/auth/spreadsheets';
const SHEETS_API = 'https://sheets.googleapis.com/v4/spreadsheets';
const TOKEN_EXPIRY_SKEW_MS = 60_000;

// Per-isolate token cache. Access tokens last an hour, so this saves a token
// exchange on all but the first request an isolate serves. It is deliberately
// not in KV: an access token is a bearer credential and does not belong in a
// store that is read by every colo.
let cachedToken = null;

export function loadServiceAccount(env) {
  const raw = env.GOOGLE_SERVICE_ACCOUNT_JSON;
  if (!raw) {
    throw new HttpError(500, 'not_configured', 'the GOOGLE_SERVICE_ACCOUNT_JSON secret is not set');
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new HttpError(500, 'not_configured', 'GOOGLE_SERVICE_ACCOUNT_JSON is not valid JSON');
  }

  if (!parsed.client_email || !parsed.private_key) {
    throw new HttpError(500, 'not_configured', 'GOOGLE_SERVICE_ACCOUNT_JSON needs client_email and private_key');
  }

  return {
    clientEmail: parsed.client_email,
    privateKey: parsed.private_key,
    tokenUri: parsed.token_uri || 'https://oauth2.googleapis.com/token',
  };
}

function base64Url(bytes) {
  let binary = '';
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function encodeJson(value) {
  return base64Url(new TextEncoder().encode(JSON.stringify(value)));
}

async function importPrivateKey(pem) {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/, '')
    .replace(/-----END [^-]+-----/, '')
    .replace(/\s+/g, '');
  const binary = atob(body);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);

  try {
    return await crypto.subtle.importKey(
      'pkcs8',
      bytes,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign'],
    );
  } catch {
    throw new HttpError(500, 'not_configured', 'the service-account private_key could not be parsed as PKCS#8');
  }
}

export async function getAccessToken(env) {
  if (cachedToken && cachedToken.expiresAt - TOKEN_EXPIRY_SKEW_MS > Date.now()) {
    return cachedToken.token;
  }

  const account = loadServiceAccount(env);
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: account.clientEmail,
    scope: TOKEN_SCOPE,
    aud: account.tokenUri,
    iat: now,
    exp: now + 3600,
  };

  const unsigned = `${encodeJson({ alg: 'RS256', typ: 'JWT' })}.${encodeJson(claims)}`;
  const key = await importPrivateKey(account.privateKey);
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key,
    new TextEncoder().encode(unsigned),
  );

  const response = await fetch(account.tokenUri, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: `${unsigned}.${base64Url(signature)}`,
    }),
  });

  const body = await response.json().catch(() => ({}));
  if (!response.ok || !body.access_token) {
    // invalid_grant here almost always means the key was revoked or the
    // machine clock is wrong; either way it is a configuration problem.
    throw new HttpError(502, 'google_auth_failed', body.error_description || body.error || `token endpoint returned ${response.status}`);
  }

  cachedToken = {
    token: body.access_token,
    expiresAt: Date.now() + (body.expires_in || 3600) * 1000,
  };
  return cachedToken.token;
}

function sheetsError(status, body, sheetId, serviceAccountEmail) {
  const message = (body && body.error && body.error.message) || `Sheets API returned ${status}`;

  if (status === 401 || status === 403) {
    throw new HttpError(502, 'sheet_not_shared', `share spreadsheet ${sheetId} with ${serviceAccountEmail} as an Editor (Google said: ${message})`);
  }
  if (status === 404) {
    throw new HttpError(502, 'sheet_not_found', `Google has no spreadsheet with id ${sheetId}`);
  }
  if (status === 429 || status >= 500) {
    throw new HttpError(503, 'sheets_api_unavailable', message);
  }
  throw new HttpError(502, 'sheets_api_error', message);
}

// Calls the Sheets API for `sheetId`. `path` is everything after the
// spreadsheet id, e.g. "/values/'Responses'!A1:append?...".
export async function sheetsFetch(env, sheetId, path, init = {}) {
  const token = await getAccessToken(env);
  const response = await fetch(`${SHEETS_API}/${encodeURIComponent(sheetId)}${path}`, {
    ...init,
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      ...(init.headers || {}),
    },
  });

  const body = await response.json().catch(() => null);
  if (!response.ok) {
    sheetsError(response.status, body, sheetId, loadServiceAccount(env).clientEmail);
  }
  return body;
}

// Exported so the Worker can tell an operator which address to share with
// before anything has been written.
export function serviceAccountEmail(env) {
  return loadServiceAccount(env).clientEmail;
}

// Test hook: the token cache is module state, which would otherwise leak
// between tests.
export function __resetTokenCache() {
  cachedToken = null;
}

// A form endpoint that appends submissions to Google Sheets.
//
// Request flow:
//   1. Verify the Cloudflare Access JWT (src/access.js). No valid token, no
//      request — the header is checked cryptographically, not just read.
//   2. Work out which spreadsheet the request is for, and check the caller's
//      Access application is allowed to write it (src/sheet-access.js).
//   3. Parse and sanity-check the body (src/payload.js).
//   4. Append a row with a Google service-account credential (src/google.js,
//      src/sheets.js), rejecting the write if the sheet's header row and the
//      submission have drifted apart.
//
// The Worker only ever appends. It has no endpoint that reads sheet contents
// back out, so a caller who can submit still cannot read other submissions.

import { json, errorResponse, corsHeaders, HttpError } from './http.js';
import { authenticate, fetchAccessGroups } from './access.js';
import { parseSheetAccess, configuredAudiences, resolveSheet, writableSheets } from './sheet-access.js';
import { readPayload, normalizePayload, stampIdentity } from './payload.js';
import { appendRecord } from './sheets.js';
import { serviceAccountEmail } from './google.js';

function resolveTab(env, sheet) {
  return sheet.tab || env.RESPONSES_TAB || 'Responses';
}

function resolveStamp(env, sheet) {
  if (typeof sheet.stamp === 'boolean') return sheet.stamp;
  return String(env.STAMP_IDENTITY ?? 'true') === 'true';
}

// Identity lookups are per-request and at most one per request, however many
// sheets ask for them.
function accessGroupLoader(request, identity) {
  let pending = null;
  return () => {
    if (!pending) pending = fetchAccessGroups(request, identity);
    return pending;
  };
}

async function handleSubmit(request, env, url, identity) {
  const sheet = await resolveSheet(env, identity, url, accessGroupLoader(request, identity));

  const raw = await readPayload(request, env);
  let data = normalizePayload(raw);
  if (resolveStamp(env, sheet)) data = stampIdentity(data, identity);

  const result = await appendRecord(env, sheet.sheetId, resolveTab(env, sheet), data, {
    allowMissingFields: sheet.allowMissingFields,
  });

  return { ok: true, sheet: sheet.label, ...result };
}

// Reports what Access said about the caller and which sheets they may write.
// Useful when a submission is being refused and it is not obvious whether the
// problem is the token, the sheet list, or the sheet itself.
async function handleWhoami(request, env, identity) {
  return {
    ok: true,
    identity: {
      type: identity.type,
      email: identity.email,
      commonName: identity.commonName,
      idpGroups: identity.idpGroups,
      auds: identity.auds,
    },
    sheets: await writableSheets(env, identity, accessGroupLoader(request, identity)),
    serviceAccount: serviceAccountEmail(env),
  };
}

async function handle(request, env, url) {
  if (request.method === 'GET' && url.pathname === '/health') {
    // Unauthenticated on purpose: this says the Worker is running and its
    // configuration parses, and nothing about what it is configured with.
    parseSheetAccess(env);
    return { ok: true };
  }

  const sheets = parseSheetAccess(env);
  const identity = await authenticate(request, env, configuredAudiences(sheets));

  if (request.method === 'GET' && url.pathname === '/whoami') {
    return handleWhoami(request, env, identity);
  }
  if (request.method === 'POST') {
    return handleSubmit(request, env, url, identity);
  }

  throw new HttpError(405, 'method_not_allowed', `${request.method} ${url.pathname} is not an endpoint of this Worker`);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const cors = corsHeaders(request, env);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    try {
      return json(await handle(request, env, url), { headers: cors });
    } catch (err) {
      return errorResponse(err, { headers: cors });
    }
  },
};

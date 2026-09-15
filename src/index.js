// A form endpoint that appends submissions to Google Sheets.
//
// Request flow:
//   1. Read the identity Cloudflare Access attached to the request (ctx.access,
//      see src/access.js). Access authenticates at the edge, so a request that
//      did not come through it arrives with no identity and is refused.
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
import { authenticate } from './access.js';
import { parseSheetAccess, resolveSheet, writableSheets } from './sheet-access.js';
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

async function handleSubmit(request, env, url, identity) {
  const sheet = resolveSheet(env, identity, url);

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
// problem is the caller's identity, the sheet list, or the sheet itself.
function handleWhoami(env, identity) {
  return {
    ok: true,
    identity: {
      type: identity.type,
      email: identity.email,
      groups: identity.groups,
      auds: identity.auds,
    },
    sheets: writableSheets(env, identity),
    serviceAccount: serviceAccountEmail(env),
  };
}

async function handle(request, env, url, ctx) {
  if (request.method === 'GET' && url.pathname === '/health') {
    // Unauthenticated on purpose: this says the Worker is running and its
    // configuration parses, and nothing about what it is configured with.
    parseSheetAccess(env);
    return { ok: true };
  }

  // Parsed before authenticating so a broken SHEET_ACCESS is reported as the
  // configuration error it is, rather than as a denial.
  parseSheetAccess(env);
  const identity = await authenticate(ctx);

  if (request.method === 'GET' && url.pathname === '/whoami') {
    return handleWhoami(env, identity);
  }
  if (request.method === 'POST') {
    return handleSubmit(request, env, url, identity);
  }

  throw new HttpError(405, 'method_not_allowed', `${request.method} ${url.pathname} is not an endpoint of this Worker`);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cors = corsHeaders(request, env);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    try {
      return json(await handle(request, env, url, ctx), { headers: cors });
    } catch (err) {
      return errorResponse(err, { headers: cors });
    }
  },
};

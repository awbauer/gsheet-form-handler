// A form endpoint that appends submissions to Google Sheets.
//
// Request flow:
//   1. Verify the Cloudflare Access JWT (src/access.js). No valid token, no
//      request — the header is checked cryptographically, not just read.
//   2. Turn the token's `aud` claim into a spreadsheet (src/bindings.js). The
//      caller never names a sheet, so there is no id to tamper with.
//   3. Parse and sanity-check the body (src/payload.js).
//   4. Append a row with a Google service-account credential (src/google.js,
//      src/sheets.js), rejecting the write if the sheet's header row and the
//      submission have drifted apart.
//
// The Worker only ever appends. It has no endpoint that reads sheet contents
// back out, so a caller who can submit still cannot read other submissions.

import { json, errorResponse, corsHeaders, HttpError } from './http.js';
import { authenticate, fetchAccessGroups } from './access.js';
import { parseBindings, audiences, selectBinding } from './bindings.js';
import { readPayload, normalizePayload, stampIdentity } from './payload.js';
import { appendRecord } from './sheets.js';
import { serviceAccountEmail } from './google.js';

function resolveTab(env, binding) {
  return binding.tab || env.RESPONSES_TAB || 'Responses';
}

function resolveStamp(env, binding) {
  if (typeof binding.stamp === 'boolean') return binding.stamp;
  return String(env.STAMP_IDENTITY ?? 'true') === 'true';
}

// Identity lookups are per-request and at most one per request, however many
// bindings ask for them.
function accessGroupLoader(request, identity) {
  let pending = null;
  return () => {
    if (!pending) pending = fetchAccessGroups(request, identity);
    return pending;
  };
}

async function handleSubmit(request, env, url, identity) {
  const binding = await selectBinding(env, identity, url, accessGroupLoader(request, identity));

  const raw = await readPayload(request, env);
  let data = normalizePayload(raw);
  if (resolveStamp(env, binding)) data = stampIdentity(data, identity);

  const result = await appendRecord(env, binding.sheetId, resolveTab(env, binding), data, {
    allowMissingFields: binding.allowMissingFields,
  });

  return { ok: true, sheet: binding.label, ...result };
}

// Reports what Access said about the caller and which sheet they are bound to.
// Useful when a submission is being refused and it is not obvious whether the
// problem is the token, the binding, or the sheet.
async function handleWhoami(request, env, url, identity) {
  const body = {
    ok: true,
    identity: {
      type: identity.type,
      email: identity.email,
      commonName: identity.commonName,
      idpGroups: identity.idpGroups,
      aud: identity.aud,
    },
    serviceAccount: serviceAccountEmail(env),
  };

  try {
    const binding = await selectBinding(env, identity, url, accessGroupLoader(request, identity));
    body.binding = { label: binding.label, tab: resolveTab(env, binding), stamp: resolveStamp(env, binding) };
  } catch (err) {
    body.binding = null;
    body.bindingError = err instanceof HttpError ? err.code : 'internal_error';
  }

  return body;
}

async function handle(request, env, url) {
  if (request.method === 'GET' && url.pathname === '/health') {
    // Unauthenticated on purpose: this says the Worker is running and its
    // configuration parses, and nothing about who or what it is bound to.
    parseBindings(env);
    return { ok: true };
  }

  const identity = await authenticate(request, env, audiences(parseBindings(env)));

  if (request.method === 'GET' && url.pathname === '/whoami') {
    return handleWhoami(request, env, url, identity);
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

// Small HTTP helpers. Every failure path in this Worker throws an HttpError so
// that the fetch handler has exactly one place that turns problems into
// responses, and so the shape of an error body is always the same:
//   { "ok": false, "error": "<stable_code>", "detail": "<human hint>" }
// The `error` code is stable and safe to branch on from a client; `detail` is
// advisory text meant for whoever is wiring the form up.

export class HttpError extends Error {
  constructor(status, code, detail) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
    this.detail = detail;
  }
}

export function json(body, { status = 200, headers = {} } = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...headers,
    },
  });
}

export function errorResponse(err, { headers = {} } = {}) {
  if (err instanceof HttpError) {
    const body = { ok: false, error: err.code };
    if (err.detail) body.detail = err.detail;
    return json(body, { status: err.status, headers });
  }
  // Anything that isn't an HttpError is a bug in this Worker, not a caller
  // mistake: log it for `wrangler tail` and tell the caller nothing useful.
  console.error('unhandled error', err && err.stack ? err.stack : err);
  return json({ ok: false, error: 'internal_error' }, { status: 500, headers });
}

// CORS_ORIGINS is a comma-separated allowlist, or "*" for any origin. An empty
// setting means "no CORS headers at all", which is the right default for a form
// served from the same hostname as the Worker.
export function corsHeaders(request, env) {
  const configured = (env.CORS_ORIGINS || '').trim();
  const origin = request.headers.get('origin');
  if (!configured || !origin) return {};

  const allowed = configured
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);

  const match = allowed.includes('*') || allowed.includes(origin);
  if (!match) return {};

  return {
    // Never reflect "*" here: Access authenticates with the CF_Authorization
    // cookie, and a wildcard origin is incompatible with credentialed requests.
    'access-control-allow-origin': origin,
    'access-control-allow-credentials': 'true',
    'access-control-allow-methods': 'POST, GET, OPTIONS',
    'access-control-allow-headers': 'content-type, cf-access-jwt-assertion',
    'access-control-max-age': '86400',
    vary: 'origin',
  };
}

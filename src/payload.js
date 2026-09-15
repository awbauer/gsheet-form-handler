// Reading and sanity-checking a submission body.
//
// Three content types are accepted so the same endpoint serves a fetch() call,
// a plain <form method="post">, and a multipart form:
//   application/json            {"FIELD":"VALUE", ...}
//   application/x-www-form-urlencoded
//   multipart/form-data         (text fields only)

import { HttpError } from './http.js';

export const MAX_KEY_LENGTH = 256;
export const MAX_VALUE_LENGTH = 50_000; // A Sheets cell holds 50k characters.

// Written by the Worker itself, so a submitter must not be able to supply
// them. `secret` is stripped for continuity with the Apps Script, where it was
// a shared password that had to be kept out of the sheet; Access replaces it,
// and anything still sending it should not have that value land in a cell.
export const RESERVED_KEYS = ['_received_at', '_identity', 'secret'];

function assertPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new HttpError(400, 'invalid_payload', 'body must be a JSON object of field names to values');
  }
  return value;
}

function entriesFromFormData(form) {
  const data = {};
  for (const [key, value] of form.entries()) {
    if (typeof value !== 'string') {
      throw new HttpError(415, 'unsupported_field', `field "${key}" is a file; this endpoint only accepts text fields`);
    }
    // Repeated names (checkbox groups) collapse to one comma-joined cell
    // rather than silently keeping only the last value.
    data[key] = Object.prototype.hasOwnProperty.call(data, key) ? `${data[key]}, ${value}` : value;
  }
  return data;
}

export async function readPayload(request, env) {
  const limit = Number(env.MAX_BODY_BYTES || 131072);
  const declared = Number(request.headers.get('content-length') || 0);
  if (declared > limit) {
    throw new HttpError(413, 'payload_too_large', `body exceeds ${limit} bytes`);
  }

  const contentType = (request.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();

  if (contentType === 'application/x-www-form-urlencoded' || contentType === 'multipart/form-data') {
    let form;
    try {
      form = await request.formData();
    } catch {
      throw new HttpError(400, 'invalid_form_body', 'could not parse the form body');
    }
    return entriesFromFormData(form);
  }

  const text = await request.text();
  if (text.length > limit) {
    throw new HttpError(413, 'payload_too_large', `body exceeds ${limit} bytes`);
  }
  if (!text.trim()) {
    throw new HttpError(400, 'invalid_payload', 'body is empty');
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new HttpError(400, 'invalid_json', 'body is not valid JSON');
  }
  return assertPlainObject(parsed);
}

// Drops reserved keys, rejects unusable ones, and trims oversized values.
export function normalizePayload(raw) {
  const data = {};

  for (const [key, value] of Object.entries(assertPlainObject(raw))) {
    const name = key.trim();
    if (!name) {
      throw new HttpError(400, 'invalid_field_name', 'field names cannot be empty');
    }
    if (name.length > MAX_KEY_LENGTH) {
      throw new HttpError(400, 'invalid_field_name', `field name "${name.slice(0, 32)}..." is longer than ${MAX_KEY_LENGTH} characters`);
    }
    if (RESERVED_KEYS.includes(name)) continue;

    if (typeof value === 'string' && value.length > MAX_VALUE_LENGTH) {
      throw new HttpError(413, 'field_too_large', `field "${name}" is longer than ${MAX_VALUE_LENGTH} characters`);
    }
    data[name] = value;
  }

  if (Object.keys(data).length === 0) {
    throw new HttpError(400, 'invalid_payload', 'submission has no writable fields');
  }
  return data;
}

// Provenance columns. Cloudflare Access already proves who the caller is, so
// recording it costs nothing and makes a sheet auditable after the fact.
export function stampIdentity(data, identity, now = new Date()) {
  return { _received_at: now.toISOString(), _identity: identity.label, ...data };
}

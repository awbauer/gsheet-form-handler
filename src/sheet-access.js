// Which Access applications may write which spreadsheet.
//
// SHEET_ACCESS (a var in wrangler.jsonc) is keyed by spreadsheet id, and each
// value lists the Access application AUD tags allowed to write it:
//
//   {
//     "1AbC...": ["32eafc7626e9...", "9b41de02a7c1..."],
//     "1XyZ...": {
//       "auds": [],
//       "label": "all-hands suggestions",
//       "tab": "Responses",
//       "allowMissingFields": true
//     }
//   }
//
// The array form is shorthand for { "auds": [...] }.
//
// A request names the sheet it is writing (?SHEET_ID=, /submit/<id>, or
// DEFAULT_SHEET_ID), and the Worker checks the caller's `aud` claim against
// that sheet's list. Naming the sheet is not trusting the caller: an id that is
// not in this map, or one whose list does not include the caller's audience, is
// refused with the same error either way, so the parameter cannot be used to
// discover which sheets exist.
//
// AN EMPTY ARRAY MEANS ANY AUTHENTICATED CALLER. Read that as "anyone holding a
// valid Access token issued by your team" — not "anyone in the Access
// application in front of this Worker". Cloudflare signs one token per
// application, all from the same team issuer, so a user authorized only for
// some unrelated application in your team also satisfies an empty list. Two
// things follow:
//
//   * Keep this Worker off a route that is reachable without Access (turn off
//     its workers.dev subdomain), or an empty list is the only thing between a
//     stray team token and your sheet.
//   * To mean "everyone in *this* application", list that application's AUD
//     rather than leaving the array empty. To narrow an open sheet without
//     naming applications, add requireEmailDomains or requireIdpGroups below.
//
// Optional per sheet, all of which further narrow an already-allowed caller:
//
//   "requireEmails":       ["ada@example.com"]
//   "requireEmailDomains": ["example.com"]
//   "requireServiceTokens":["e367826f93b8d71185e03fe518aff3b4.access"]
//   "requireIdpGroups":    ["Finance-Team"]   // from the JWT `custom.groups`
//   "requireAccessGroups": ["Finance"]        // from /cdn-cgi/access/get-identity
//
// requireIdpGroups reads a custom SAML/OIDC claim, which Cloudflare documents
// as best-effort: Access trims the `custom` claim at roughly 1 KB, so a user in
// many groups can arrive without their groups at all. requireAccessGroups asks
// the identity endpoint instead, which is authoritative but costs a subrequest
// and returns nothing for a service token.

import { HttpError } from './http.js';

const cache = new WeakMap();

function asList(value) {
  if (!value) return [];
  const list = Array.isArray(value) ? value : [value];
  return list.filter((entry) => typeof entry === 'string' && entry.trim()).map((entry) => entry.trim());
}

export function parseSheetAccess(env) {
  if (typeof env === 'object' && env !== null && cache.has(env)) return cache.get(env);

  const raw = env.SHEET_ACCESS;
  let value = raw;
  if (typeof raw === 'string') {
    if (!raw.trim()) value = null;
    else {
      try {
        value = JSON.parse(raw);
      } catch {
        throw new HttpError(500, 'not_configured', 'SHEET_ACCESS is not valid JSON');
      }
    }
  }

  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new HttpError(500, 'not_configured', 'SHEET_ACCESS must be an object keyed by spreadsheet id');
  }

  const entries = Object.entries(value);
  if (entries.length === 0) {
    throw new HttpError(500, 'not_configured', 'SHEET_ACCESS is empty; add one entry per spreadsheet');
  }

  const sheets = new Map();
  for (const [sheetId, config] of entries) {
    const record = Array.isArray(config) ? { auds: config } : config;
    if (!record || typeof record !== 'object') {
      throw new HttpError(500, 'not_configured', `SHEET_ACCESS["${sheetId}"] must be an array of AUDs or an object`);
    }
    if (!Array.isArray(record.auds)) {
      throw new HttpError(500, 'not_configured', `SHEET_ACCESS["${sheetId}"] is missing an "auds" array (use [] to allow any authenticated caller)`);
    }

    const auds = asList(record.auds);
    sheets.set(sheetId, {
      sheetId,
      auds,
      // An empty list is a decision, not an oversight, so it is named here and
      // reported by /whoami rather than being invisible in the config.
      open: auds.length === 0,
      label: typeof record.label === 'string' && record.label.trim() ? record.label.trim() : sheetId,
      tab: typeof record.tab === 'string' && record.tab.trim() ? record.tab.trim() : null,
      stamp: typeof record.stamp === 'boolean' ? record.stamp : null,
      allowMissingFields: record.allowMissingFields === true,
      requireEmails: asList(record.requireEmails).map((email) => email.toLowerCase()),
      requireEmailDomains: asList(record.requireEmailDomains).map((domain) => domain.toLowerCase().replace(/^@/, '')),
      requireServiceTokens: asList(record.requireServiceTokens),
      requireIdpGroups: asList(record.requireIdpGroups),
      requireAccessGroups: asList(record.requireAccessGroups),
    });
  }

  if (typeof env === 'object' && env !== null) cache.set(env, sheets);
  return sheets;
}

// The union of every configured audience, used to reject a token from an
// unrelated application before any sheet is considered. Null when some sheet
// accepts any authenticated caller, since there is then nothing to pin against.
export function configuredAudiences(sheets) {
  const all = new Set();
  for (const sheet of sheets.values()) {
    if (sheet.open) return null;
    for (const aud of sheet.auds) all.add(aud);
  }
  return all;
}

export function audienceAllowed(sheet, identity) {
  if (sheet.open) return true;
  return identity.auds.some((aud) => sheet.auds.includes(aud));
}

// Narrowing gate 1: is this a named principal? Open when none are named.
export function principalAllowed(sheet, identity) {
  const declared =
    sheet.requireEmails.length + sheet.requireEmailDomains.length + sheet.requireServiceTokens.length;
  if (declared === 0) return true;

  if (identity.email) {
    if (sheet.requireEmails.includes(identity.email)) return true;
    const domain = identity.email.slice(identity.email.lastIndexOf('@') + 1);
    if (domain && sheet.requireEmailDomains.includes(domain)) return true;
  }
  if (identity.commonName && sheet.requireServiceTokens.includes(identity.commonName)) return true;
  return false;
}

// Narrowing gate 2: group membership. `loadAccessGroups` is only called when a
// sheet actually asks for it.
export async function groupsAllowed(sheet, identity, loadAccessGroups) {
  const declared = sheet.requireIdpGroups.length + sheet.requireAccessGroups.length;
  if (declared === 0) return true;

  if (sheet.requireIdpGroups.some((group) => identity.idpGroups.includes(group))) return true;

  if (sheet.requireAccessGroups.length > 0) {
    const groups = await loadAccessGroups();
    if (sheet.requireAccessGroups.some((group) => groups.includes(group))) return true;
  }
  return false;
}

export async function callerMayWrite(sheet, identity, loadAccessGroups) {
  if (!audienceAllowed(sheet, identity)) return false;
  if (!principalAllowed(sheet, identity)) return false;
  return groupsAllowed(sheet, identity, loadAccessGroups);
}

// Which spreadsheet the request is for: an explicit SHEET_ID parameter, the
// trailing segment of /submit/<id>, or DEFAULT_SHEET_ID. Exported for tests.
export function sheetKeyFrom(url, env) {
  const parameter = url.searchParams.get('SHEET_ID') || url.searchParams.get('sheet_id');
  if (parameter && parameter.trim()) return parameter.trim();

  const path = url.pathname.match(/^\/submit\/(.+)$/);
  if (path) return decodeURIComponent(path[1]);

  const fallback = (env.DEFAULT_SHEET_ID || '').trim();
  return fallback || null;
}

export async function resolveSheet(env, identity, url, loadAccessGroups) {
  const sheets = parseSheetAccess(env);

  const key = sheetKeyFrom(url, env);
  if (!key) {
    throw new HttpError(400, 'sheet_not_specified', 'pass ?SHEET_ID=<spreadsheet id>, post to /submit/<spreadsheet id>, or set DEFAULT_SHEET_ID');
  }

  const sheet = sheets.get(key);
  // An unconfigured id and an id this caller may not write are reported
  // identically, so the parameter cannot be used to enumerate sheets.
  if (!sheet || !(await callerMayWrite(sheet, identity, loadAccessGroups))) {
    throw new HttpError(403, 'not_authorized', `${identity.label} may not write the requested sheet`);
  }
  return sheet;
}

// The sheets this caller may write, for /whoami. Showing someone their own
// entitlements reveals nothing they could not already establish by submitting.
export async function writableSheets(env, identity, loadAccessGroups) {
  const allowed = [];
  for (const sheet of parseSheetAccess(env).values()) {
    if (await callerMayWrite(sheet, identity, loadAccessGroups)) {
      allowed.push({ sheetId: sheet.sheetId, label: sheet.label, openToAnyAuthenticatedCaller: sheet.open });
    }
  }
  return allowed;
}

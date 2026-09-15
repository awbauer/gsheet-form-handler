// Which sheet a request may write to, decided by Cloudflare Access.
//
// The mapping is "one Access application per spreadsheet", and the link
// between them is the application's AUD tag. Access stamps the AUD of the
// application the caller was authorized for into the `aud` claim of the JWT it
// signs, so the Worker can read `aud` and know both *who* the caller is and
// *which* sheet they were let through for — without keeping any copy of your
// directory.
//
// That means the group of users who may write a given sheet is just the Access
// policy on that application: an Access Group, an IdP group, an email list, a
// domain, a service token, device posture, country, mTLS. It is managed in
// Zero Trust, is audited there, and is enforced at the edge before this Worker
// ever runs. Nothing here needs KV, D1, or a config file listing people.
//
// SHEET_BINDINGS (a var in wrangler.jsonc) therefore holds only the part
// Cloudflare cannot know: which spreadsheet each application writes to.
//
//   [
//     {
//       "aud": "32eafc7626e9...",     // Access app AUD tag (required)
//       "sheetId": "1AbC...",          // Google spreadsheet id (required)
//       "label": "Finance intake",     // shown in errors and /whoami
//       "tab": "Responses",            // optional, defaults to RESPONSES_TAB
//       "path": "/submit/finance",     // optional, if one app serves several
//       "stamp": true,                 // optional, defaults to STAMP_IDENTITY
//       "allowMissingFields": false    // optional, see src/sheets.js
//     }
//   ]
//
// The optional narrowing constraints below exist for the case where one Access
// application fronts several sheets on different paths and you want a second
// check inside the Worker. They are *defence in depth*, not the primary gate —
// the Access policy is the primary gate.
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
// and only works for browser sessions (a service token has no identity to
// fetch). Prefer expressing group membership in the Access policy itself.

import { HttpError } from './http.js';

const bindingCache = new WeakMap();

function asList(value) {
  if (!value) return [];
  const list = Array.isArray(value) ? value : [value];
  return list.filter((entry) => typeof entry === 'string' && entry.trim()).map((entry) => entry.trim());
}

export function parseBindings(env) {
  if (typeof env === 'object' && env !== null && bindingCache.has(env)) return bindingCache.get(env);

  const raw = env.SHEET_BINDINGS;
  let value = raw;
  if (typeof raw === 'string') {
    if (!raw.trim()) value = [];
    else {
      try {
        value = JSON.parse(raw);
      } catch {
        throw new HttpError(500, 'not_configured', 'SHEET_BINDINGS is not valid JSON');
      }
    }
  }

  if (!Array.isArray(value)) {
    throw new HttpError(500, 'not_configured', 'SHEET_BINDINGS must be an array of bindings');
  }
  if (value.length === 0) {
    throw new HttpError(500, 'not_configured', 'SHEET_BINDINGS has no bindings; add one per Access application');
  }

  const bindings = value.map((entry, index) => {
    if (!entry || typeof entry !== 'object') {
      throw new HttpError(500, 'not_configured', `SHEET_BINDINGS[${index}] is not an object`);
    }
    if (typeof entry.aud !== 'string' || !entry.aud.trim()) {
      throw new HttpError(500, 'not_configured', `SHEET_BINDINGS[${index}] is missing "aud"`);
    }
    if (typeof entry.sheetId !== 'string' || !entry.sheetId.trim()) {
      throw new HttpError(500, 'not_configured', `SHEET_BINDINGS[${index}] is missing "sheetId"`);
    }
    return {
      aud: entry.aud.trim(),
      sheetId: entry.sheetId.trim(),
      label: typeof entry.label === 'string' && entry.label.trim() ? entry.label.trim() : entry.sheetId.trim(),
      tab: typeof entry.tab === 'string' && entry.tab.trim() ? entry.tab.trim() : null,
      path: typeof entry.path === 'string' && entry.path.trim() ? entry.path.trim() : null,
      stamp: typeof entry.stamp === 'boolean' ? entry.stamp : null,
      allowMissingFields: entry.allowMissingFields === true,
      requireEmails: asList(entry.requireEmails).map((email) => email.toLowerCase()),
      requireEmailDomains: asList(entry.requireEmailDomains).map((domain) => domain.toLowerCase().replace(/^@/, '')),
      requireServiceTokens: asList(entry.requireServiceTokens),
      requireIdpGroups: asList(entry.requireIdpGroups),
      requireAccessGroups: asList(entry.requireAccessGroups),
    };
  });

  if (typeof env === 'object' && env !== null) bindingCache.set(env, bindings);
  return bindings;
}

export function audiences(bindings) {
  return new Set(bindings.map((binding) => binding.aud));
}

// Gate 1: is this principal one of the named principals? Open when the binding
// names none.
export function principalAllowed(binding, identity) {
  const declared =
    binding.requireEmails.length + binding.requireEmailDomains.length + binding.requireServiceTokens.length;
  if (declared === 0) return true;

  if (identity.email) {
    if (binding.requireEmails.includes(identity.email)) return true;
    const domain = identity.email.slice(identity.email.lastIndexOf('@') + 1);
    if (domain && binding.requireEmailDomains.includes(domain)) return true;
  }
  if (identity.commonName && binding.requireServiceTokens.includes(identity.commonName)) return true;
  return false;
}

// Gate 2: group membership. Open when the binding declares no groups.
// `loadAccessGroups` is only called when a binding actually asks for them.
export async function groupsAllowed(binding, identity, loadAccessGroups) {
  const declared = binding.requireIdpGroups.length + binding.requireAccessGroups.length;
  if (declared === 0) return true;

  if (binding.requireIdpGroups.some((group) => identity.idpGroups.includes(group))) return true;

  if (binding.requireAccessGroups.length > 0) {
    const groups = await loadAccessGroups();
    if (binding.requireAccessGroups.some((group) => groups.includes(group))) return true;
  }
  return false;
}

// Picks the binding for this request. `identity.aud` already had to match one
// of the configured audiences for the JWT to verify at all, so the usual case
// is a single candidate and no further checks.
export async function selectBinding(env, identity, url, loadAccessGroups) {
  const bindings = parseBindings(env);
  const candidates = bindings.filter(
    (binding) => binding.aud === identity.aud && (!binding.path || binding.path === url.pathname),
  );

  if (candidates.length === 0) {
    throw new HttpError(403, 'no_sheet_for_application', `no sheet is bound to Access application ${identity.aud} at ${url.pathname}`);
  }

  for (const binding of candidates) {
    if (!principalAllowed(binding, identity)) continue;
    if (!(await groupsAllowed(binding, identity, loadAccessGroups))) continue;
    return binding;
  }

  throw new HttpError(403, 'not_authorized', `${identity.label} passed Access but does not satisfy the extra constraints on this binding`);
}

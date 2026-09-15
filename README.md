# gsheet-form-handler

A Cloudflare Worker that appends form submissions to a Google Sheet.

It does what the Google Apps Script `doPost` handler it replaces did — accept a
flat JSON object, match each key to a column on a `Responses` tab, append a row
— but authenticates with Cloudflare Access and writes through the Sheets API
with a Google service account, so it can live on your own hostname and serve
several spreadsheets from one deployment.

```
POST https://forms.example.com/submit/1AbC...
Content-Type: application/json

{ "name": "Ada", "email": "ada@example.com", "message": "hello" }
```

```json
{ "ok": true, "sheet": "contact form", "columns": 5, "createdHeaders": false,
  "updatedRange": "Responses!A41:E41" }
```

## How access control works

**There is no user database in this Worker.** Who may write a given spreadsheet
is decided by Cloudflare Access policy, and `SHEET_ACCESS` says which Access
applications count for which sheet.

The link between the two is the Access **AUD tag**. You put an Access
application in front of the endpoint; Access authenticates the caller, applies
your policy, and signs a JWT whose `aud` claim names the application it let them
through for. `SHEET_ACCESS` is keyed by spreadsheet id and lists the audiences
allowed to write it:

```jsonc
"SHEET_ACCESS": {
  // written by two applications: the finance form and an admin console
  "1AbC...": ["32eafc76...", "9b41de02..."],

  // written by anyone holding a valid Access token from your team
  "1XyZ...": []
}
```

A request names the sheet it is writing — `?SHEET_ID=`, `/submit/<id>`, or
`DEFAULT_SHEET_ID` — and the Worker checks the caller's audience against that
sheet's list. Naming the sheet is not the same as being trusted with it: an id
that is not in the map and an id the caller may not write are refused
identically, so the parameter cannot be used to discover which sheets exist.

The consequences are worth being explicit about:

- **Membership lives in Zero Trust**, where it is already audited, already syncs
  from your IdP, and already supports Access Groups, SCIM, device posture,
  country and mTLS rules. The Worker does not re-implement any of it and cannot
  drift out of sync with it.
- **Several applications can share a sheet, and one application can write
  several sheets.** Both are just list membership.
- **Unauthorized requests never reach the Worker at all** — Access rejects them
  at the edge — and if one somehow does, it fails JWT verification here.

### What an empty array actually means

`[]` means **any caller holding a valid Access token issued by your team** — not
"anyone in the application in front of this Worker". Cloudflare signs one token
per application, all from the same team issuer, so a user authorized only for
some unrelated application in your Zero Trust org also satisfies an empty list.
Two things follow:

- **Keep this Worker off a route that is reachable without Access** — turn off
  its `workers.dev` subdomain. With an empty list, that route is the only thing
  between a stray team token and your sheet.
- **To mean "everyone in *this* application", list that application's AUD**
  rather than leaving the array empty. To open a sheet broadly but not that
  broadly, leave the array empty and add `requireEmailDomains` or
  `requireIdpGroups`, which still apply.

One more consequence: if any sheet is open, the Worker cannot pin the JWT
audience check to a known set, because any team-issued token has to get past it
to reach the per-sheet check. The issuer is still pinned, and a token naming no
application at all is still refused.

### Which Access attributes are usable, and which are not

| Attribute | Where it comes from | Use it for |
| --- | --- | --- |
| `aud` | Always in the app token | **Authorizing the sheet.** Never trimmed, never absent. |
| `email` | App token, human logins | Identifying the submitter; stamped into `_identity`. |
| `common_name` | App token, service tokens | Identifying a machine client (`sub` is empty and there is no email). |
| `custom.groups` | App token, **only if** you configure `groups` as a custom SAML attribute / OIDC claim | A hint, not a gate — see below. |
| Access + IdP groups | `/cdn-cgi/access/get-identity` | Authoritative group membership, browser sessions only, costs a subrequest. |
| Device posture, country, IP | `/cdn-cgi/access/get-identity` | Better expressed as an Access policy rule. |

Cloudflare's own documentation is blunt about the group claim:

> Access trims custom attributes and claims when the serialized `custom` claim
> exceeds roughly 1 KB... a user who belongs to many groups can receive a token
> without their `groups` claim while other users on the same application keep
> it. **Do not rely on custom claims in the JWT for authorization decisions
> when they may grow large.**

So a Worker that gated on `custom.groups` would deny exactly the users in the
most groups, intermittently, and look like a flaky bug. That is why groups are
not the primary mechanism here. If you want group-based narrowing anyway, a
sheet can declare `requireIdpGroups` (reads the claim) or `requireAccessGroups`
(calls `get-identity`, authoritative) — but prefer expressing it as an Access
policy and letting `aud` carry the answer.

### What this Worker does *not* trust

The `Cf-Access-Authenticated-User-Email` header. It is convenient and it is
also just a header: any client can send one, and a Worker route stays reachable
on its own hostname even when you believe Access is in front of it. This Worker
verifies the JWT signature against `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`,
pins the issuer, and requires the audience to be one you configured. An
unverified token is treated as no token.

## Setup

### 1. Google service account

The Worker calls the Sheets API directly as a service account — there is no
Apps Script runtime and no OAuth consent screen.

1. In the Google Cloud console, create a project and **enable the Google Sheets
   API**.
2. Create a **service account**, then create a **JSON key** for it.
3. Note the service account's address, `something@project.iam.gserviceaccount.com`.
4. **Share every target spreadsheet with that address as an Editor**, exactly as
   you would share it with a colleague. Nothing else grants the Worker access —
   owning the Cloud project does not.

If you skip step 4, submissions fail with `sheet_not_shared` and the error names
the address to share with. `GET /whoami` also reports it, so you can copy it out
before the first submission.

```sh
npx wrangler secret put GOOGLE_SERVICE_ACCOUNT_JSON   # paste the whole key JSON
```

### 2. Cloudflare Access application

For each spreadsheet:

1. Zero Trust → **Access** → **Applications** → **Add an application** →
   *Self-hosted*.
2. Point it at the path this form posts to, e.g. `forms.example.com/submit/finance`.
3. Add the policy that defines who may submit — an Access Group, an IdP group,
   an email domain, a service token for server-to-server posts.
4. Copy the **Application Audience (AUD) tag** from the application's overview.

### 3. Configure the Worker

In `wrangler.jsonc`:

```jsonc
"vars": {
  "ACCESS_TEAM_DOMAIN": "acme",
  "SHEET_ACCESS": {
    "1AbC...": ["32eafc76..."],
    "1XyZ...": { "auds": ["9b41de02...", "32eafc76..."], "label": "hr intake",
                 "tab": "Submissions", "allowMissingFields": true }
  },
  "DEFAULT_SHEET_ID": ""
}
```

Then `npx wrangler deploy`, and add a Worker route for the hostname so the
Access application and the Worker sit on the same path.

## Endpoints

| Method | Path | Behaviour |
| --- | --- | --- |
| `POST` | `/submit/<sheet id>`, or any path with `?SHEET_ID=` | Append a row. |
| `GET` | `/whoami` | What Access said about you, which sheets you may write, and the service-account address to share with. |
| `GET` | `/health` | Liveness and "the configuration parses". Unauthenticated, reveals nothing. |

`POST` accepts `application/json`, `application/x-www-form-urlencoded` and
`multipart/form-data` (text fields only), so a plain `<form method="post">`
works as well as `fetch`. Repeated field names — a checkbox group — collapse into
one comma-joined cell.

Every row is prefixed with two columns unless `STAMP_IDENTITY` is `"false"`:

| `_received_at` | `_identity` |
| --- | --- |
| `2026-01-02T03:04:05.000Z` | `ada@example.com` or `service-token:e367...access` |

Because stamped columns are part of the submission, they are part of the
header comparison too. Migrating an existing Apps Script sheet: either add
`_received_at` and `_identity` as the first two columns of the header row, or
set `STAMP_IDENTITY` to `"false"`.

`_received_at`, `_identity` and `secret` are reserved: they are stripped from
the submission before the row is built, so a submitter cannot forge their own
provenance. (`secret` is stripped for continuity with the Apps Script, where it
was a shared password that had to be kept out of the sheet. Access replaces it.)

## Header drift is an error, not an auto-migration

The first submission to an empty tab writes the header row and defines the shape
of the form. After that, **a submission whose fields do not match the header row
is rejected with `409 header_mismatch`** and nothing is written:

```json
{ "ok": false, "error": "header_mismatch",
  "detail": "the submission does not match the header row of \"Responses\" (fields not in the sheet: emailAddress; columns the submission did not include: email). Add the columns to the sheet, correct the form, or set \"allowMissingFields\" on the sheet." }
```

The Apps Script appended a new column the first time it saw an unfamiliar key.
That is forgiving in the moment and lossy over time: a typo'd field name, a
renamed input, or a half-deployed client quietly produces a sheet with two
columns meaning the same thing and rows that are only partly populated — and
nobody finds out until someone tries to read the data. Failing the write puts
the problem in front of whoever changed the form, while it is still cheap to
fix, and keeps the column set something a human decided on.

To change a form's shape, edit the header row in the sheet and deploy the client
change. To widen it in one step, rename the tab (or set `"tab"` on the sheet)
so the next submission starts a fresh sheet.

Key **order** is not checked — JSON object order carries no meaning — only the
set of names.

`"allowMissingFields": true` on a sheet relaxes one half of this: a submission
may omit columns (they are written blank), but an unknown field is still an
error. Plain HTML forms generally need it, because an unchecked checkbox posts
nothing at all.

## Errors

All failures return `{ "ok": false, "error": "<code>", "detail": "..." }`. The
code is stable; the detail is advisory text for whoever is wiring the form up.

| Code | Status | Meaning |
| --- | --- | --- |
| `access_jwt_missing` | 401 | No Access token — the request did not come through Access. |
| `access_jwt_bad_signature`, `access_jwt_unknown_key`, `access_jwt_malformed` | 401 | Token did not verify. |
| `access_jwt_expired` | 401 | Sign in again. |
| `access_jwt_wrong_issuer`, `access_jwt_wrong_audience` | 403 | Token is from another team or another application. |
| `sheet_not_specified` | 400 | The request named no sheet and `DEFAULT_SHEET_ID` is unset. |
| `not_authorized` | 403 | The sheet is not configured, or this caller's application is not on its list. |
| `invalid_json`, `invalid_payload`, `invalid_field_name` | 400 | Unusable body. |
| `header_mismatch` | 409 | The form's shape and the sheet's header row disagree. |
| `payload_too_large`, `field_too_large` | 413 | Over `MAX_BODY_BYTES` or a 50k-character cell. |
| `too_many_columns` | 422 | A first submission defining more than 512 columns. |
| `not_configured` | 500 | Missing team domain, sheet map, or service-account secret. |
| `sheet_not_shared` | 502 | Share the spreadsheet with the service account. |
| `sheet_not_found` | 502 | Google has no spreadsheet with that id. |
| `sheets_api_unavailable` | 503 | Google rate-limited us or is down; retry. |

## Configuration reference

| Var | Default | Purpose |
| --- | --- | --- |
| `ACCESS_TEAM_DOMAIN` | — | `acme` or `acme.cloudflareaccess.com`. |
| `SHEET_ACCESS` | — | Spreadsheet id → allowed Access AUDs; see `src/sheet-access.js`. |
| `DEFAULT_SHEET_ID` | *(empty)* | Sheet used when a request names none. |
| `RESPONSES_TAB` | `Responses` | Default tab; a sheet's `tab` wins. |
| `STAMP_IDENTITY` | `true` | Add `_received_at` / `_identity`; a sheet's `stamp` wins. |
| `CORS_ORIGINS` | *(empty)* | Comma-separated origins, or `*`. Empty means no CORS headers. |
| `MAX_BODY_BYTES` | `131072` | Request body ceiling. |
| `GOOGLE_SERVICE_ACCOUNT_JSON` | — | **Secret.** The service-account key JSON. |

Per-sheet keys: `auds` (required; `[]` allows any authenticated caller),
`label`, `tab`, `stamp`, `allowMissingFields`, `requireEmails`,
`requireEmailDomains`, `requireServiceTokens`, `requireIdpGroups`,
`requireAccessGroups`. An array in place of the object is shorthand for `auds`.

## Known limits

- **Appends are not serialised.** Two simultaneous submissions both append, and
  the Sheets API handles that; but the "read headers, then append" pair is not
  atomic. With header drift now an error rather than a schema edit, the only
  race left is two submissions to a brand-new empty tab, where both may try to
  write the header row. Send the first submission yourself, or pre-create the
  header row, if that matters.
- **An empty `auds` array is wider than it looks** — see above. It is the one
  setting here that can be wrong in a way Access will not catch for you.
- **`requireAccessGroups` does not work for service tokens.** A service token
  has no IdP identity to fetch, so `get-identity` has nothing to return. Use
  `requireServiceTokens`, or put the token in the Access policy.
- **Google access tokens are cached per isolate**, not shared, so a burst across
  many colos costs one token exchange each. Deliberate: an access token is a
  bearer credential and does not belong in a store every colo reads.
- **CORS with `*` still sends `Access-Control-Allow-Origin: <origin>`**, because
  Access authenticates with a cookie and a wildcard origin is incompatible with
  credentialed requests.

## Development

```sh
npm install
npm test            # pure-logic tests, no network, no wrangler needed
npx wrangler dev
npx wrangler tail   # unexpected errors are logged here, not returned to callers
```

`npm test` covers claim validation, sheet authorization, header-drift detection,
value handling and payload sanitising — the parts where a mistake is a security
or data-integrity problem. The Sheets and Access HTTP calls are thin wrappers
over `fetch` and are exercised against the real services with `wrangler dev`.

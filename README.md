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
your policy, and hands the Worker the result as `ctx.access` — including
`ctx.access.aud`, the tag of the application it let them through for.
`SHEET_ACCESS` is keyed by spreadsheet id and lists the audiences allowed to
write it:

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
  at the edge — and a request that arrives without having been authenticated by
  Access has no `ctx.access` and is refused here.

### What an empty array actually means

`[]` means **any caller Access admitted to this route**. The runtime populates
`ctx.access` only when Access authenticated the request against an application
covering the route being called, so a token minted for some unrelated
application elsewhere in your Zero Trust org does not satisfy an empty list, and
a route Access is not in front of produces no identity at all rather than a
usable one.

What an empty array still does not distinguish: **if several Access applications
route to this Worker, it admits callers from all of them.** To mean "everyone in
*this* application", list that application's AUD rather than leaving the array
empty. To open a sheet broadly but not that broadly, leave the array empty and
add `requireEmailDomains` or `requireIdpGroups`, which still apply.

### Which Access attributes are usable, and which are not

| Attribute | Where it comes from | Use it for |
| --- | --- | --- |
| `aud` | `ctx.access.aud` | **Authorizing the sheet.** Present on every authenticated request. |
| `email` | `ctx.access.getIdentity()` | Identifying the submitter; stamped into `_identity`. |
| Access + IdP groups | `ctx.access.getIdentity()` | Group membership, authoritative. |
| Device posture, country, IP | `ctx.access.getIdentity()` | Better expressed as an Access policy rule. |

`getIdentity()` returns the identity Access itself holds, so the groups it
reports are authoritative. There is no ~1 KB `custom` claim to be silently
trimmed here — that trimming is what made JWT group claims unsafe to gate on,
because it drops the groups of exactly the users who belong to the most of them.
A sheet can declare `requireIdpGroups` or `requireAccessGroups` and both are
matched against that one list.

Still prefer expressing membership as an Access policy and letting `aud` carry
the answer: the policy is audited and syncs from your IdP, and a list in
`SHEET_ACCESS` is neither.

### What this Worker does *not* trust

Request headers, including `Cf-Access-Authenticated-User-Email`. They are
convenient and they are also just headers: any client can send one, and a Worker
route stays reachable on its own hostname even when you believe Access is in
front of it.

Identity comes from `ctx.access` instead, which the runtime attaches only after
Access has authenticated the request against one of your own applications. A
caller cannot forge it, because it is not part of the request they sent. A
request Access did not authenticate arrives with `ctx.access` undefined and is
refused, so a route that is reachable without Access fails closed rather than
falling back to whatever the caller claimed to be.

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
npx wrangler secret put GOOGLE_SERVICE_ACCOUNT_KEY   # paste the whole key JSON
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
| `2026-01-02T03:04:05.000Z` | `ada@example.com` |

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
| `access_jwt_missing` | 401 | No Access identity — the request did not come through Access. |
| `access_identity_unknown` | 403 | Access authenticated the caller but returned no email. A service token has no identity behind it and is refused here. |
| `sheet_not_specified` | 400 | The request named no sheet and `DEFAULT_SHEET_ID` is unset. |
| `not_authorized` | 403 | The sheet is not configured, or this caller's application is not on its list. |
| `invalid_json`, `invalid_payload`, `invalid_field_name` | 400 | Unusable body. |
| `header_mismatch` | 409 | The form's shape and the sheet's header row disagree. |
| `payload_too_large`, `field_too_large` | 413 | Over `MAX_BODY_BYTES` or a 50k-character cell. |
| `too_many_columns` | 422 | A first submission defining more than 512 columns. |
| `not_configured` | 500 | Missing or unparseable sheet map, or missing service-account secret. |
| `sheet_not_shared` | 502 | Share the spreadsheet with the service account. |
| `sheet_not_found` | 502 | Google has no spreadsheet with that id. |
| `sheets_api_unavailable` | 503 | Google rate-limited us or is down; retry. |

## Configuration reference

| Var | Default | Purpose |
| --- | --- | --- |
| `SHEET_ACCESS` | — | Spreadsheet id → allowed Access AUDs; see `src/sheet-access.js`. |
| `DEFAULT_SHEET_ID` | *(empty)* | Sheet used when a request names none. |
| `RESPONSES_TAB` | `Responses` | Default tab; a sheet's `tab` wins. |
| `STAMP_IDENTITY` | `true` | Add `_received_at` / `_identity`; a sheet's `stamp` wins. |
| `CORS_ORIGINS` | *(empty)* | Comma-separated origins, or `*`. Empty means no CORS headers. |
| `MAX_BODY_BYTES` | `131072` | Request body ceiling. |
| `GOOGLE_SERVICE_ACCOUNT_KEY` | — | **Secret.** The service-account key JSON. |

Per-sheet keys: `auds` (required; `[]` allows any caller Access admitted to this
route), `label`, `tab`, `stamp`, `allowMissingFields`, `requireEmails`,
`requireEmailDomains`, `requireServiceTokens`, `requireIdpGroups`,
`requireAccessGroups`. An array in place of the object is shorthand for `auds`.

`requireIdpGroups` and `requireAccessGroups` both match against the groups
`getIdentity()` returns, and a sheet naming groups under either is matched
against the union. `requireServiceTokens` can no longer be satisfied — a service
token is refused for having no identity — but a sheet declaring one stays
closed rather than becoming unconstrained.

## Known limits

- **Appends are not serialised.** Two simultaneous submissions both append, and
  the Sheets API handles that; but the "read headers, then append" pair is not
  atomic. With header drift now an error rather than a schema edit, the only
  race left is two submissions to a brand-new empty tab, where both may try to
  write the header row. Send the first submission yourself, or pre-create the
  header row, if that matters.
- **An empty `auds` array admits every Access application that routes here** —
  see above. It is the one setting here that can be wrong in a way Access will
  not catch for you.
- **Service tokens cannot submit.** A service token authenticates to Access but
  has no IdP identity behind it, so `getIdentity()` returns no email and the
  request is refused with `access_identity_unknown`. This Worker is built for
  browser submissions; machine clients would need an identity to stamp into
  `_identity`.
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

`npm test` covers identity handling, sheet authorization, header-drift
detection, value handling and payload sanitising — the parts where a mistake is
a security or data-integrity problem.

The `access.dev` block in `wrangler.jsonc` simulates a signed-in Access identity
under `wrangler dev`, so both paths can be exercised locally: change
`identity.email` to submit as someone else, or delete the block to see what an
unauthenticated request gets. It applies to `wrangler dev` only and is ignored
on deploy, where the real Access application supplies `ctx.access`. The Sheets
API calls are thin wrappers over `fetch` and still need the real service.

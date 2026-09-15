// Turning a flat JSON object into a row on the "Responses" tab.
//
// Row 1 holds the header names and defines the shape of the form. The first
// submission to an empty tab writes that header row; every submission after it
// must match the header row exactly, and a request whose fields have drifted is
// rejected with `header_mismatch` rather than silently reshaping the sheet.
//
// This is the deliberate difference from the Apps Script it replaces, which
// appended a new column the first time it saw an unfamiliar key. That is
// forgiving in the moment and lossy over time: a typo'd field name, a renamed
// input, or a half-deployed client quietly produces a sheet with two columns
// that mean the same thing and rows that are only partly populated, and nobody
// finds out until someone reads the data. Failing the write puts the problem in
// front of whoever changed the form, while it is still cheap to fix.
//
// A binding can set "allowMissingFields": true to accept a submission that
// omits some columns (an unchecked checkbox never posts a value, so plain HTML
// forms usually need this); unknown fields are an error either way.
//
// Values are written with valueInputOption=RAW, so the Sheets API stores them
// verbatim and never parses them. The Apps Script had to prefix `=`, `+`, `-`
// and `@` with an apostrophe to stop a submitted value executing as a formula;
// RAW removes the whole class of problem without mangling legitimate values
// like "-5" or "+44 20 7946 0958".

import { HttpError } from './http.js';
import { sheetsFetch } from './google.js';

export const MAX_COLUMNS = 512;

// A1 notation quotes a sheet name with single quotes and escapes an embedded
// quote by doubling it.
export function quoteTabName(name) {
  return `'${String(name).replace(/'/g, "''")}'`;
}

function range(tab, suffix) {
  return encodeURIComponent(`${quoteTabName(tab)}!${suffix}`);
}

// Compares the sheet's header row against the fields in the submission.
// Exported for tests.
export function diffHeaders(headers, data, { allowMissingFields = false } = {}) {
  const fields = Object.keys(data);
  const known = new Set(headers);
  const submitted = new Set(fields);

  return {
    unexpected: fields.filter((field) => !known.has(field)),
    missing: allowMissingFields ? [] : headers.filter((header) => !submitted.has(header)),
  };
}

export function assertHeadersMatch(headers, data, { allowMissingFields = false, tab = 'Responses' } = {}) {
  const { unexpected, missing } = diffHeaders(headers, data, { allowMissingFields });
  if (unexpected.length === 0 && missing.length === 0) return;

  const problems = [];
  if (unexpected.length > 0) problems.push(`fields not in the sheet: ${unexpected.join(', ')}`);
  if (missing.length > 0) problems.push(`columns the submission did not include: ${missing.join(', ')}`);

  throw new HttpError(
    409,
    'header_mismatch',
    `the submission does not match the header row of "${tab}" (${problems.join('; ')}). ` +
      'Add the columns to the sheet, correct the form, or set "allowMissingFields" on the binding.',
  );
}

export function cellValue(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'object') return JSON.stringify(value);
  return value;
}

export function buildRow(headers, data) {
  return headers.map((header) =>
    Object.prototype.hasOwnProperty.call(data, header) ? cellValue(data[header]) : '',
  );
}

async function tabExists(env, sheetId, tab) {
  const meta = await sheetsFetch(env, sheetId, '?fields=sheets.properties.title');
  return (meta.sheets || []).some((sheet) => sheet.properties && sheet.properties.title === tab);
}

async function createTab(env, sheetId, tab) {
  try {
    await sheetsFetch(env, sheetId, ':batchUpdate', {
      method: 'POST',
      body: JSON.stringify({ requests: [{ addSheet: { properties: { title: tab } } }] }),
    });
  } catch (err) {
    // Two submissions racing to create the same tab: the loser gets
    // "already exists", which is the state it wanted anyway.
    const alreadyExists = err instanceof HttpError && /already exists/i.test(err.detail || '');
    if (!alreadyExists) throw err;
  }
}

async function readHeaderRow(env, sheetId, tab) {
  try {
    const body = await sheetsFetch(env, sheetId, `/values/${range(tab, '1:1')}?majorDimension=ROWS`);
    const row = (body.values && body.values[0]) || [];
    return row.map((value) => String(value));
  } catch (err) {
    // The API reports a missing tab as an unparseable range, not a 404.
    if (!(err instanceof HttpError) || err.code !== 'sheets_api_error') throw err;
    if (await tabExists(env, sheetId, tab)) throw err;
    await createTab(env, sheetId, tab);
    return [];
  }
}

async function writeHeaderRow(env, sheetId, tab, headers) {
  if (headers.length > MAX_COLUMNS) {
    throw new HttpError(422, 'too_many_columns', `a submission cannot define more than ${MAX_COLUMNS} columns`);
  }
  await sheetsFetch(env, sheetId, `/values/${range(tab, 'A1')}?valueInputOption=RAW`, {
    method: 'PUT',
    body: JSON.stringify({ values: [headers] }),
  });
}

export async function appendRecord(env, sheetId, tab, data, { allowMissingFields = false } = {}) {
  let headers = await readHeaderRow(env, sheetId, tab);
  let createdHeaders = false;

  if (headers.length === 0) {
    // An empty tab has no shape yet, so this submission defines it.
    headers = Object.keys(data);
    await writeHeaderRow(env, sheetId, tab, headers);
    createdHeaders = true;
  } else {
    assertHeadersMatch(headers, data, { allowMissingFields, tab });
  }

  const result = await sheetsFetch(
    env,
    sheetId,
    `/values/${range(tab, 'A1')}:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS`,
    { method: 'POST', body: JSON.stringify({ values: [buildRow(headers, data)] }) },
  );

  return {
    columns: headers.length,
    createdHeaders,
    updatedRange: (result && result.updates && result.updates.updatedRange) || null,
  };
}

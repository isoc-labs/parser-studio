// Default deny for automatic mapping (owner decision 2026-11-28), end to end: sample -> Map Fields -> the Ruby the
// user downloads, executed on the raw logs.
//
// An official Stellar field is written automatically only for a field the shared Semantic Policy lists, and only
// from a source that stands for the record. Every other source field - one that merely carries the name of a
// Stellar field, or a member of an object of the record - keeps its own name and value in the manufacturer
// namespace, on the screen and in the generated parser alike. Such a field is still offered to ChatGPT mapping,
// which the user confirms, and to manual mapping.
import { test, expect, type Page, type Locator } from './support/downloadSink';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { LISTED_OFFICIAL_FIELDS, officialMappings } from './normalizationAcceptance';

const RUNNER = resolve('scripts/verification/ruby-golden-event-runner.rb');
const isObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);
function leaves(value: unknown, out: string[] = []): string[] {
  if (Array.isArray(value)) for (const item of value) leaves(item, out);
  else if (isObject(value)) for (const item of Object.values(value)) leaves(item, out);
  else if (value !== null && value !== undefined) out.push(String(value));
  return out;
}

// Listed fields under their own names, with values their protections accept.
const LISTED = (n: number) => ({
  srcip: '10.20.0.' + n, dstip: '198.51.100.' + n, srcport: 51000 + n, dstport: 443, proto: 6,
  action: n === 2 ? 'deny' : 'allow', username: 'user' + n, vlan: 120 + n, srcmac: '02:00:00:00:00:0' + n,
  url: 'https://portal.example.test/p' + n, timestamp: '2026-11-27T10:00:0' + n + 'Z',
});
// Names of Stellar fields the policy does not list. Each was written as the official field from its name alone
// before this decision (severity until 2026-11-27); the values are of the documented type on purpose.
const NOT_LISTED = (n: number) => ({
  hostname: 'edge-0' + n, severity: 70 + n, fidelity: 80 + n, duration: 1500 + n, file_size: 2048 + n,
  appid: 40 + n, policyid: 7, process_name: 'svc' + n + '.exe', event_id: 4620 + n, icmp_type: '8',
  hostip: '10.99.0.' + n, command: 'run-' + n,
});
// Listed names inside an object of the record: they name that object (a translated endpoint, a file time, a
// referrer), not the record.
const MEMBERS = (n: number) => ({
  xlate: { srcip: '203.0.113.' + n, srcport: 40000 + n }, file: { timestamp: '2020-01-0' + n + 'T00:00:00Z' },
  referrer: { url: 'https://other.example.test/r' + n }, target: { username: 'victim' + n },
});
// A vendor name that is not a Stellar name at all (used for the manual mapping).
const OTHER = (n: number) => ({ dev_host: 'node-0' + n });
const EVENTS = [1, 2, 3].map(n => ({ ...LISTED(n), ...NOT_LISTED(n), ...MEMBERS(n), ...OTHER(n) }));
const RAW = EVENTS.map(event => JSON.stringify(event));
const VENDOR_SOURCES = [...Object.keys(NOT_LISTED(1)), 'xlate.srcip', 'xlate.srcport', 'file.timestamp', 'referrer.url',
  'target.username', 'dev_host'];

async function openMap(page: Page): Promise<Locator> {
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(RAW.join('\n'));
  await page.getByLabel('Parser manufacturer').fill('Example Security');
  await page.getByLabel('Parser product', { exact: true }).fill('Policy Probe');
  await expect(page.getByLabel('Automatic event accounting')).toContainText('3/3 events analyzed locally');
  await page.getByRole('button', { name: 'Analyze Logs', exact: true }).click();
  const review = page.getByRole('button', { name: 'Review Fields', exact: true });
  await expect(review).toBeEnabled({ timeout: 20_000 });
  await review.click();
  await page.getByLabel('Review Fields stage').getByRole('button', { name: 'Map Fields' }).click();
  const map = page.getByLabel('Map Fields stage');
  await expect(map).toBeVisible();
  return map;
}
/** Create the parser files, download the Ruby and run it on every raw log of the sample (one event each). */
async function downloadedRubyRecords(page: Page, map: Locator): Promise<{ ruby: string; records: Record<string, unknown>[] }> {
  await map.getByRole('button', { name: 'Create Parser' }).click();
  await expect(page.getByLabel('Create Parser stage')).toBeVisible();
  await page.getByRole('button', { name: 'Create Parser Files' }).click();
  const files = page.getByLabel('Generated parser files');
  await expect(files).toContainText('Parser files created successfully', { timeout: 20_000 });
  const downloadPromise = page.waitForEvent('download');
  await files.getByRole('button', { name: /customized_[a-z0-9_]+$/ }).click();
  const ruby = readFileSync((await (await downloadPromise).path())!, 'utf8');
  expect(ruby.length).toBeGreaterThan(0);
  const run = spawnSync(process.env.PARSER_RUBY_BIN || 'ruby', [RUNNER], {
    input: JSON.stringify({ cases: RAW.map((raw, index) => ({ id: 'e' + index, ruby, raw })) }),
    encoding: 'utf8', timeout: 60_000, maxBuffer: 4 * 1024 * 1024,
  });
  expect(run.status, 'ruby runner: ' + String(run.stderr).slice(0, 300)).toBe(0);
  const out = JSON.parse(run.stdout) as { ruby: string; results: Record<string, { calls: [unknown, unknown][] }> };
  const records = RAW.map((_, index) => {
    const calls = out.results['e' + index]!.calls;
    expect(calls.length, 'one event for one raw log').toBe(1);
    expect(isObject(calls[0]![1])).toBe(true);
    return calls[0]![1] as Record<string, unknown>;
  });
  return { ruby: out.ruby, records };
}
/** What default deny requires of one output event, on the screen or from the Ruby. `extra` are official fields the
 * user mapped on purpose in this test (root key -> value). */
function checkEvent(record: Record<string, unknown>, n: number, where: string, extra: Record<string, unknown> = {}) {
  // Official: the listed fields, with the values of the event (a time is kept as the same instant).
  for (const [name, value] of Object.entries(LISTED(n))) {
    expect(Object.prototype.hasOwnProperty.call(record, name), where + ' official ' + name).toBe(true);
    if (name === 'timestamp') expect(Date.parse(String(record[name])) || Number(record[name]), where + ' timestamp')
      .toBe(Date.parse(String(value)));
    else expect(record[name], where + ' ' + name).toBe(value);
  }
  for (const [name, value] of Object.entries(extra)) expect(record[name], where + ' user-mapped ' + name).toBe(value);
  // Not official: no root key for a name the policy does not list (unless the user mapped it in this test).
  for (const name of Object.keys(NOT_LISTED(n)))
    expect(Object.prototype.hasOwnProperty.call(record, name), where + ' must not write ' + name).toBe(false);
  expect(record.srcip, where + ' srcip is the endpoint of the record, not the translated one').toBe('10.20.0.' + n);
  // Kept: every value of the event is still in the output.
  const kept = leaves(record);
  for (const value of [...Object.values(NOT_LISTED(n)), ...leaves(MEMBERS(n)), ...Object.values(OTHER(n))])
    expect(kept, where + ' keeps ' + String(value)).toContain(String(value));
  expect(isObject(record['Example Security']), where + ' manufacturer namespace').toBe(true);
}
const officialKeys = (record: Record<string, unknown>, also: readonly string[] = []) =>
  Object.keys(record).filter(key => LISTED_OFFICIAL_FIELDS.includes(key) || also.includes(key)).sort();
async function shownEvent(map: Locator): Promise<{ record: Record<string, unknown>; n: number }> {
  const record = JSON.parse((await map.locator('.normalization-full-preview pre').nth(2).textContent()) ?? '{}') as Record<string, unknown>;
  const n = EVENTS.findIndex(event => event.srcip === record.srcip) + 1;
  expect(n, 'the previewed event is one of the sample').toBeGreaterThan(0);
  return { record, n };
}

test('default deny: only listed fields become official, on the screen and in the downloaded Ruby', async ({ page }) => {
  test.skip(!process.env.PARSER_STUDIO_BROWSER_BACKEND,
    'Needs the real compile backend; the exact-head browser shards provide it.');
  const map = await openMap(page);

  // Screen: the official rows are exactly the listed fields, each from the root-level source of the same name.
  const official = await officialMappings(map);
  expect(official).toEqual(Object.fromEntries(Object.keys(LISTED(1)).map(name => [name, name])));
  for (const target of Object.values(official)) expect(LISTED_OFFICIAL_FIELDS).toContain(target);
  // Nothing else is even proposed: no recommendation and no "Check first" row for the other names.
  await expect(map.getByLabel('Recommended field matches').getByRole('button', { name: /^Apply official mapping / })).toHaveCount(0);
  // Every source field that is not official is still there, as a vendor field, to map with ChatGPT or by hand.
  for (const source of VENDOR_SOURCES)
    await expect(map.locator('article.normalization-map-row.custom[data-source-path="' + source + '"]'), source).toHaveCount(1);

  const shown = await shownEvent(map);
  const { ruby, records } = await downloadedRubyRecords(page, map);
  records.forEach((record, index) => checkEvent(record, index + 1, 'ruby ' + ruby + ' event ' + (index + 1)));
  // The screen showed the same official fields the Ruby wrote for that event.
  checkEvent(shown.record, shown.n, 'screen preview');
  expect(officialKeys(shown.record)).toEqual(officialKeys(records[shown.n - 1]!));
  expect(officialKeys(shown.record)).toEqual(Object.keys(LISTED(1)).sort());
});

test('default deny: a field that is not listed is mapped only by ChatGPT with the user\'s confirmation or by hand', async ({ page }) => {
  test.skip(!process.env.PARSER_STUDIO_BROWSER_BACKEND,
    'Needs the real compile backend; the exact-head browser shards provide it.');
  test.setTimeout(90_000);
  const map = await openMap(page);
  const assistant = map.getByLabel('ChatGPT JSONata field mapping');
  await assistant.getByRole('button', { name: 'Improve mappings with ChatGPT JSONata' }).click();
  await assistant.getByRole('button', { name: 'Prepare Mapping Prompt' }).click();
  const promptText = await assistant.getByLabel('ChatGPT JSONata mapping prompt').inputValue();
  // The prompt hands the fields default deny left unmapped to ChatGPT.
  const unmapped = promptText.split('Source fields without an official Stellar Cyber mapping: ')[1]?.split('\n')[0] ?? '';
  for (const name of ['hostname', 'policyid', 'severity', 'xlate.srcip', 'dev_host']) expect(unmapped, 'prompt offers ' + name).toContain('"' + name + '"');
  const sha = promptText.match(/"sha256":\s*"([a-f0-9]{64})"/)?.[1];
  expect(sha).toMatch(/^[a-f0-9]{64}$/);
  await assistant.getByLabel('Paste ChatGPT JSONata mapping response').fill(JSON.stringify({
    contract: 'parser-studio.mapping-jsonata.v0.1', sample: { sha256: sha, events: 3 },
    mappings: [
      { expression: 'policyid', target: 'fw_policy_id' },
      { expression: 'hostname', target: 'hostname' },
      { expression: 'xlate.srcip', target: 'srcip' },
    ],
  }));
  await assistant.getByRole('button', { name: 'Check JSONata Mappings' }).click();
  const reviewed = assistant.getByLabel('Reviewed ChatGPT JSONata mappings');
  const row = (text: string) => reviewed.locator('label.jsonata-assist-row').filter({ hasText: text });
  // A proposal for a field the policy does not list is never ready by itself: the user has to confirm its meaning.
  for (const text of ['policyid → fw_policy_id', 'hostname → hostname']) {
    await expect(row(text)).toContainText('CHECK FIRST');
    await expect(row(text).locator('input[type="checkbox"]')).not.toBeChecked();
  }
  // The translated address cannot take the place of the endpoint the record already has.
  await expect(row('xlate.srcip → srcip')).toContainText('BLOCKED');
  await expect(row('xlate.srcip → srcip').locator('input[type="checkbox"]')).toBeDisabled();
  expect((await officialMappings(map)).policyid, 'nothing is applied by the check').toBeUndefined();

  // The user confirms one of the two; the other stays a vendor field.
  await row('policyid → fw_policy_id').locator('input[type="checkbox"]').check();
  await assistant.getByLabel('I reviewed the selected JSONata mappings').check();
  const apply = assistant.getByRole('button', { name: /Apply 1 Reviewed Mapping/ });
  await expect(apply).toBeDisabled();
  await assistant.getByLabel('I confirm uncertain mapping meanings').check();
  await apply.click();
  await expect(map.locator('article.normalization-map-row.verified[data-source-path="policyid"]')).toHaveCount(1);

  // Manual mapping: the user opens the folded list of vendor fields and types the Stellar field for one of them.
  await map.locator('details.normalization-vendor-list > summary').click();
  const manual = map.locator('article.normalization-map-row[data-source-path="dev_host"] input[aria-label^="Stellar field "]');
  await manual.fill('computer_name');
  await expect(map.locator('article.normalization-map-row.verified[data-source-path="dev_host"]')).toHaveCount(1);

  const official = await officialMappings(map);
  expect(official).toEqual({ ...Object.fromEntries(Object.keys(LISTED(1)).map(name => [name, name])),
    policyid: 'fw_policy_id', dev_host: 'computer_name' });
  await expect(map.locator('article.normalization-map-row.custom[data-source-path="hostname"]')).toHaveCount(1);

  const shown = await shownEvent(map);
  const { ruby, records } = await downloadedRubyRecords(page, map);
  const chosen = (n: number) => ({ fw_policy_id: '7', computer_name: 'node-0' + n });
  records.forEach((record, index) => checkEvent(record, index + 1, 'ruby ' + ruby + ' event ' + (index + 1), chosen(index + 1)));
  checkEvent(shown.record, shown.n, 'screen preview', chosen(shown.n));
  expect(officialKeys(shown.record, ['fw_policy_id', 'computer_name']))
    .toEqual(officialKeys(records[shown.n - 1]!, ['fw_policy_id', 'computer_name']));
});

import {typeParserDetail} from './support/parserIdentity';
import {test,expect} from './support/downloadSink';
import type {Download,Page} from '@playwright/test';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';

// Parser details (manufacturer, product, version, .conf port) typed with real key presses in both creation paths.
// 1. An editing control stays on the page while its value is edited; the names the user typed are the names of
//    the created files (the final-step identity card used to leave the page at the first valid character).
// 2. A change of the details makes the created files out of date. The pasted ChatGPT reply (written by this
//    test; ChatGPT is not called), its test and its approval are kept. The prompt embeds the names and version,
//    so it is withdrawn while they are out of date; it does not embed the port. A change of the original logs
//    still starts over.
// 3. A Map Fields row stays under the keyboard while its Stellar field name is typed.
// SYNTHETIC lines in the FortiGate key=value layout and the Snort "fast" alert layout; documentation addresses.
const KV='date=2026-10-15 time=00:04:12 devname="FGT-EDGE01" action="blocked" srcip=192.0.2.10 srcport=51514 dstip=198.51.100.20 dstport=443 proto=6\n'+
  'date=2026-10-15 time=00:04:13 devname="FGT-EDGE01" action="allowed" srcip=192.0.2.11 srcport=51515 dstip=198.51.100.21 dstport=80 proto=6';
const ALERTS='05/30-19:09:10.917356  [**] [1:527:8] SYNTHETIC same source and destination [**] [Classification: Potentially Bad Traffic] [Priority: 2] {UDP} 192.0.2.10:68 -> 198.51.100.255:67\n'+
  '05/30-19:09:28.472094  [**] [1:2012811:2] SYNTHETIC query for a test domain [**] [Classification: Potentially Bad Traffic] [Priority: 2] {UDP} 192.0.2.11:1029 -> 198.51.100.1:53';
const HOLDOUT='12/30-14:09:21.116402  [**] [1:1917:6] SYNTHETIC service discovery attempt [**] [Classification: Detection of a Network Scan] [Priority: 3] {TCP} 192.0.2.12:1035 -> 198.51.100.2:1900\n'+
  '01/21-02:23:42.327730  [**] [1:2014520:2] SYNTHETIC attachment served over HTTP [**] [Classification: Misc activity] [Priority: 3] {TCP} 198.51.100.3:80 -> 192.0.2.13:1051';
const PATTERN=String.raw`^(?<ts>[0-9/:.-]+) +\[\*\*\] \[(?<sig>[0-9:]+)\] (?<msg>[^\[]+) \[\*\*\] \[(?<ck>[A-Za-z]+): (?<cls>[^\]]+)\] \[(?<pk>[A-Za-z]+): (?<pri>\d+)\] \{(?<proto>[A-Z]+)\} (?<s>(?<src>[0-9.]+):(?<sport>\d+)) -> (?<d>(?<dst>[0-9.]+):(?<dport>\d+))$`;
function reply(projectId:string){
  const map=(source:string,target:string,type:'ip'|'port')=>[
    {op:'map_field',source,target,data_type:type,group:'top_fields'},{op:'cast_type',target,data_type:type}];
  return JSON.stringify({contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
    projectId,sourceFormat:'regex',bodyFormat:'regex',
    sample:{sha256:createHash('sha256').update(ALERTS).digest('hex'),events:2},
    stages:[{op:'split_event',boundary:'single-line'},{op:'parse_regex',pattern:PATTERN},
      ...map('src','srcip','ip'),...map('dst','dstip','ip'),...map('sport','srcport','port'),...map('dport','dstport','port'),
      {op:'classify',defaultIndex:'syslog',rules:[]},{op:'fallback_unparsed',mode:'retain_unparsed'}],
    nativeVerified:false,targetVerified:false});
}
async function saved(page:Page,click:()=>Promise<void>):Promise<{name:string;text:string}>{
  const [download]:[Download,void]=await Promise.all([page.waitForEvent('download'),click()]);
  return {name:download.suggestedFilename(),text:await readFile((await download.path())!,'utf8')};
}

test.skip(
  process.env.PARSER_STUDIO_LIVE_BACKEND!=='1' || process.env.PARSER_STUDIO_TEST_MULTIPASS!=='1',
  'Requires the exact-pinned loopback authoring backend and the Multi-Pass preview service.'
);

test('Auto Parser: the final-step identity card stays while its values are typed and names the created files',async({page,context})=>{
  test.setTimeout(180_000);
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(KV);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:20000});
  await review.click();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  await page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser'}).click();
  const create=page.getByRole('button',{name:'Create Parser Files'});
  const product=page.getByLabel('Parser product',{exact:true});
  const note=page.getByLabel('Placeholder parser name');
  const files=page.getByLabel('Generated parser files');
  await expect(create).toBeDisabled();
  await expect(note).toContainText('Downloaded files are blocked');

  await typeParserDetail(page,'Parser manufacturer','Fortinet');
  await expect(create).toBeDisabled();
  // Every key reaches the field: the first valid character must not take the card away.
  await product.click();
  await page.keyboard.press('ControlOrMeta+A');
  await page.keyboard.press('Backspace');
  await expect(product).toBeFocused();
  await expect(product).toHaveValue('');
  await page.keyboard.type('FortiGatee');
  await page.keyboard.press('Backspace');
  await page.keyboard.press('Home');
  await page.keyboard.press('Delete');
  await page.keyboard.type('F');
  await expect(product).toBeFocused();
  await expect(product).toHaveValue('FortiGate');
  await expect(note).toHaveCount(0);
  await expect(create).toBeEnabled();
  // Valid, then empty, then valid again: creation follows the value and the field keeps the focus.
  await page.keyboard.press('ControlOrMeta+A');
  await page.keyboard.press('Delete');
  await expect(product).toBeFocused();
  await expect(create).toBeDisabled();
  await expect(note).toContainText('product');
  await context.grantPermissions(['clipboard-read','clipboard-write']);
  await page.evaluate(text=>navigator.clipboard.writeText(text),'FortiGate');
  await page.keyboard.press('ControlOrMeta+V');
  await expect(product).toBeFocused();
  await expect(product).toHaveValue('FortiGate');
  // Leaving the step and coming back keeps what was typed.
  await page.getByRole('button',{name:'Map Fields',exact:true}).click();
  await page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser'}).click();
  await expect(page.getByLabel('Parser manufacturer',{exact:true})).toHaveValue('Fortinet');
  await expect(product).toHaveValue('FortiGate');

  await create.click();
  await expect(files).toContainText('Parser files created successfully',{timeout:30000});
  const conf=await saved(page,()=>files.getByRole('button',{name:/customized_fortinet_fortigate\.conf$/}).click());
  const ruby=await saved(page,()=>files.getByRole('button',{name:/customized_fortinet_fortigate$/}).click());
  expect(conf.name).toBe('customized_fortinet_fortigate.conf');
  expect(ruby.name).toBe('customized_fortinet_fortigate');
  expect(conf.text).toMatch(/^\s*port\s+6801\s*$/m);
  expect(conf.text).toContain('customized_fortinet_fortigate');
  expect(ruby.text).not.toContain('Demo Local Draft');
  // A new port makes the created files out of date; the names stay and the next files carry the port.
  const port=page.getByRole('spinbutton',{name:'Parser listener port'});
  await port.click();
  await page.keyboard.press('ControlOrMeta+A');
  await page.keyboard.type('7514');
  await expect(port).toBeFocused();
  await expect(port).toHaveValue('7514');
  await expect(files).toHaveCount(0);
  await create.click();
  await expect(files).toContainText('Parser files created successfully',{timeout:30000});
  const moved=await saved(page,()=>files.getByRole('button',{name:/customized_fortinet_fortigate\.conf$/}).click());
  expect(moved.text).toMatch(/^\s*port\s+7514\s*$/m);
});

test('ChatGPT Assisted: parser details typed after the reply keep the reply, its test and its approval',async({page})=>{
  test.setTimeout(240_000);
  await page.goto('/?workspace=chatgpt');
  await page.getByLabel('ChatGPT local sample logs').fill(ALERTS);
  await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
  const prompt=page.getByLabel('ChatGPT copyable prompt');
  await expect(prompt).toBeVisible({timeout:30000});
  const prepared=await prompt.inputValue();
  const projectId=/draft-[a-z][a-z0-9_]+/.exec(prepared)![0];
  // The prompt editor stays while its text is cleared and typed again.
  await prompt.click();
  await page.keyboard.press('ControlOrMeta+A');
  await page.keyboard.press('Backspace');
  await expect(prompt).toBeFocused();
  await expect(prompt).toHaveValue('');
  await prompt.fill(prepared);

  const response=page.getByLabel('ChatGPT result JSON');
  const answer=reply(projectId);
  await response.fill(answer);
  await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
  await page.getByLabel('Additional ChatGPT test logs').fill(HOLDOUT);
  await page.getByLabel('Confirm test examples are different').check();
  await page.getByRole('button',{name:'Test Proposed Fix'}).click();
  const tested=page.getByLabel('ChatGPT fix test result');
  await expect(tested).toContainText('Overall test: PASS',{timeout:30000});
  const approval=page.getByLabel('Approve tested ChatGPT fix');
  await approval.check();
  const apply=page.getByRole('button',{name:'Apply Fix & Create Parser Files'});
  const note=page.getByLabel('Placeholder parser name');
  await expect(apply).toBeDisabled();
  await expect(note).toContainText('Downloaded files are blocked');

  // The product asks for the real names here. Typing them must not discard the work above.
  await typeParserDetail(page,'Parser manufacturer','Snort');
  await typeParserDetail(page,'Parser product','IDS');
  await typeParserDetail(page,'Parser product version','2.9');
  await expect(prompt).toHaveCount(0);
  await expect(page.getByLabel('ChatGPT prompt out of date')).toContainText('checks are kept');
  await expect(response).toHaveValue(answer);
  await expect(tested).toContainText('Overall test: PASS');
  await expect(approval).toBeChecked();
  await expect(note).toHaveCount(0);
  await expect(apply).toBeEnabled();

  // A name typed while the files are being created: files for the earlier name are not offered.
  let release=()=>{};
  const held=new Promise<void>(resolve=>{release=resolve;});
  await page.route('**/api/v1/parser-pairs/generate',async route=>{await held;await route.continue();});
  await apply.click();
  await page.getByLabel('Parser product',{exact:true}).click();
  await page.keyboard.press('End');
  await page.keyboard.type('S');
  release();
  const created=page.getByLabel('ChatGPT created parser files');
  await expect(page.getByRole('status').filter({hasText:'changed while the files were being created'})).toBeVisible({timeout:30000});
  await expect(created).toHaveCount(0);
  await page.unroute('**/api/v1/parser-pairs/generate');
  await page.keyboard.press('Backspace');
  await expect(page.getByLabel('Parser product',{exact:true})).toHaveValue('IDS');

  await apply.click();
  await expect(created).toContainText('Parser files created successfully',{timeout:60000});
  const conf=await saved(page,()=>created.getByRole('button',{name:'Download customized_snort_ids.conf'}).click());
  const ruby=await saved(page,()=>created.getByRole('button',{name:'Download customized_snort_ids',exact:true}).click());
  expect(conf.name).toBe('customized_snort_ids.conf');
  expect(ruby.name).toBe('customized_snort_ids');
  expect(conf.text).toMatch(/^\s*port\s+6801\s*$/m);
  expect(ruby.text).not.toContain('Demo Local Draft');
  expect(ruby.text).not.toContain('demo_firewall');

  // The .conf port alone: created files go out of date, the reply and its approval stay, new files carry the port.
  const port=page.getByRole('spinbutton',{name:'Parser listener port'});
  await port.click();
  await page.keyboard.press('ControlOrMeta+A');
  await page.keyboard.type('7514');
  await expect(port).toHaveValue('7514');
  await expect(created).toHaveCount(0);
  await expect(page.getByRole('status').filter({hasText:'Create the parser files again'})).toBeVisible();
  await expect(response).toHaveValue(answer);
  await expect(approval).toBeChecked();
  await apply.click();
  await expect(created).toContainText('Parser files created successfully',{timeout:60000});
  const moved=await saved(page,()=>created.getByRole('button',{name:'Download customized_snort_ids.conf'}).click());
  expect(moved.text).toMatch(/^\s*port\s+7514\s*$/m);

  // The original logs are a parsing input: changing them starts over.
  await page.getByLabel('ChatGPT local sample logs').fill(ALERTS+'\n'+HOLDOUT.split('\n')[0]);
  await expect(page.getByLabel('ChatGPT prompt out of date')).toHaveCount(0);
  await expect(response).toHaveValue('');
  await expect(created).toHaveCount(0);
});

test('Map Fields: a row stays under the keyboard while a Stellar field name is typed through other official names',async({page})=>{
  test.setTimeout(120_000);
  const wide=KV.split('\n').map(line=>line+' '+Array.from({length:14},(_,i)=>'extra'+i+'=value'+i).join(' ')).join('\n');
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(wide);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:20000});
  await review.click();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  const folded=page.locator('details.normalization-vendor-list');
  await folded.locator('summary').click();
  const row=page.locator('article[data-source-path$="devname"]');
  const field=row.getByLabel(/^Stellar field /);
  await expect(folded.locator('article[data-source-path$="devname"]')).toHaveCount(1);
  // "srcip" is an official name on the way to "srcip_host": the row must not leave before the name is complete.
  await field.click();
  await page.keyboard.press('ControlOrMeta+A');
  await page.keyboard.type('srcip_host');
  await expect(field).toBeFocused();
  await expect(field).toHaveValue('srcip_host');
  await expect(folded.locator('article[data-source-path$="devname"]')).toHaveCount(1);
  // Once focus leaves the row it is listed with the matched fields, with the name the user typed.
  await page.keyboard.press('Tab');
  await page.locator('h3',{hasText:'Review field matches'}).click();
  await expect(folded.locator('article[data-source-path$="devname"]')).toHaveCount(0);
  await expect(row.getByLabel(/^Stellar field /)).toHaveValue('srcip_host');
  await expect(row.locator('.normalization-map-status')).toContainText('Matched to Stellar');
});

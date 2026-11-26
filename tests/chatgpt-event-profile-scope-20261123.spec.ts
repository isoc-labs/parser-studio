import {expandZipDownload} from '../backend/src/downloaded-artifact-validation';
import {readFile} from 'node:fs/promises';
import {test,expect} from './support/downloadSink';

// ChatGPT Assisted on a parser with event profiles (PAN-OS TRAFFIC + CEF in one stream). The user improves
// one event type; the other type keeps its parsing and mappings; one multi-type parser is generated.
// The ChatGPT reply below is written by this test: it is NOT a real ChatGPT answer and proves no AI success rate.
// SYNTHETIC lines after the documented PAN-OS TRAFFIC and ArcSight CEF formats.
const PAN='<14>Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51514,443,62001,443,0x400053,tcp,allow,1840,1200,640,12,2026/10/15 00:03:01,20,any,0,987654321,0x0,10.0.0.0-10.255.255.255,United States,0,7,5,aged-out,0,0,0,0,vsys1,PA-FW01,from-policy';
const PAN2=PAN.replace('10.10.20.15','10.10.20.16');
const CEF='CEF:0|Vendor|Product|1.0|100|Login|5|src=10.0.0.7 dst=10.0.0.8 spt=51234 dpt=443 act=allow';
const CEF2=CEF.replace('10.0.0.7','10.0.0.9');
const HOLDOUT=[CEF.replace('10.0.0.7','10.0.0.11').replace('Login','Logout'),CEF.replace('10.0.0.7','10.0.0.12').replace('act=allow','act=deny')].join('\n');

type Stage={op:string;[key:string]:unknown};

test('ChatGPT Assisted improves one event type of a multi-type parser and generates one parser',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_LIVE_BACKEND!=='1','Requires the same-HEAD backend.');
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill([PAN,CEF,PAN2,CEF2].join('\n'));
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeEnabled({timeout:20000});
  await page.getByRole('complementary',{name:'Parser Studio navigation'})
    .getByRole('button',{name:'ChatGPT Assisted Parser'}).click();
  const scope=page.getByLabel('ChatGPT event type scope');
  await expect(scope).toBeVisible({timeout:15000});
  await scope.selectOption('structured_family_cef');
  await expect(page.getByLabel('ChatGPT local sample logs')).toHaveValue([CEF,CEF2].join('\n'));
  await page.getByLabel('Parser manufacturer').fill('Palo Alto Networks');
  await page.getByLabel('Parser product',{exact:true}).fill('PAN-OS');
  const prepare=page.getByRole('button',{name:'Prepare ChatGPT Prompt'});
  await expect(prepare).toBeEnabled({timeout:15000});
  await prepare.click();
  const copied=page.getByLabel('ChatGPT copyable prompt');
  await expect(copied).toBeVisible({timeout:20000});
  const prompt=await copied.inputValue();
  expect(prompt).toContain([CEF,CEF2].join('\n'));
  expect(prompt).not.toContain('TRAFFIC,end');
  const baseline=/----- BEGIN VALIDATED BASELINE RECIPE -----\n([\s\S]+?)\n----- END VALIDATED BASELINE RECIPE -----/.exec(prompt);
  expect(baseline).toBeTruthy();
  const recipe=JSON.parse(baseline![1]!) as {stages:Stage[]};
  // One bounded correction: the CEF name becomes the Stellar Cyber event_name field.
  const name=recipe.stages.find(stage=>stage.op==='map_field'&&stage.source==='body.cef_name');
  expect(name).toBeTruthy();
  name!.target='event_name';name!.group='top_fields';
  await page.getByLabel('ChatGPT result JSON').fill(JSON.stringify(recipe));
  await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
  await expect(page.getByLabel('ChatGPT result ready for testing')).toBeVisible({timeout:15000});
  await page.getByLabel('Additional ChatGPT test logs').fill(HOLDOUT);
  await page.getByLabel('Confirm test examples are different').check();
  await page.getByRole('button',{name:'Test Proposed Fix'}).click();
  await expect(page.getByLabel('ChatGPT fix test result')).toContainText('Overall test: PASS',{timeout:20000});
  await page.getByLabel('Approve tested ChatGPT fix').check();
  await page.getByRole('button',{name:'Apply Fix & Create Parser Files'}).click();
  await expect(page.getByLabel('ChatGPT created parser files')).toContainText('Parser files created successfully',{timeout:30000});
  await page.getByRole('button',{name:'Apply to event type structured_family_cef'}).click();
  const selection=page.getByLabel('ChatGPT event type selection');
  await expect(selection.getByRole('status')).toContainText('Other event types are unchanged');
  const generate=selection.getByRole('button',{name:'Validate & Generate One Multi-Type Parser'});
  await expect(generate).toBeEnabled({timeout:20000});
  await generate.click();
  const downloads=selection.getByLabel('Combined parser downloads');
  await expect(downloads).toContainText('Two integrity-checked DRAFT files are available',{timeout:30000});
  const ruby=downloads.getByRole('button',{name:/^Download (?!.*\.conf$)/}).first();
  const pending=page.waitForEvent('download');
  await ruby.click();
  const chunks:Buffer[]=[];
  for await(const part of await (await pending).createReadStream())chunks.push(Buffer.from(part));
  const confButton=downloads.getByRole('button',{name:/^Download .*\.conf$/});
  const [conf]=await Promise.all([page.waitForEvent('download'),confButton.click()]);
  const confText=await readFile(await conf.path(),'utf8');
  expect(confText).toMatch(/^\s+port 6801$/m);
  const [archive]=await Promise.all([page.waitForEvent('download'),downloads.getByRole('button',{name:'Download Parser Package'}).click()]);
  const expanded=expandZipDownload(await readFile(await archive.path()));
  expect(expanded.problems).toEqual([]);
  const rubyText=Buffer.concat(chunks).toString('utf8');
  expect(expanded.entries.find(e=>e.name===conf.suggestedFilename().replace(/\.conf$/,''))?.content).toBe(rubyText);
  expect(expanded.entries.find(e=>e.name===conf.suggestedFilename())?.content).toBe(confText);
  const b64=/Base64.strict_decode64\('([^']+)'\)/.exec(Buffer.concat(chunks).toString('utf8'))?.[1];
  expect(b64).toBeTruthy();
  type Fields=Record<string,{normalized_name:string}>;
  type Group={topFields:Fields;nsFields:Fields;vendorFields:Fields};
  const compiled=JSON.parse(Buffer.from(b64!,'base64').toString('utf8')) as {normalization:Group&{
    eventProfiles:{variants:(Group&{name:string})[]}}};
  const variants=compiled.normalization.eventProfiles.variants;
  expect(variants.map(variant=>variant.name)).toEqual(['panos_traffic_csv','structured_family_cef']);
  const of=(name:string)=>variants.find(variant=>variant.name===name)!;
  const sources=(group:Group)=>[...Object.keys(group.topFields),...Object.keys(group.nsFields),...Object.keys(group.vendorFields)];
  // The corrected CEF name is a Stellar Cyber field of the CEF type only.
  expect(of('structured_family_cef').topFields['body.cef_name']?.normalized_name).toBe('event_name');
  expect(of('structured_family_cef').vendorFields['body.cef_name']).toBeUndefined();
  // PAN-OS TRAFFIC keeps its own mappings; nothing moved to the shared mappings.
  expect(sources(of('panos_traffic_csv'))).not.toContain('body.cef_name');
  expect(of('panos_traffic_csv').topFields['generic.fields.src']?.normalized_name).toBe('srcip');
  expect(sources(compiled.normalization)).not.toContain('body.cef_name');
});

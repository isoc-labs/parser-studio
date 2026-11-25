import {test,expect} from './support/downloadSink';
import {createHash} from 'node:crypto';

// P4 mapping fallback on a parser with event profiles (PAN-OS TRAFFIC + CEF): automatic mapping first, then a
// ChatGPT JSONata mapping for one event type, then the generated parser. The pasted reply is written by this
// test, not by ChatGPT, and proves no AI success rate. SYNTHETIC lines after the documented formats.
const PAN='<14>Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51514,443,62001,443,0x400053,tcp,allow,1840,1200,640,12,2026/10/15 00:03:01,20,any,0,987654321,0x0,10.0.0.0-10.255.255.255,United States,0,7,5,aged-out,0,0,0,0,vsys1,PA-FW01,from-policy';
const CEF='CEF:0|Vendor|Product|1.0|100|Login|5|src=10.0.0.7 dst=10.0.0.8 spt=51234 dpt=443 act=allow';
const FULL=[PAN,CEF,PAN.replace('10.10.20.15','10.10.20.16'),CEF.replace('10.0.0.7','10.0.0.9')].join('\n');

test('ChatGPT JSONata mapping changes one event type of a multi-type parser and the generated parser',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_LIVE_BACKEND!=='1','Requires the same-HEAD backend.');
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(FULL);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const reviewButton=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(reviewButton).toBeEnabled({timeout:20000});
  await reviewButton.click();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  const map=page.getByLabel('Map Fields stage');
  await expect(map).toBeVisible();
  await map.getByRole('button',{name:'Improve mappings with ChatGPT JSONata'}).click();
  await map.getByLabel('ChatGPT mapping event type scope').selectOption('structured_family_cef');
  await map.getByLabel('Include observed values in ChatGPT mapping prompt').check();
  await map.getByRole('button',{name:'Prepare Mapping Prompt'}).click();
  const area=map.getByLabel('ChatGPT JSONata mapping prompt');
  await expect(area).toBeVisible({timeout:15000});
  const prompt=await area.inputValue();
  expect(prompt).toContain('Relevant Stellar Cyber 7.0 dictionary entries');
  expect(prompt).toContain('Improve only event type structured_family_cef');
  expect(prompt).toContain('Login');
  const sha=/"sha256": "([a-f0-9]{64})"/.exec(prompt)![1]!;
  await map.getByLabel('Paste ChatGPT JSONata mapping response').fill(JSON.stringify({contract:'parser-studio.mapping-jsonata.v0.1',
    sample:{sha256:sha,events:2},mappings:[{expression:'body.cef_name',target:'event_name'}]}));
  await map.getByRole('button',{name:'Check JSONata Mappings'}).click();
  await expect(map.getByLabel('Reviewed ChatGPT JSONata mappings')).toContainText('event_name');
  const row=map.getByLabel('Approve JSONata mapping body.cef_name to event_name');
  if(!(await row.isChecked()))await row.check();
  await map.getByLabel('I reviewed the selected JSONata mappings').check();
  const uncertain=map.getByLabel('I confirm uncertain mapping meanings');
  if(await uncertain.count())await uncertain.check();
  await map.getByRole('button',{name:'Apply 1 Reviewed Mapping'}).click();
  // The field preview is recomputed after the change; the generated project below is the evidence.
  const create=map.getByRole('button',{name:'Create Parser'});
  await expect(create).toBeEnabled({timeout:20000});
  await create.click();
  await expect(page.getByLabel('Create Parser stage')).toBeVisible();
  const generate=page.waitForResponse(response=>
    response.request().method()==='POST'&&response.url().endsWith('/parser-pairs/generate'));
  await page.getByRole('button',{name:'Create Parser Files'}).click();
  const result=await generate;
  expect(result.status()).toBe(200);
  const pair=await result.json() as {files:{name:string;content:string;sha256:string}[]};
  const ruby=pair.files.find(file=>!file.name.endsWith('.conf'))!;
  const encoded=/Base64.strict_decode64\('([^']+)'\)/.exec(ruby.content)?.[1];
  const project=JSON.parse(Buffer.from(encoded!,'base64').toString('utf8'));
  const variants=project.normalization.eventProfiles.variants as {name:string;topFields:Record<string,{normalized_name:string}>;
    vendorFields:Record<string,unknown>}[];
  const find=(name:string)=>variants.find(variant=>variant.name===name)!;
  expect(find('structured_family_cef').topFields['body.cef_name']?.normalized_name).toBe('event_name');
  expect(find('structured_family_cef').vendorFields['body.cef_name']).toBeUndefined();
  expect(find('panos_traffic_csv').topFields['body.cef_name']).toBeUndefined();
  expect(find('panos_traffic_csv').topFields['generic.fields.src']?.normalized_name).toBe('srcip');
  const downloaded=page.waitForEvent('download');
  await page.getByLabel('Generated parser files').getByRole('button',{name:ruby.name,exact:true}).click();
  const chunks:Buffer[]=[];
  for await(const chunk of await (await downloaded).createReadStream())chunks.push(Buffer.from(chunk));
  expect(createHash('sha256').update(Buffer.concat(chunks)).digest('hex')).toBe(ruby.sha256);
});

import {enterSyntheticParserIdentity} from './support/parserIdentity';
import {test,expect} from './support/downloadSink';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {officialMappings} from './normalizationAcceptance';

async function goToMapFields(page:import('@playwright/test').Page,raw:string){
  await page.goto('/');
  await enterSyntheticParserIdentity(page);
  await page.getByLabel('Auto Parser raw logs').fill(raw);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Automatic event accounting'))
    .toContainText('2/2 events analyzed locally',{timeout:20000});
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:20000});
  await review.click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  const map=page.getByLabel('Map Fields stage');
  await expect(map).toBeVisible();
  await expect(map).toContainText('Stellar field dictionary 7.0.xs');
  return map;
}

test('fixed Stellar 7.0 Dictionary: conflicting address aliases cannot be bulk-approved',async({page})=>{
  const raw=[
    {src_ip:'192.0.2.11',source_ip:'203.0.113.20',request_status:200},
    {src_ip:'192.0.2.12',source_ip:'203.0.113.21',request_status:403},
  ].map(item=>JSON.stringify(item)).join('\n');
  const map=await goToMapFields(page,raw);
  const suggested=map.getByLabel('Recommended field matches');
  await expect(suggested.getByRole('button',{name:'Apply 0 recommended matches'})).toBeDisabled();
  await expect(suggested.getByText(/multiple source fields map to the same/i)).toHaveCount(2);
  await expect(suggested.getByRole('button',{name:'Apply official mapping src_ip'})).toBeVisible();
  await expect(suggested.getByRole('button',{name:'Apply official mapping source_ip'})).toBeVisible();
  await expect(suggested.getByRole('button',{name:'Apply official mapping request_status'})).toHaveCount(0);
  await suggested.getByRole('button',{name:'Apply official mapping src_ip'}).click();
  await expect(suggested.getByRole('button',{name:'Apply official mapping source_ip'})).toHaveCount(0);
  await expect(map.getByLabel('Field mapping checks')).toContainText('No mapping problems found');
  await expect(map.getByLabel('Field changes only')).toContainText('srcip');
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveCount(0);
});

// Default deny (owner decision 2026-11-28): process.name, process.pid, file.hash.sha256, host.ip and user.name are
// names of the 7.0 dictionary, and until then the equal name alone made them Stellar fields. The policy lists
// none of them (which process, which host and whose file a record means is not said by the name), so they keep
// their own names as vendor fields and the user or the ChatGPT assistant decides.
test('fixed Stellar 7.0 Dictionary: a nested name that equals a dictionary name is kept as a vendor field',async({page})=>{
  const row=(pid:number,ip:string)=>({
    process:{name:'powershell.exe',pid},file:{hash:{sha256:'a'.repeat(64)}},
    host:{ip},user:{name:'test.user'},
  });
  const raw=[row(151,'192.0.2.10'),row(152,'192.0.2.11')]
    .map(item=>JSON.stringify(item)).join('\n');
  const map=await goToMapFields(page,raw);
  const suggested=map.getByLabel('Recommended field matches');
  await expect(map.getByLabel('Field mapping summary')).toContainText('Matched to Stellar0');
  await expect(map.getByLabel('Field mapping summary')).toContainText('Vendor fields retained5');
  await expect(map.getByLabel('Field mapping summary')).toContainText('Left out of output0');
  await expect(suggested.getByRole('button',{name:'Apply 0 recommended matches'})).toBeDisabled();
  expect(await officialMappings(map.getByLabel('Field mapping editor'))).toEqual({});
  const vendor=await map.locator('article.normalization-map-row.custom')
    .evaluateAll(nodes=>nodes.map(node=>node.getAttribute('data-source-path')));
  expect(vendor.sort()).toEqual(
    ['process.name','process.pid','file.hash.sha256','host.ip','user.name'].sort());
  await map.getByRole('button',{name:'Back to Review Fields'}).click();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Back to Logs'}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(raw);
});


test('7.0 nested field mappings generate real backend DRAFT files with checked digests',async({page})=>{
  // Default deny (2026-11-28): rule.name is the nested dictionary name the policy lists; the other five nested
  // names are carried as vendor fields.
  const raw=[
    {rule:{name:'allow-web'},process:{name:'safe.exe',pid:100},file:{hash:{sha256:'a'.repeat(64)}},host:{ip:'192.0.2.11'},user:{name:'synthetic_a'}},
    {rule:{name:'allow-dns'},process:{name:'safe2.exe',pid:101},file:{hash:{sha256:'b'.repeat(64)}},host:{ip:'192.0.2.12'},user:{name:'synthetic_b'}},
  ].map(item=>JSON.stringify(item)).join('\n');
  const requests:string[]=[];
  page.on('request',req=>{
    if(req.method()==='POST'&&req.url().includes('/api/v1/parser-pairs/')){
      requests.push(req.url());
      expect(req.postData()??'').not.toContain('synthetic_a');
      expect(req.postData()??'').not.toContain('192.0.2.11');
    }
  });
  const map=await goToMapFields(page,raw);
  await expect(map.getByLabel('Field mapping summary')).toContainText('Matched to Stellar1');
  await expect(map.getByLabel('Field mapping summary')).toContainText('Vendor fields retained5');
  expect(await officialMappings(map.getByLabel('Field mapping editor'))).toEqual({'rule.name':'rule.name'});
  await expect(map.getByLabel('Field mapping checks')).toContainText('All current field mappings passed the sample checks');
  await map.getByRole('button',{name:'Create Parser',exact:true}).click();
  await expect(page.getByLabel('Create Parser stage')).toBeVisible();
  const response=page.waitForResponse(r=>r.url().endsWith('/parser-pairs/generate')&&r.request().method()==='POST');
  await page.getByRole('button',{name:'Create Parser Files'}).click();
  const result=await response;
  expect(result.status()).toBe(200);
  const pair=await result.json() as {
    manifest:{status:string;engineVerified:boolean;targetImportVerified:boolean;fileHashes:Record<string,string>};
    files:Array<{name:string;content:string;sha256:string}>;
  };
  expect(pair.manifest).toMatchObject({status:'DRAFT',engineVerified:false,targetImportVerified:false});
  expect(pair.files).toHaveLength(2);
  const ruby=pair.files.find(item=>!item.name.endsWith('.conf'));
  expect(ruby).toBeDefined();
  // The production DRAFT Ruby holds a base64-encoded checked project, not
  // plaintext normalization rules. Decode that project and verify the actual
  // Backend compiler input that was embedded in the downloaded artifact.
  const encoded=ruby!.content.match(/Base64\.strict_decode64\('([A-Za-z0-9+/=]+)'\)/)?.[1];
  expect(encoded).toBeTruthy();
  const embedded=JSON.parse(Buffer.from(encoded!,'base64').toString('utf8')) as {
    normalization:{
      topFields:Record<string,{normalized_name:string;data_type:string}>;
      nsFields:Record<string,{normalized_name:string;data_type:string}>;
      vendorFields:Record<string,{normalized_name:string;data_type:string}>;
    };
  };
  expect(embedded.normalization.nsFields['rule.name']).toMatchObject({normalized_name:'rule.name',data_type:'string'});
  expect(Object.keys(embedded.normalization.topFields)).toEqual([]);
  expect(Object.keys(embedded.normalization.nsFields)).toEqual(['rule.name']);
  for(const [field,type] of [
    ['process.name','string'],['process.pid','integer'],
    ['file.hash.sha256','string'],['host.ip','ip'],['user.name','string'],
  ]){
    expect(embedded.normalization.vendorFields[field]).toMatchObject({data_type:type});
  }
  // Five sources, five different vendor names: process.name and user.name do not fall on one output name.
  expect(new Set(Object.values(embedded.normalization.vendorFields).map(item=>item.normalized_name)).size).toBe(5);
  expect(ruby!.content).not.toContain('synthetic_a');
  const sha=(value:string|Buffer)=>createHash('sha256').update(value).digest('hex');
  for(const file of pair.files){
    expect(sha(file.content)).toBe(file.sha256);
    expect(pair.manifest.fileHashes[file.name]).toBe(file.sha256);
    const pendingDownload=page.waitForEvent('download');
    await page.getByLabel('Generated parser files').getByRole('button',{name:file.name,exact:true}).click();
    const downloaded=await pendingDownload;
    expect(sha(await readFile(await downloaded.path()))).toBe(file.sha256);
  }
  expect(requests.some(url=>url.endsWith('/parser-pairs/generate'))).toBe(true);
  await expect(page.getByLabel('Generated parser files')).toContainText('Native runtime and Stellar target verification are separate; nothing was deployed.');
});

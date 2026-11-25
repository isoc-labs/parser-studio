import {test,expect,type Page} from './support/downloadSink';
import {mkdirSync,writeFileSync} from 'node:fs';

// The journey of a first user through the Auto Parser on the DEPLOYED Development Preview: no local web server, no
// local backend, no mocked route. Run by ops/preview-domain/playwright.deployed.config.ts (release.sh verify), never
// by the evergreen *.spec.ts suite. Each case goes from pasted lines to the two downloaded files and checks that
// - the page talks to its own origin only, raises no page error and gets no 5xx answer,
// - the .conf listens on the default port 6801, or on the port the user typed,
// - each downloaded file is byte for byte the generated one.
// With PARSER_STUDIO_DEPLOYED_OUT set, <out>/<case>/ receives parser.rb, parser.conf, runtime.lines (the sample, then
// lines the parser has not seen) and runtime.expect (texts the Ruby 2.4.9 records of those lines must contain: values
// of fields that were not in the sample, and the whole text of a line the parser cannot read). SYNTHETIC lines.
interface Case{readonly port:number|null;readonly sample:readonly string[];readonly runtime:readonly string[];readonly expect:readonly string[]}
const SYSLOG='<134>Nov 25 21:40:01 edge-fw-01 fwd: ';
const PREFIX='<134>Oct 19 08:23:59 ftd01 %FTD-4-430002: Intrusion event detected ';
const CASES:Readonly<Record<string,Case>>={
  // Syslog header + key=value, the default listener port.
  syslog_kv_default_port:{port:null,
    sample:[SYSLOG+'srcip=10.44.7.21 dstip=198.51.100.77 srcport=51522 dstport=8443 proto=tcp action=permit',
      SYSLOG+'srcip=10.44.7.22 dstip=198.51.100.78 srcport=51523 dstport=443 proto=tcp action=deny'],
    runtime:[SYSLOG+'srcip=2001:db8::21 dstip=2001:db8::77 srcport=40000 dstport=53 proto=udp action=permit policy_tag=zx-new-k1',
      'this line is not a firewall event'],
    expect:['2001:db8::21','zx-new-k1','this line is not a firewall event']},
  // key=value separated by commas, a listener port typed by the user.
  comma_kv_custom_port:{port:6819,
    sample:['srcip=10.0.0.1,dstip=10.0.0.2,action=deny','srcip=10.0.0.3,dstip=10.0.0.4,action=permit'],
    runtime:['srcip=10.0.0.5,dstip=10.0.0.6,action=deny,zone_tag=zx-new-c1'],
    expect:['10.0.0.5','10.0.0.6','zx-new-c1']},
  // key=value separated by semicolons.
  semicolon_kv:{port:null,
    sample:['srcip=10.0.0.1;dstip=10.0.0.2;action=deny','srcip=10.0.0.3;dstip=10.0.0.4;action=permit'],
    runtime:['srcip=10.0.0.5;dstip=10.0.0.6;action=deny;zone_tag=zx-new-s1'],
    expect:['10.0.0.5','10.0.0.6','zx-new-s1']},
  // JSON with nested objects.
  json_nested:{port:null,
    sample:['{"event":{"type":"alert","severity":3},"net":{"src":{"ip":"10.9.8.7","port":51000},"dst":{"ip":"203.0.113.40","port":443}}}',
      '{"event":{"type":"flow","severity":1},"net":{"src":{"ip":"10.9.8.8","port":51001},"dst":{"ip":"203.0.113.41","port":8443}}}'],
    runtime:['{"event":{"type":"alert","severity":5,"tag":"zx-new-j1"},"net":{"src":{"ip":"10.9.8.9","port":51002},"dst":{"ip":"203.0.113.42","port":22}}}'],
    expect:['10.9.8.9','203.0.113.42','zx-new-j1']},
  // A text prefix followed by key=value pairs behind a Syslog header.
  syslog_text_prefix_kv:{port:null,
    sample:[PREFIX+'signature=1000123 src=192.0.2.40 dst=198.51.100.5 action=block',
      PREFIX+'signature=1000124 src=192.0.2.41 dst=198.51.100.6 action=alert'],
    runtime:[PREFIX+'signature=1000125 src=192.0.2.42 dst=198.51.100.7 action=block'],
    expect:['1000125','192.0.2.42','198.51.100.7']},
};
const OUT=process.env.PARSER_STUDIO_DEPLOYED_OUT;

async function journey(page:Page,baseURL:string,name:string){
  const item=CASES[name]!;
  const origin=new URL(baseURL).origin;
  const pageErrors:string[]=[],offOrigin:string[]=[],serverErrors:string[]=[];
  page.on('pageerror',error=>pageErrors.push(error.message));
  page.on('request',request=>{
    const url=request.url();
    if(!url.startsWith(origin+'/')&&!url.startsWith('data:')&&!url.startsWith('blob:'))offOrigin.push(url);
  });
  page.on('response',response=>{if(response.status()>=500)serverErrors.push(response.status()+' '+response.url());});
  await page.goto('/');
  const listener=page.getByRole('spinbutton',{name:'Parser listener port'}).first();
  await expect(listener).toHaveValue('6801');
  if(item.port!==null)await listener.fill(String(item.port));
  await page.getByLabel('Auto Parser raw logs').fill(item.sample.join('\n'));
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary'))
    .toContainText(item.sample.length+' of '+item.sample.length+' log events structurally parsed',{timeout:40_000});
  const review=page.getByRole('button',{name:'Review Fields',exact:true}).last();
  await expect(review).toBeEnabled({timeout:30_000});
  await review.click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible({timeout:20_000});
  await page.getByRole('button',{name:'Map Fields',exact:true}).last().click();
  await expect(page.getByLabel('Map Fields stage')).toBeVisible({timeout:20_000});
  await page.getByRole('button',{name:'Create Parser',exact:true}).last().click();
  await expect(page.getByLabel('Create Parser stage')).toBeVisible({timeout:20_000});
  const generate=page.waitForResponse(response=>
    response.request().method()==='POST'&&response.url().endsWith('/parser-pairs/generate'));
  await page.getByRole('button',{name:'Create Parser Files'}).click();
  const result=await generate;
  expect(result.status()).toBe(200);
  expect(new URL(result.url()).origin).toBe(origin);
  const generated=page.getByLabel('Generated parser files');
  await expect(generated).toContainText('Parser files created successfully',{timeout:40_000});
  const pair=await result.json() as {files:{name:string;content:string;sha256:string}[]};
  const ruby=pair.files.find(file=>!file.name.endsWith('.conf'))!;
  const conf=pair.files.find(file=>file.name.endsWith('.conf'))!;
  for(const file of [ruby,conf]){
    const downloaded=page.waitForEvent('download');
    await generated.getByRole('button',{name:file.name,exact:true}).click();
    const chunks:Buffer[]=[];
    for await(const chunk of await (await downloaded).createReadStream())chunks.push(Buffer.from(chunk));
    expect(Buffer.concat(chunks).toString('utf8')).toBe(file.content);
  }
  expect(conf.content).toContain('port '+(item.port??6801));
  expect(conf.content).toContain('@type '+ruby.name);
  expect(ruby.content.length).toBeGreaterThan(1000);
  if(OUT){
    const dir=OUT+'/'+name;
    mkdirSync(dir,{recursive:true});
    writeFileSync(dir+'/parser.rb',ruby.content);
    writeFileSync(dir+'/parser.conf',conf.content);
    writeFileSync(dir+'/runtime.lines',[...item.sample,...item.runtime].join('\n')+'\n');
    writeFileSync(dir+'/runtime.expect',item.expect.join('\n')+'\n');
    writeFileSync(dir+'/journey.json',JSON.stringify({origin,port:item.port??6801,
      files:pair.files.map(file=>({name:file.name,sha256:file.sha256,bytes:file.content.length})),pageErrors,offOrigin,serverErrors},null,1));
  }
  expect(pageErrors).toEqual([]);
  expect(offOrigin).toEqual([]);
  expect(serverErrors).toEqual([]);
}

for(const name of Object.keys(CASES))
  test('deployed preview: '+name.replace(/_/g,' ')+' goes from pasted lines to the downloaded parser files',async({page,baseURL})=>{
    test.setTimeout(240_000);
    await journey(page,baseURL!,name);
  });

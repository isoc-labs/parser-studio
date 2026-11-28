// Independent test data loader shared by browser, aggregate Native and gate tests.
// Never derive destination truth from the product's mapping plan.
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';

type Value=string|number;
/** A documented value the event must keep and must not write to the named official field (default deny). */
export interface GoldenDeclinedDestination{source:string;target:string;value:Value}
export function loadGoldenDeclinedDestinations(root=process.cwd()):Record<string,GoldenDeclinedDestination[]>{
  const semantic=JSON.parse(readFileSync(resolve(root,'evals/golden-corpus/stellar70-semantic-goldens.v1.json'),'utf8')) as {
    cases:Record<string,{target:string}[]>; notOfficial?:Record<string,GoldenDeclinedDestination[]>;
  };
  const result:Record<string,GoldenDeclinedDestination[]>=Object.create(null);
  for(const [id,rows] of Object.entries(semantic.notOfficial??{})){
    if(!Object.prototype.hasOwnProperty.call(semantic.cases,id))throw new Error('GOLDEN_DECLINED_UNKNOWN_CASE '+id);
    for(const row of rows){
      if(!row.source||!row.target||(typeof row.value!=='string'&&typeof row.value!=='number')||
        semantic.cases[id]!.some(expected=>expected.target===row.target))
        throw new Error('GOLDEN_DECLINED_INVALID '+id+' '+row.target);
    }
    result[id]=rows;
  }
  return result;
}
export function loadGoldenDestinationExpectations(root=process.cwd()):Record<string,Record<string,Value>>{
  const base='evals/golden-corpus/';
  const endpoints=JSON.parse(readFileSync(resolve(root,base+'stellar70-endpoint-goldens.v1.json'),'utf8')) as {
    contract:string; cases:Record<string,Record<string,Value>>;
  };
  const semantic=JSON.parse(readFileSync(resolve(root,base+'stellar70-semantic-goldens.v1.json'),'utf8')) as {
    contract:string; cases:Record<string,{source:string;target:string;value:Value}[]>;
  };
  if(endpoints.contract!=='parserstudio.stellar70-endpoint-goldens.v1'||
    semantic.contract!=='parserstudio.stellar70-semantic-goldens.v1'||
    JSON.stringify(Object.keys(endpoints.cases).sort())!==JSON.stringify(Object.keys(semantic.cases).sort()))
    throw new Error('GOLDEN_DESTINATION_REGISTRY_MISMATCH');
  const result:Record<string,Record<string,Value>>=Object.create(null);
  for(const [id,fields] of Object.entries(endpoints.cases)){
    const entries=Object.entries(fields);
    const targets=new Set(entries.map(([target])=>target));
    for(const row of semantic.cases[id]!){
      if(!row.source||!row.target||targets.has(row.target)||
        (typeof row.value!=='string'&&typeof row.value!=='number'))
        throw new Error('GOLDEN_DESTINATION_INVALID '+id+' '+row.target);
      targets.add(row.target);entries.push([row.target,row.value]);
    }
    result[id]=Object.fromEntries(entries);
  }
  return result;
}

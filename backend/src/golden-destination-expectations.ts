// Independent test data loader shared by browser, aggregate Native and gate tests.
// Never derive destination truth from the product's mapping plan.
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';

type Value=string|number;
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

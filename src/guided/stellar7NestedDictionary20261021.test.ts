import {describe,it,expect} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {findStellarMetadataField,STELLAR_METADATA_CATALOG_PROVENANCE} from './stellarMetadataCatalog';
import {suggestNormalizationCandidates,valueFitsNormalizationTarget} from './normalizationCandidates';
import {validateNormalizationMappings} from './normalizationValidation';

describe('fixed Stellar Cyber 7.0 namespace contract, no cross-version fallback',()=>{
  it('exposes only explicitly documented, typed 7.0 nested destinations',()=>{
    expect(STELLAR_METADATA_CATALOG_PROVENANCE.release).toBe('7.0.xs');
    for(const [name,type] of [
      ['host.ip','ip'],['host.name','string'],['user.name','string'],
      ['process.name','string'],['process.pid','integer'],
      ['process.command_line','string'],['process.hash.sha256','string'],
      ['file.name','string'],['file.path','string'],['file.hash.sha256','string'],
    ]){
      expect(findStellarMetadataField(name)).toMatchObject({
        name,mappingType:type,mappable:true,group:'ns_fields',
      });
    }
    expect(findStellarMetadataField('file')).toMatchObject({mappable:false});
    expect(findStellarMetadataField('process')).toMatchObject({mappable:false});
    expect(findStellarMetadataField('unknown.hash.sha256')).toBeUndefined();
  });

  it('validates documented hash meanings rather than string type alone',()=>{
    expect(valueFitsNormalizationTarget('sha256','string','a'.repeat(32))).toBe(false);
    expect(valueFitsNormalizationTarget('sha256','string','a'.repeat(64))).toBe(true);
    expect(valueFitsNormalizationTarget('file.hash.sha256','string','a'.repeat(32))).toBe(false);
    expect(valueFitsNormalizationTarget('process.hash.sha256','string','A'.repeat(64))).toBe(true);
    expect(valueFitsNormalizationTarget('file.hash.sha1','string','a'.repeat(40))).toBe(true);
    expect(valueFitsNormalizationTarget('file.hash.md5','string','x'.repeat(32))).toBe(false);
    expect(valueFitsNormalizationTarget('action','string',200)).toBe(false);
    expect(valueFitsNormalizationTarget('action','string','block')).toBe(true);
  });

  // Default deny, 2026-11-28: a nested 7.0 name is proposed only when the policy lists it (rule.name). The other
  // names of the namespace supplement (process, file, host, user) are documented fields a user or a reviewed
  // ChatGPT mapping may write; a matching name is not a reason to write them automatically.
  it('proposes a nested 7.0 name only when the policy lists it',()=>{
    const data={
      process:{name:'powershell.exe',pid:890,hash:{sha256:'a'.repeat(64)}},
      file:{hash:{sha256:'b'.repeat(64)}},
      host:{ip:'198.51.100.25'},user:{name:'test.user'},rule:{name:'Block-PowerShell'},
    };
    expect(suggestNormalizationCandidates(data,[]).map(item=>[item.source,item.target,item.confidence,item.group]))
      .toEqual([['rule.name','rule.name','HIGH','ns_fields']]);
    expect(suggestNormalizationCandidates({file:{hash:{sha256:'a'.repeat(32)}}},[])).toEqual([]);
  });

  it('writes reviewed namespace mapping to nested preview while respecting official type',()=>{
    const draft=createDraft();draft.format='json';
    draft.mappings=[
      {id:'proc',source:'process.name',target:'process.name',type:'string'},
      {id:'host',source:'host.ip',target:'host.ip',type:'ip'},
    ];
    draft.guided={...draft.guided!,groups:{...draft.guided!.groups,proc:'ns_fields',host:'ns_fields'}};
    const result=preview(JSON.stringify({process:{name:'powershell.exe'},host:{ip:'192.0.2.9'}}),draft);
    expect(result.events[0]?.normalized).toMatchObject({process:{name:'powershell.exe'},host:{ip:'192.0.2.9'}});
    expect(validateNormalizationMappings(result,draft.mappings,draft.guided.groups)).toEqual([]);
  });
});

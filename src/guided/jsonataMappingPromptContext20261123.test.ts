import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';
import {createJsonataMappingPrompt} from './jsonataMappingAssist';
import {familyPromptContext,familyScopes,familySource,projectFamilyDraft} from './familyScopedAssist';
import {findStellarMetadataField} from './stellarMetadataCatalog';

// P4: the ChatGPT mapping prompt carries what a correct Stellar Cyber 7.0 mapping needs: the relevant
// dictionary entries with their types and documented meaning, the source fields still unmapped, and for a
// parser with event profiles the event types and their mappings. SYNTHETIC lines after documented formats.
const PAN='<14>Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51514,443,62001,443,0x400053,tcp,allow,1840,1200,640,12,2026/10/15 00:03:01,20,any,0,987654321,0x0,10.0.0.0-10.255.255.255,United States,0,7,5,aged-out,0,0,0,0,vsys1,PA-FW01,from-policy';
const CEF='CEF:0|Vendor|Product|1.0|100|Login|5|src=10.0.0.7 dst=10.0.0.8 spt=51234 dpt=443 act=allow';
const CEF2=CEF.replace('10.0.0.7','10.0.0.9');
const FULL=[PAN,CEF,PAN.replace('10.10.20.15','10.10.20.16'),CEF2].join('\n');

const section=(prompt:string,title:string)=>{
  const at=prompt.indexOf(title);
  expect(at,title).toBeGreaterThanOrEqual(0);
  return JSON.parse(prompt.slice(at+title.length).split('\n\n')[0]!) as unknown;
};

describe('the ChatGPT mapping prompt',()=>{
  it('lists the relevant Stellar Cyber 7.0 dictionary entries and the unmapped source fields',async()=>{
    const routed=buildAutomaticGenericStructuralDraft(FULL,createDraft())!.draft;
    const scope=familyScopes(routed,preview(FULL,routed))!.find(item=>item.name==='structured_family_cef')!;
    const draft=projectFamilyDraft(routed,scope.name)!;
    const source=familySource(FULL,scope);
    const {prompt}=await createJsonataMappingPrompt(preview(source,draft),draft,true);
    const entries=section(prompt,'Relevant Stellar Cyber 7.0 dictionary entries: ') as
      {name:string;type:string;group:string;description:string}[];
    const srcip=entries.find(entry=>entry.name==='srcip')!;
    expect(srcip).toEqual({name:'srcip',type:findStellarMetadataField('srcip')!.mappingType,
      group:'top_fields',description:findStellarMetadataField('srcip')!.descriptions[0]!.slice(0,200)});
    // Targets already in use and common security targets are both present, each once.
    for(const name of ['dstip','srcport','dstport','action','event_name'])
      expect(entries.filter(entry=>entry.name===name)).toHaveLength(1);
    expect(entries.every(entry=>findStellarMetadataField(entry.name)?.mappable)).toBe(true);
    const unmapped=section(prompt,'Source fields without an official Stellar Cyber mapping: ') as string[];
    expect(unmapped).toContain('body.act');
    expect(unmapped).toContain('body.cef_name');
    expect(unmapped).not.toContain('body.src');
  });
  it('describes the event types of the parser when one type is selected',async()=>{
    const routed=buildAutomaticGenericStructuralDraft(FULL,createDraft())!.draft;
    const suite=preview(FULL,routed);
    const scopes=familyScopes(routed,suite)!;
    const draft=projectFamilyDraft(routed,'structured_family_cef')!;
    const source=familySource(FULL,scopes.find(item=>item.name==='structured_family_cef')!);
    const context=familyPromptContext(routed,scopes,'structured_family_cef');
    const {prompt}=await createJsonataMappingPrompt(preview(source,draft),draft,false,{eventProfileContext:context});
    expect(prompt).toContain('Improve only event type structured_family_cef');
    expect(prompt).not.toContain('10.10.20.15');
  });
});

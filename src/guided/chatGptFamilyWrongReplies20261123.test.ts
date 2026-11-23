import {beforeAll,describe,expect,it} from 'vitest';
import {createDraft,type ParserDraft,type SuiteResult} from '../model';
import {preview} from '../parser';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';
import {buildReviewableRecipe} from './parserRecipeV2';
import {extractRecipeJson} from './aiReplyExtract';
import {importRecoveryAIRecipe,importReviewOnlyAIRecipe,proposeV01EnrichmentFromAI,proposeV01FieldMappingFromAI,
  proposeV01MappingCorrectionFromAI,proposeV01RecoveryParserFromAI,type AIImportResult} from './aiRecipeExchange';
import {compareCandidate,compareMappingCorrectionCandidate,normalizedMappingOutputPath} from './autoParserRegression';
import {familyScopes,familySource,mergeFamilyCandidate,projectFamilyDraft} from './familyScopedAssist';
import {toBackendProject} from './backendAdapter';

// Deliberately wrong ChatGPT replies for one event type of a multi-type parser (PAN-OS TRAFFIC + CEF), each run
// through the same checks as the ChatGPT Assisted screen: reply extraction, recipe import, the one-change
// proposal, comparison with the original and different examples, and the merge into the event type.
// The replies are written by this test, not by ChatGPT: the results say nothing about an AI success rate.
// SYNTHETIC lines after the documented PAN-OS TRAFFIC and ArcSight CEF formats.
const PAN='<14>Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51514,443,62001,443,0x400053,tcp,allow,1840,1200,640,12,2026/10/15 00:03:01,20,any,0,987654321,0x0,10.0.0.0-10.255.255.255,United States,0,7,5,aged-out,0,0,0,0,vsys1,PA-FW01,from-policy';
const PAN2=PAN.replace('10.10.20.15','10.10.20.16');
const CEF='CEF:0|Vendor|Product|1.0|100|Login|5|src=10.0.0.7 dst=10.0.0.8 spt=51234 dpt=443 act=allow';
const CEF2=CEF.replace('10.0.0.7','10.0.0.9');
const HOLDOUT=[CEF.replace('10.0.0.7','10.0.0.11').replace('Login','Logout'),
  CEF.replace('10.0.0.7','10.0.0.12').replace('act=allow','act=deny')].join('\n');
const FULL=[PAN,CEF,PAN2,CEF2].join('\n');
const FAMILY='structured_family_cef';

type Stage={op:string;[key:string]:unknown};
type Recipe={stages:Stage[];[key:string]:unknown};
type Verdict={accepted:true;draft:ParserDraft}|{accepted:false;stage:string;reason:string};

let routed:ParserDraft,fullSuite:SuiteResult,scopedSource:string,scoped:ParserDraft,scopedSuite:SuiteResult,baseline:Recipe;
beforeAll(async()=>{
  routed=buildAutomaticGenericStructuralDraft(FULL,createDraft())!.draft;
  fullSuite=preview(FULL,routed);
  const scope=familyScopes(routed,fullSuite)!.find(item=>item.name===FAMILY)!;
  scopedSource=familySource(FULL,scope);
  scoped=projectFamilyDraft(routed,FAMILY)!;
  scopedSuite=preview(scopedSource,scoped);
  const reviewed=await buildReviewableRecipe(scopedSource,scoped,scopedSuite);
  if(!reviewed.ok)throw new Error('no baseline recipe');
  baseline=reviewed.recipe as unknown as Recipe;
});

/** The ChatGPT Assisted checks, in screen order, for one reply to the prompt of FAMILY. */
async function check(reply:string,family=FAMILY):Promise<Verdict>{
  const extracted=extractRecipeJson(reply);
  if(!extracted)return {accepted:false,stage:'extract',reason:'NON_JSON_RESPONSE'};
  let imported:AIImportResult=await importReviewOnlyAIRecipe(extracted.text,scopedSource,scoped,scopedSuite);
  if(!imported.ok&&imported.reason==='CURRENT_RECIPE_UNAVAILABLE')
    imported=await importRecoveryAIRecipe(extracted.text,scopedSource,scoped,scopedSuite);
  if(!imported.ok)return {accepted:false,stage:'import',reason:imported.reason};
  let proposal;let scope:{oldTarget:string;newTarget:string}|undefined;
  if(imported.report.mode==='FULL_RECOVERY')proposal=proposeV01RecoveryParserFromAI(imported,scoped);
  else{
    proposal=proposeV01FieldMappingFromAI(imported,scopedSource,scoped,scopedSuite);
    if(!proposal.ok){
      const correction=proposeV01MappingCorrectionFromAI(imported,scopedSource,scoped,scopedSuite);
      if(correction.ok){
        proposal=correction;
        scope={oldTarget:normalizedMappingOutputPath(scoped,correction.mappingId),
          newTarget:normalizedMappingOutputPath(correction.candidate,correction.mappingId)};
      }else proposal=proposeV01EnrichmentFromAI(imported,scopedSource,scoped,scopedSuite);
    }
  }
  if(!proposal.ok)return {accepted:false,stage:'proposal',reason:proposal.reason};
  const input={source:scopedSource,baseline:scopedSuite,candidate:preview(scopedSource,proposal.candidate),
    holdout:{source:HOLDOUT,baseline:preview(HOLDOUT,scoped),candidate:preview(HOLDOUT,proposal.candidate)}};
  const compared=scope?compareMappingCorrectionCandidate(input,scope):compareCandidate(input);
  if(!compared.acceptedWithoutRegression){
    const b=compared.baseline;
    return {accepted:false,stage:'compare',reason:b.fieldRemovals?'FIELD_REMOVED':b.typeChanges?'TYPE_CHANGED':
      b.regressions?'REGRESSION':compared.holdout&&!compared.holdout.regressions?'HOLDOUT':'HOLDOUT_REGRESSION'};
  }
  const merged=mergeFamilyCandidate(routed,family,proposal.candidate,fullSuite);
  if(!merged.ok)return {accepted:false,stage:'merge',reason:merged.reason};
  if(!toBackendProject(merged.draft).ok)return {accepted:false,stage:'backend',reason:'BACKEND_UNSUPPORTED'};
  return {accepted:true,draft:merged.draft};
}
const edit=(change:(recipe:Recipe)=>void)=>{
  const recipe=JSON.parse(JSON.stringify(baseline)) as Recipe;change(recipe);return JSON.stringify(recipe);
};
const mapOf=(recipe:Recipe,source:string)=>recipe.stages.find(stage=>stage.op==='map_field'&&stage.source===source)!;
const official=(draft:ParserDraft,source:string)=>preview(source,draft).events.map(event=>event.normalized);

describe('wrong ChatGPT replies for one event type are blocked before anything changes',()=>{
  it('a correct one-field correction passes every check and changes only that event type',async()=>{
    const verdict=await check(edit(recipe=>{const act=mapOf(recipe,'body.act');act.target='action';act.group='top_fields';}));
    expect(verdict.accepted,JSON.stringify(verdict)).toBe(true);
    if(!verdict.accepted)return;
    const before=official(routed,FULL),after=official(verdict.draft,FULL);
    expect(after[0]).toEqual(before[0]);expect(after[2]).toEqual(before[2]);
    expect((after[1] as Record<string,unknown>).action).toBe('allow');
  });
  const wrong:[string,()=>string,string[]][]=[
    ['a missing field (an existing mapping removed)',()=>edit(recipe=>{
      recipe.stages=recipe.stages.filter(stage=>!(stage.op==='map_field'&&stage.source==='body.dst'));
      recipe.stages=recipe.stages.filter(stage=>!(stage.op==='cast_type'&&stage.target==='dstip'));}),
      ['proposal:NO_SINGLE_SAFE_MAPPING','proposal:UNSUPPORTED_OPERATOR_CHANGE','proposal:NO_SINGLE_MAPPING_CHANGE','proposal:NO_SINGLE_ENRICHMENT_CHANGE']],
    ['a changed value (source IP read from the destination)',()=>edit(recipe=>{mapOf(recipe,'body.src').source='body.dst';}),
      ['proposal:NO_SINGLE_SAFE_MAPPING','proposal:UNSUPPORTED_OPERATOR_CHANGE','proposal:NO_SINGLE_MAPPING_CHANGE','proposal:NO_SINGLE_ENRICHMENT_CHANGE','compare:REGRESSION','compare:TYPE_CHANGED']],
    ['a false verification claim',()=>edit(recipe=>{recipe.nativeVerified=true;recipe.targetVerified=true;}),
      ['import:UNTRUSTED_RECIPE','import:INVALID_JSON']],
    ['a field that does not exist',()=>edit(recipe=>{recipe.stages.splice(recipe.stages.findIndex(stage=>stage.op==='classify'),0,
      {op:'map_field',source:'body.suser',target:'srcuser',data_type:'string',group:'top_fields'});}),
      // The additive check reports SOURCE_NOT_PRESENT; the screen shows the reason of the last check tried.
      ['proposal:SOURCE_NOT_PRESENT','proposal:UNSUPPORTED_OPERATOR_CHANGE']],
    ['a field of another event type (PAN-OS path in the CEF type)',()=>edit(recipe=>{recipe.stages.splice(recipe.stages.findIndex(stage=>stage.op==='classify'),0,
      {op:'map_field',source:'generic.fields.app',target:'appid_name',data_type:'string',group:'top_fields'});}),
      // The additive check reports SOURCE_NOT_PRESENT; the screen shows the reason of the last check tried.
      ['proposal:SOURCE_NOT_PRESENT','proposal:UNSUPPORTED_OPERATOR_CHANGE']],
    ['a reply that changes how every event type is read',()=>edit(recipe=>{recipe.sourceFormat='kv';recipe.bodyFormat='kv';
      const at=recipe.stages.findIndex(stage=>stage.op==='parse_generic_structural');
      recipe.stages[at]={op:'parse_kv',pairDelimiter:' ',kvDelimiter:'='};}),
      ['import:UNTRUSTED_RECIPE','import:INVALID_JSON','proposal:UNSUPPORTED_OPERATOR_CHANGE','proposal:UNSUPPORTED_RECIPE','merge:SOURCE_FORMAT_CHANGED']],
    ['an unbounded Regex',()=>edit(recipe=>{recipe.sourceFormat='regex';recipe.bodyFormat='regex';
      const at=recipe.stages.findIndex(stage=>stage.op==='parse_generic_structural');
      recipe.stages[at]={op:'parse_regex',pattern:'^(?<msg>(a+)+)$'};}),
      ['import:UNTRUSTED_RECIPE','import:INVALID_JSON','proposal:UNSUPPORTED_OPERATOR_CHANGE','proposal:UNSUPPORTED_RECIPE']],
    ['a Recipe contract violation',()=>edit(recipe=>{recipe.contract='parser-studio.recipe.v0.3';}),
      ['import:UNTRUSTED_RECIPE','import:INVALID_JSON']],
    ['prose instead of a recipe',()=>'Sure! Here is how I would parse these logs: split on spaces and map src to srcip.',
      ['extract:NON_JSON_RESPONSE']],
  ];
  for(const [name,reply,expected] of wrong)
    it('blocks '+name,async()=>{
      const verdict=await check(reply());
      expect(verdict.accepted).toBe(false);
      if(verdict.accepted)return;
      expect(expected,JSON.stringify(verdict)).toContain(verdict.stage+':'+verdict.reason);
    });
  it('blocks a correct CEF result applied to the wrong event type',async()=>{
    const verdict=await check(edit(recipe=>{const act=mapOf(recipe,'body.act');act.target='action';act.group='top_fields';}),
      'panos_traffic_csv');
    expect(verdict).toEqual({accepted:false,stage:'merge',reason:'SOURCE_NOT_IN_FAMILY'});
  });
});

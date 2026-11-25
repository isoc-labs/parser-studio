import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {buildEventCoverageEvidence} from './chatGptEventCoverage';

// What the ChatGPT Assisted parsing prompt says about the automatic attempt: per original record the verdict of
// the local preview, which keys were not read, and the criteria a returned recipe is judged by. SYNTHETIC lines.
const GOOD='srcip=10.0.0.1 dstip=10.0.0.2 action=allow';
const LOST='srcip=10.0.0.3 dstip=10.0.0.4 msg="unterminated action=deny';
const FREE='kernel panic - not syncing: fatal exception';

function evidence(lines:string[]){
  const source=lines.join('\n');
  const draft={...createDraft(),format:'kv' as const,
    mappings:[{id:'m1',authoring:{version:1 as const,origin:'AUTO' as const},source:'srcip',target:'srcip',type:'ip' as const}]};
  return buildEventCoverageEvidence(source,draft,preview(source,draft)).text;
}
const block=(text:string)=>{
  const lines=text.split('\n');
  const at=lines.findIndex(line=>line.startsWith('Automatic parse result per original record'));
  expect(at).toBeGreaterThanOrEqual(0);
  return JSON.parse(lines[at+1]!) as {events:Array<{record:number;verdict:string;format:string;
    extractedFields:number;notRead?:string[];issues:string[]}>;verdicts:Record<string,number>};
};

describe('the parsing prompt states the automatic result of every record',()=>{
  it('names the verdict of each record, in order',()=>{
    const result=block(evidence([GOOD,LOST,FREE]));
    expect(result.events.map(event=>event.record)).toEqual([1,2,3]);
    expect(result.events[0]!.verdict).toBe('FULL');
    expect(result.events[1]!.verdict).not.toBe('FULL');
    expect(result.events[2]!.verdict).not.toBe('FULL');
    expect(result.verdicts.FULL).toBe(1);
    expect(result.events[0]!.extractedFields).toBe(3);
  });
  it('carries no field value of the log, only names and codes',()=>{
    const text=evidence([GOOD,LOST,FREE]);
    const result=JSON.stringify(block(text));
    for(const value of ['10.0.0.1','10.0.0.3','allow','deny','unterminated','kernel panic'])
      expect(result).not.toContain(value);
  });
  it('states the criteria a returned recipe is judged by',()=>{
    const text=evidence([GOOD,LOST]);
    expect(text).toContain('Parsing success criteria');
    expect(text).toContain('exactly one event per original record');
    expect(text).toContain('parser_raw_msg');
    expect(text).toContain('never FULL');
  });
});

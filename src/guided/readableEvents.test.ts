/**
 * Events that cannot be parsed do not stop the creation of a parser for the events that can (Phase 3, P2,
 * owner decision of 2026-11-22). The sample is split on the verdict of each event; the events that are left
 * out are named with their kind and their number.
 */
import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {analyzeLogEnvelopes} from './autoParserEnvelope';
import {describeExcluded,readableEvents} from './readableEvents';

const KV=(n:number)=>'<134>Nov 21 10:00:0'+n+' fw1 traffic: srcip=10.0.0.'+n+' dstip=10.0.1.'+n+' srcport=5123'+n+' dstport=443 proto=6 action=accept';
const UNCLOSED='<134>Nov 21 10:00:04 fw1 traffic: srcip=10.0.0.9 dstip=10.0.0.10 msg="unterminated action=accept';
const FREE='kernel panic - not syncing: fatal exception in interrupt';
const LOST_PAIR='<134>Nov 21 10:00:06 fw1 url=/login?user=bob,src=10.0.0.1,dst=10.0.0.2';
const JSON1='{"ts":"2026-11-21T10:00:01Z","src_ip":"10.0.0.5","dest_ip":"10.0.0.9","action":"allow"}';
// SYNTHETIC, PAN-OS SYSTEM field order without a Syslog PRI.
const PAN_SYSTEM='Oct 15 00:05:00 PA-FW01 1,2026/10/15 00:05:00,012345678901,SYSTEM,general,0,2026/10/15 00:05:00,,general,,0,0,general,informational,"User admin logged in",12345,0x0,0,0,0,0,,PA-FW01';

function split(lines:readonly string[]){
  const sample=lines.join('\n');
  const suite=preview(sample,{...createDraft(),format:'auto'});
  return readableEvents(sample,suite,analyzeLogEnvelopes(sample,'single-line').events);
}

describe('the readable events of a sample',()=>{
  it('are the events read completely, in their order, beside a count of the others by kind',()=>{
    const found=split([KV(1),UNCLOSED,KV(2),FREE,KV(3)]);
    expect(found).not.toBeNull();
    expect(found!.source).toBe([KV(1),KV(2),KV(3)].join('\n'));
    expect([found!.count,found!.total]).toEqual([3,5]);
    expect(found!.excluded).toEqual([
      {kind:'RFC 3164 Syslog with a key=value body that could not be read',count:1,events:[2]},
      {kind:'unrecognized format',count:1,events:[4]},
    ]);
    expect(describeExcluded(found!.excluded))
      .toBe('1 × RFC 3164 Syslog with a key=value body that could not be read, 1 × unrecognized format');
  });

  it('do not include an event that was only partly read',()=>{
    const found=split([KV(1),LOST_PAIR,KV(2)]);
    expect(found!.source).toBe([KV(1),KV(2)].join('\n'));
    expect(found!.excluded).toEqual([{kind:'partly read: some values were not extracted',count:1,events:[2]}]);
  });

  it('name a delimited record that has no column names',()=>{
    const found=split([KV(1),PAN_SYSTEM,PAN_SYSTEM.replace('00:05:00','00:05:01'),JSON1]);
    expect(found!.source).toBe([KV(1),JSON1].join('\n'));
    expect(found!.excluded).toEqual([{kind:'delimited record without column names',count:2,events:[2,3]}]);
  });

  it('are the same events whatever the order of the sample',()=>{
    const lines=[KV(1),UNCLOSED,JSON1,FREE];
    const kept=(order:readonly string[])=>split(order)!.source.split('\n').sort();
    expect(kept([...lines].reverse())).toEqual(kept(lines));
    expect(split([...lines].reverse())!.excluded.map(group=>[group.kind,group.count]).sort())
      .toEqual(split(lines)!.excluded.map(group=>[group.kind,group.count]).sort());
  });

  it('is nothing to split when every event is readable, or none is',()=>{
    expect(split([KV(1),KV(2),JSON1])).toBeNull();
    expect(split([FREE,UNCLOSED])).toBeNull();
    expect(split([KV(1)])).toBeNull();
  });

  it('is not offered when the suite does not describe the sample line by line',()=>{
    const sample=[KV(1),FREE].join('\n');
    const suite=preview(KV(1),{...createDraft(),format:'auto'});
    expect(readableEvents(sample,suite,analyzeLogEnvelopes(sample,'single-line').events)).toBeNull();
    expect(readableEvents(sample,null,[])).toBeNull();
  });
});

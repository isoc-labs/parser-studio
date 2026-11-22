/**
 * The events of a sample that the Auto Parser read completely, and the events it did not (Phase 3, P2; owner
 * decision of 2026-11-22: events that cannot be parsed do not stop the creation of a parser for those that can).
 *
 * Every event has its own verdict. A parser is created for the events whose verdict is FULL; the others are
 * named with their kind and their number and never shown as parsed. At run time the generated parser marks
 * such an event as not parsed (parser_err_msg, backend/templates/canonical-operators.rb.tpl) and copies neither
 * fields nor raw text; the receiver is expected to report it as an unparsed raw log (source reading of the
 * patched Fluentd inputs, not verified on a Stellar Cyber system).
 */
import type {SuiteResult} from '../model';
import {splitEvents,MAX_EVENTS} from '../parser';

export interface ExcludedEvents{
  /** Why the events are not covered, in the words shown to the user. */
  kind:string;
  count:number;
  /** One-based numbers of the events in the original sample. */
  events:number[];
}
export interface ReadableEvents{
  /** The readable events, one per line, in their original order. */
  source:string;
  count:number;
  total:number;
  excluded:ExcludedEvents[];
}
interface ScannedEvent{envelope:string;body:string;status:string}

const ENVELOPE_NAMES:Readonly<Record<string,string>>={rfc3164:'RFC 3164 Syslog',rfc5424:'RFC 5424 Syslog'};
const BODY_NAMES:Readonly<Record<string,string>>={kv:'key=value',json:'JSON',cef:'CEF',leef:'LEEF',csv:'delimited'};

/** The kind of an event that was not read completely: what the first scan and the native verdict say. */
function excludedKind(scan:ScannedEvent|undefined,verdict:string):string{
  if(verdict==='PARTIAL')return 'partly read: some values were not extracted';
  if(!scan)return 'unrecognized format';
  const envelope=ENVELOPE_NAMES[scan.envelope];
  if(scan.status==='HEADER_MALFORMED')return (envelope??'Syslog')+' header that could not be read';
  if(scan.envelope==='none'&&scan.body==='csv')return 'delimited record without column names';
  const body=BODY_NAMES[scan.body];
  if(scan.status==='BODY_MALFORMED'&&body)return (envelope?envelope+' with a ':'')+body+' body that could not be read';
  if(scan.body==='unknown'||!body)return 'unrecognized format';
  return (envelope?envelope+' with a ':'')+body+' body that was not read completely';
}

/**
 * Splits a single-line sample into the events read completely (FULL) and the others. Returns null when there
 * is nothing to split: no event or every event is readable, no event is readable (the sample needs another
 * route, for example ChatGPT Assisted), or the suite does not describe the sample line by line.
 */
export function readableEvents(sample:string,suite:Pick<SuiteResult,'events'>|null|undefined,
  scan:readonly ScannedEvent[]):ReadableEvents|null{
  if(!suite)return null;
  const records=splitEvents(sample,'single-line',MAX_EVENTS+1);
  if(records.length<2||records.length>MAX_EVENTS||records.length!==suite.events.length)return null;
  const kept:string[]=[];
  const excluded=new Map<string,ExcludedEvents>();
  records.forEach((record,index)=>{
    const verdict=String(suite.events[index]!.parseStatus);
    if(verdict==='FULL'){kept.push(record.raw);return;}
    const kind=excludedKind(scan[index],verdict);
    const group=excluded.get(kind)??{kind,count:0,events:[]};
    group.count+=1;group.events.push(index+1);
    excluded.set(kind,group);
  });
  if(kept.length===0||kept.length===records.length)return null;
  return {source:kept.join('\n'),count:kept.length,total:records.length,excluded:[...excluded.values()]};
}

/** "1 × unrecognized format, 2 × delimited record without column names" */
export function describeExcluded(excluded:readonly ExcludedEvents[]):string{
  return excluded.map(group=>group.count+' × '+group.kind).join(', ');
}

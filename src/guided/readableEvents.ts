/**
 * The events of a sample that the Auto Parser read completely, and the events it did not (Phase 3, P2; owner
 * decision of 2026-11-22: events that cannot be parsed do not stop the creation of a parser for those that can).
 *
 * Every event has its own verdict. A parser is created for the events whose verdict is FULL; the others are
 * named with their kind and their number and never shown as parsed. At run time the generated parser marks
 * such an event as not parsed (parser_err_msg, backend/templates/canonical-operators.rb.tpl) and keeps its
 * complete original text in parser_raw_msg, the Stellar Cyber 7.0 dictionary field for the raw message of a
 * parsing error (owner decision of 2026-11-22), when it returns an error record. Target delivery or retention
 * is not verified.
 *
 * The split uses the verdicts the Auto Parser goes on with. With the automatic draft these are the server analysis
 * (every event SOURCE_PARSED) and the first scan (every event RECOGNIZED); the browser preview alone is not enough.
 * An event one of them refuses is not readable, so the sample of readable events can always go on (2026-11-25).
 */
import type {ParserDraft,SuiteResult} from '../model';
import {buildSourceReviewedBoundedDraft,headerlessCsvEvents,nativelyReadEvents,type GenericStructuralSourceReview} from './genericStructuralAutoDraft';
import {originalContainerCompilerGate} from './sourceContainerCompilerGate';
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
  /** A jointly validated bounded extraction candidate, not a scanner guess. */
  candidate?:ParserDraft;
}
interface ScannedEvent{envelope:string;body:string;status:string}

const ENVELOPE_NAMES:Readonly<Record<string,string>>={rfc3164:'RFC 3164 Syslog',rfc5424:'RFC 5424 Syslog'};
const BODY_NAMES:Readonly<Record<string,string>>={kv:'key=value',json:'JSON',cef:'CEF',leef:'LEEF',csv:'delimited'};

/** The kind of an event that was not read completely: what the first scan and the native verdict say. */
function excludedKind(scan:ScannedEvent|undefined,verdict:string):string{
  if(verdict==='PARTIAL')return 'partly read: some values were not extracted';
  if(!scan)return 'unrecognized format';
  const envelope=ENVELOPE_NAMES[scan.envelope];
  // The envelope of a header that could not be read is not established (an RFC 5424 line with VERSION 2 is scanned
  // as a damaged RFC 3164 header), so no envelope is named.
  if(scan.status==='HEADER_MALFORMED')return 'Syslog header that could not be read';
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
  scan:readonly ScannedEvent[],sourceParsed?:readonly boolean[],
  boundedAccepted?:readonly boolean[]):ReadableEvents|null{
  if(!suite)return null;
  const records=splitEvents(sample,'single-line',MAX_EVENTS+1);
  if(records.length<2||records.length>MAX_EVENTS||records.length!==suite.events.length)return null;
  // sourceParsed: the verdict of the server analysis for each event, given with the automatic draft.
  if(sourceParsed&&sourceParsed.length!==records.length)return null;
  if(boundedAccepted&&boundedAccepted.length!==records.length)return null;
  if(records.some((record,i)=>suite.events[i]?.raw!==record.raw||suite.events[i]?.line!==record.line))return null;
  const kept:string[]=[];
  const excluded=new Map<string,ExcludedEvents>();
  records.forEach((record,index)=>{
    const verdict=String(suite.events[index]!.parseStatus);
    const accepted=!sourceParsed||(sourceParsed[index]===true&&scan[index]?.status==='RECOGNIZED');
    if((verdict==='FULL'&&accepted)||boundedAccepted?.[index]===true){kept.push(record.raw);return;}
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

/** Recover structured bounded candidates when the initial scanner is incomplete.
 * The exact source frames and the same adoption contract used by the ordinary
 * Auto Parser are required. A whole-message capture is not a new readable
 * structured event. Every retained event must pass one common candidate.
 */
export function readableEventsWithBoundedCandidate(sample:string,draft:ParserDraft,
  suite:SuiteResult|undefined,scan:readonly ScannedEvent[],review:GenericStructuralSourceReview):ReadableEvents|null{
  const parsed=review.events.map(event=>event.preview.status==='SOURCE_PARSED');
  const ordinary=readableEvents(sample,suite,scan,parsed);
  const records=splitEvents(sample,'single-line',MAX_EVENTS+1);
  if(!suite||draft.format!=='auto'||review.raw!==sample||review.metadataLines||
     review.transportFramingParts||originalContainerCompilerGate(sample,review)||
     records.length<2||records.length>MAX_EVENTS||records.length!==review.events.length||
     records.length!==scan.length||records.length!==suite.events.length)return ordinary;
  const encoder=new TextEncoder(),decoder=new TextDecoder('utf-8',{fatal:true});
  const bytes=encoder.encode(sample);
  if(bytes.length>65536)return ordinary;
  let end=0;
  for(const [i,event] of review.events.entries()){
    if(!Number.isInteger(event.startByte)||!Number.isInteger(event.endByte)||
       event.startByte<end||event.endByte<=event.startByte||event.endByte>bytes.length||
       suite.events[i]?.raw!==records[i]!.raw||suite.events[i]?.line!==records[i]!.line)return ordinary;
    try{if(decoder.decode(bytes.slice(event.startByte,event.endByte))!==records[i]!.raw)return ordinary;}
    catch{return ordinary;}
    end=event.endByte;
  }
  const standard=records.map((_,i)=>parsed[i]===true&&scan[i]?.status==='RECOGNIZED'&&suite.events[i]?.parseStatus==='FULL');
  const csv=headerlessCsvEvents(scan),native=nativelyReadEvents(scan);
  const build=(indices:readonly number[])=>{
    let offset=0;
    const source=indices.map(i=>records[i]!.raw).join('\n');
    const events=indices.map(i=>{
      const startByte=offset,endByte=startByte+encoder.encode(records[i]!.raw).length;
      offset=endByte+1;
      return {startByte,endByte,preview:review.events[i]!.preview};
    });
    return buildSourceReviewedBoundedDraft(source,draft,{raw:source,events},
      indices.map(i=>csv[i]!),indices.map(i=>native[i]!));
  };
  const extra=records.map((_,i)=>{
    if(standard[i]||!parsed[i])return false;
    const candidate=build([i]);
    const fields=candidate?.suite.events[0]?.fields;
    if(!fields)return false;
    const generic=fields.generic as {mode?:string}|undefined;
    // Do not upgrade free text merely because a generic message was retained.
    return !['bsd_tagged_message','bsd_bracket_pid_message','bsd_classic_pid_message'].includes(generic?.mode??'');
  });
  if(!extra.some(Boolean))return ordinary;
  const indices=records.flatMap((_,i)=>standard[i]||extra[i]?[i]:[]);
  if(indices.length===records.length)return ordinary; // the full-source adoption path is separate
  const candidate=build(indices);
  if(!candidate)return ordinary; // never offer incompatible independent candidates as one parser
  const subset=readableEvents(sample,suite,scan,parsed,extra);
  return subset?{...subset,candidate:candidate.draft}:ordinary;
}

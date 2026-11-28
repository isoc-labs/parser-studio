import type {MappingRule,MappingWhen,SuiteResult} from '../model';
import {listSafeLeafPaths,lookupFieldValue} from '../fieldPaths';
import {convertValue} from '../parser';
import {canonicalIgnoreSourceValue} from '../../backend/src/canonical-operator-contract';
import {meetsStellar7ValueConstraints} from '../stellar7ValueConstraints';
import semanticPolicy from '../../runtime/multipass/semantic-policy.v1.json';
import {explicitPortSourceAlias} from './sourcePortPolicy';
export {sourceHasExcludedPortSegment,explicitPortSourceAlias} from './sourcePortPolicy';
import type {FieldGroup} from './contract';
import {findStellarMetadataField} from './stellarMetadataCatalog';

export interface NormalizationCandidate {
  source:string;
  target:string;
  type:MappingRule['type'];
  group:FieldGroup;
  confidence:'HIGH'|'REVIEW';
  method:'EXACT_DICTIONARY_NAME'|'DOCUMENTED_ALIAS';
  explanation:string;
  catalogVerified:true;
  catalogRelease:'7.0.xs';
  observed:number;
  compatibleObserved:number;
  total:number;
  replacesMappingId?:string;
  currentTarget?:string;
  safeForBulk:boolean;
  when?:MappingWhen;
  eligibleObserved:number;
  skippedForSemantics:number;
}

const ALIASES:Readonly<Record<string,string>>=semanticPolicy.normalizationAliases;
/** Default deny. The only official fields a name can be proposed for are those the shared policy lists, each
 * with its dictionary definition and the reason a name can carry that meaning. A matching name, alias, type or
 * range is not such a reason: any other field keeps its own name and value, and reviewed ChatGPT mapping and
 * manual mapping remain. */
const AUTO_APPROVED_TARGETS=new Set<string>(Object.keys(semanticPolicy.autoApprovedTargets));
const WHITESPACE_FREE_TARGETS=new Set(['srcport','dstport','srcip','dstip']);
/** Official fields a sparse source may be approved for when the source is named exactly like the field. */
const SPARSE_SAFE_TARGETS=new Set(['srcip','dstip','srcport','dstport','proto','proto_name','url']);
/** A name is evidence only where it stands for the record itself: at the root, or in the container the READER
 * of the event writes the pairs of the record into. A root-level name that has a target is always a whole path
 * the dictionary or the alias table lists (candidateForSource), so only the containers are decided here. Which
 * containers those are follows from the reading (the
 * effective format of the events that carry the source), never from the text of the path: in a JSON log
 * `fields.srcip`, `body.srcip` or `xlate.srcip` is an object of the log and names another endpoint. The table
 * lists what the readers of this product build: the key=value, column and vendor nodes and the Syslog header of
 * Generic Structural, the body of a Syslog record, and the SD-PARAMs of an RFC 5424 structured-data element. A
 * container that is missing here costs a proposal; it never causes one. */
const RECORD_CONTAINERS:Readonly<Record<string,RegExp>>={
  generic_structural:/^(?:generic\.(?:kv|fields)|watchguard(?:\.kv)?|junos_sd|juniper|asa|syslog|body(?:\.leef_extension)?)\.[^.]+$/u,
  syslog_rfc3164:/^body\.[^.]+$/u,
  syslog_rfc5424:/^(?:body|syslog_sd\.[^.]+\.params)\.[^.]+$/u,
};
function recordLevelSource(source:string,formats:readonly (string|undefined)[]):boolean{
  return formats.length>0&&formats.every(format=>RECORD_CONTAINERS[format??'']?.test(source)===true);
}
// A normalized event keeps the source record under this name; its paths are the source paths one level down.
const SOURCE_COPY='parserstudio_source.';
/** The path a source is judged by: an atom is a slice of the key=value pair beside it. */
function recordPathOf(source:string):string{
  const local=source.startsWith(SOURCE_COPY)?source.slice(SOURCE_COPY.length):source;
  const atom=/^((?:.+\.)?)atoms\.([A-Za-z0-9_]+)_001$/u.exec(local);
  return atom?atom[1]+'kv.'+atom[2]:local;
}
const URL_SHAPED=/^(?:[a-z][a-z0-9+.-]*:\/\/\S+|\/\S*)$/iu;
/** Extension keys whose meaning the format specification defines: the ArcSight CEF Implementation Standard
 * (src sourceAddress, dst destinationAddress, spt sourcePort, dpt destinationPort, proto transportProtocol,
 * request requestUrl) and the IBM QRadar LEEF predefined attributes (src, dst, srcPort, dstPort, proto, url).
 * In the extension of a CEF or LEEF record such a key has no reading other than its official field, like a
 * source named as the field itself, so the sparse rule treats both alike (golden r2_trendmicro_cef: a Deep
 * Security Agent packet record carries dst, spt and dpt, the Manager record of the same sample does not).
 * A record is CEF or LEEF when the CEF or LEEF grammar read it (cefLeefReading) and the container of the key
 * holds the version that grammar writes for its header (cef_version, leef_version). A JSON or key=value body is
 * neither, whatever its keys are called: an author-written cef_version must not switch on CEF meanings
 * (independent audit 2026-11-23, F2). A documented positional layout defines its positions the same way: the WatchGuard Traffic
 * Monitor layout (Generic Structural mode watchguard_traffic_monitor) has a source and a destination port
 * position that an ICMP message leaves out (golden r2_watchguard_traffic). */
const SPEC_DEFINED_EXTENSION_KEYS:readonly {version?:string;reading?:string;mode?:string;container?:string;
  keys:Readonly<Record<string,readonly string[]>>}[]=[
  {version:'cef_version',reading:'cef',keys:{src:['srcip'],dst:['dstip'],spt:['srcport'],dpt:['dstport'],
    proto:['proto','proto_name'],request:['url']}},
  {version:'leef_version',reading:'leef',keys:{src:['srcip'],dst:['dstip'],srcPort:['srcport'],dstPort:['dstport'],
    proto:['proto','proto_name'],url:['url']}},
  {mode:'watchguard_traffic_monitor',container:'watchguard',keys:{src_ip:['srcip'],dst_ip:['dstip'],
    src_port:['srcport'],dst_port:['dstport']}},
];
function readingMode(fields:Record<string,unknown>):unknown{
  const mode=lookupFieldValue(fields,'generic.mode');
  return mode.found?mode.value:undefined;
}
/** Which of the CEF and LEEF grammars read an event, if one did: its format, the family the mixed router chose, or
 * the body the Syslog or Generic Structural reader reports (bodyKind). */
const CEF_LEEF_BODY_READERS=new Set(['syslog_rfc3164','syslog_rfc5424','generic_structural']);
function cefLeefReading(event:SuiteResult['events'][number]):string|undefined{
  const format=event.effectiveFormat;
  const kind=format==='mixed'?/(?:^|_)(cef|leef)$/u.exec(event.readingFamily??'')?.[1]:
    format==='cef'||format==='leef'?format:CEF_LEEF_BODY_READERS.has(format??'')?event.bodyKind:undefined;
  return kind==='cef'||kind==='leef'?kind:undefined;
}
/** The official fields a CEF/LEEF specification assigns to the source in every event that carries it. */
function specDefinedTargets(source:string,events:readonly Record<string,unknown>[],
  readings:readonly (string|undefined)[]):readonly string[]{
  const at=source.lastIndexOf('.');
  const container=at<0?'':source.slice(0,at),key=source.slice(at+1);
  let targets:readonly string[]=[];
  for(const [index,fields] of events.entries()){
    if(!lookupFieldValue(fields,source).found)continue;
    const holder=container?objectAt(fields,container):fields;
    const spec=holder?SPEC_DEFINED_EXTENSION_KEYS.find(item=>item.mode!==undefined
      ?container===item.container&&readingMode(fields)===item.mode
      :readings[index]===item.reading&&Object.prototype.hasOwnProperty.call(holder,item.version!)):undefined;
    const named=spec&&Object.prototype.hasOwnProperty.call(spec.keys,key)?spec.keys[key]!:[];
    if(!named.length||(targets.length&&targets!==named))return [];
    targets=named;
  }
  return targets;
}
type Looked={found:true;value:unknown}|{found:false};
/** The other sparse-safe fields are checked by the type of the field; a URL has no such check. */
function sparseSafeValues(target:string,values:readonly Looked[]):boolean{
  return target!=='url'||values.every(result=>result.found&&typeof result.value==='string'&&
    URL_SHAPED.test(result.value.trim()));
}
/** Field names under which a record states its IP protocol. `transport` is not one of them: FortiGate writes
 * the translated source port under that name. */
const PROTOCOL_EVIDENCE_NAMES=['protocol-id','protocol_id','protocol','proto','proto_name','protocol_name',
  'ipproto','ip_proto','l4proto','ip_protocol','l4_proto','l4_protocol'];
/** Members of a protocol object that are not the protocol itself ({name:'tcp',flags:'SYN'}: audit G-13). */
const PROTOCOL_NON_IDENTITY_MEMBERS=new Set(['flags','tcp_flags','flag','state','direction']);
/** Aliases whose documented meaning depends on the protocol: Zeek writes the ICMP type and code in
 * id.orig_p and id.resp_p. They are ports only beside a TCP or UDP protocol. */
const PROTOCOL_DEPENDENT_PORT_ALIASES=new Set(['id.orig_p','id.resp_p']);
/** The source key behind a Generic Structural `atoms.<key>_001` first piece. */
function firstAtomKeyOf(source:string):string|undefined{
  return /^(?:.+\.)?atoms\.([A-Za-z0-9_]+)_001$/.exec(source)?.[1];
}

function overlaps(a:string,b:string):boolean{
  return a===b||a.startsWith(b+'.')||b.startsWith(a+'.');
}
/** A value the run time does not map and does not count as an error: absent, a blank-only string
 * (canonicalIgnoreSourceValue), or a placeholder. The review of a sample must agree with the run time. */
export function ignored(value:unknown):boolean{
  return canonicalIgnoreSourceValue(value,[])||['','N/A','-'].includes(String(value));
}

// Published 7.0 proto_name is a transport protocol, not a vendor application
// or service label. An unknown name is still reviewable, never auto-approved.
const DOCUMENTED_PROTO_NAMES=new Set(semanticPolicy.officialProtocolNames);
const TRANSPORT_NUMERIC=new Set<string>(
  semanticPolicy.transportPortProtocols.numeric.map(String));
const TRANSPORT_NAMES=new Set<string>(semanticPolicy.transportPortProtocols.names);
/** Where the protocol that qualifies `source` is recorded. An atom such as
 * `generic.atoms.dport_001` is a slice of `generic.kv.dport`, so the protocol
 * lives beside the KV carrier, not beside the atom. */
function protocolContextPrefixes(source:string):string[]{
  const prefix=source.includes('.')?source.slice(0,source.lastIndexOf('.')+1):'';
  if(firstAtomKeyOf(source)===undefined)return [prefix];
  return [prefix,source.slice(0,source.lastIndexOf('atoms.'))+'kv.'];
}
function objectAt(fields:Record<string,unknown>,path:string):Record<string,unknown>|null{
  if(!path)return fields;
  const found=lookupFieldValue(fields,path);
  return found.found&&found.value!==null&&typeof found.value==='object'&&!Array.isArray(found.value)
    ?found.value as Record<string,unknown>:null;
}
/** What the record says about its IP protocol beside `source`: the values of the protocol fields in the object
 * that holds the source (for an atom also in the key=value carrier beside it). Field names are compared without
 * regard to case, as the aliases are (`Protocol=ICMP` beside `SrcPort`). `withRoot` adds the root of the event;
 * a source whose path names no object (a literal dotted key such as Zeek's id.orig_p) is at the root, and a
 * literal key that is written with the same prefix ("flow.proto" beside "flow.sport") is its sibling. A protocol
 * field that holds an object or a list says what its scalar members say ({name:'icmp',number:1}); a null
 * member, like a null field, says nothing (independent audit 2026-11-21, F-03, F-04). */
function scalarLeaves(value:unknown,out:string[]):void{
  if(value!==null&&typeof value==='object'){
    for(const child of Object.values(value as Record<string,unknown>))scalarLeaves(child,out);
    return;
  }
  if(value!==null&&value!==undefined)out.push(String(value).trim().toLowerCase());
}
/** The object of the event that holds `source` - the deepest one its path leads to - and what the source is
 * written with inside that object up to its last dot ("flow." of the literal key "flow.sport", in the root of
 * the event or in the body of a Syslog reading alike: independent audit 2026-11-22, G-07). */
function holderOf(fields:Record<string,unknown>,source:string):{container:Record<string,unknown>;written:string}{
  let head=source;
  for(;;){
    head=head.slice(0,Math.max(0,head.lastIndexOf('.')));
    // The root of the event (an empty path) is always an object.
    const container=objectAt(fields,head);
    if(container){
      const key=source.slice(head?head.length+1:0);
      return {container,written:key.slice(0,key.lastIndexOf('.')+1).toLowerCase()};
    }
  }
}
function protocolValuesBeside(fields:Record<string,unknown>,source:string,withRoot:boolean):string[]{
  const holder=holderOf(fields,source);
  const containers=new Map<Record<string,unknown>,string>([[holder.container,holder.written]]);
  for(const prefix of protocolContextPrefixes(source).slice(1)){
    const container=objectAt(fields,prefix.slice(0,-1));
    if(container)containers.set(container,'');
  }
  // From the root of the event the source is written with everything up to its last dot.
  if(withRoot&&!containers.has(fields))containers.set(fields,source.slice(0,source.lastIndexOf('.')+1).toLowerCase());
  const values:string[]=[];
  for(const [container,written] of containers)for(const key of Object.keys(container)){
    const name=key.toLowerCase();
    const local=name.startsWith(written)?name.slice(written.length):name;
    protocolLeaves(container[key],local.split('.'),values);
  }
  return values;
}
/** The protocol values of one field, by the path of each scalar: a segment that names a protocol field
 * ("protocol", "flow.l4.proto", a literal key "protocol.name", ECS network.transport) makes the scalars at or
 * below it protocol evidence, except members that are not the protocol itself (flags). Audit G-13. */
function protocolLeaves(value:unknown,path:string[],out:string[]):void{
  if(value!==null&&typeof value==='object'&&!Array.isArray(value)){
    // Only a protocol object, or the ECS network object, is read: another object of the event is another
    // family of the record, whose protocol says nothing about this port.
    if(!path.some(segment=>PROTOCOL_EVIDENCE_NAMES.includes(segment))&&path[path.length-1]!=='network')return;
    for(const [key,child] of Object.entries(value as Record<string,unknown>))
      protocolLeaves(child,[...path,...key.toLowerCase().split('.')],out);
    return;
  }
  // ECS network.transport names the protocol; a bare transport field does not (FortiGate transport= is a port).
  // ECS network.protocol is the application protocol (http, dns, tls), not the IP protocol (re-audit A1).
  const at=path.findIndex((segment,i)=>(PROTOCOL_EVIDENCE_NAMES.includes(segment)&&
    !(segment==='protocol'&&i>0&&path[i-1]==='network'))||
    (segment==='transport'&&i>0&&path[i-1]==='network'));
  if(at<0)return;
  if(at<path.length-1&&PROTOCOL_NON_IDENTITY_MEMBERS.has(path[path.length-1]!))return;
  scalarLeaves(value,out);
}
const isTransport=(value:string):boolean=>TRANSPORT_NUMERIC.has(value)||TRANSPORT_NAMES.has(value);
/** A protocol observation is not proof of a Layer 4 port unless it names an
 * independently reviewed carrier. Unknown/contradicting evidence is REVIEW. */
function unsupportedPortProtocolInEvent(
  fields:Record<string,unknown>,source:string,
):boolean{
  return protocolValuesBeside(fields,source,true).some(value=>!isTransport(value));
}
/** The record itself says that its ports are TCP or UDP ports: in the object that holds the port, not at the
 * root of an event whose port lives in a nested family. */
function transportEvidenceInEvent(fields:Record<string,unknown>,source:string):boolean{
  return protocolValuesBeside(fields,source,false).some(isTransport);
}
/** Shared, versioned source-field contract. A declared port label has higher
 * identity evidence than abbreviated aliases (spt/sport etc). The field must
 * still pass Stellar's integer/range constraints and source ambiguity checks.
 * No vendor, product or sample-specific path is required.
 */
// A matching label is not enough: these vendor log fields have distinct
// meanings from Stellar's context-specific names or require unit conversion.
// Restrict the guard to records with FortiOS's recognizable field family so
// Windows/EDR payloads with independently supported semantics stay unaffected.
/** The containers around a source field as path prefixes, innermost first, the root ('') last.
 * One vendor record is read at the root by the KV and JSON formats and inside a container by others
 * (generic.kv.*, body.*, a Syslog-wrapped JSON body). What a record is does not depend on which reading produced
 * it, so the evidence that names the record is looked for in each container around the field - all of it in the
 * same container, never pieced together from different levels. Looking at the root only left the guards below
 * silent for the same record behind a PRI: a FortiGate web-filter line read by Generic Structural had its
 * requested web host mapped to Stellar hostname. */
function recordPrefixes(source:string):string[]{
  const prefixes:string[]=[];
  for(let end=source.lastIndexOf('.');end>0;end=source.lastIndexOf('.',end-1))prefixes.push(source.slice(0,end+1));
  prefixes.push('');
  return prefixes;
}
function fortiGateRecord(fields:Record<string,unknown>,source:string):boolean{
  return recordPrefixes(source).some(prefix=>
    lookupFieldValue(fields,prefix+'logid').found&&
    (lookupFieldValue(fields,prefix+'vd').found||lookupFieldValue(fields,prefix+'srcintf').found)&&
    lookupFieldValue(fields,prefix+'type').found);
}
const FORTINET_FALSE_FRIENDS=new Set([
  'type','eventtype','event_type','direction','duration','hostname',
]);
/** One rule for every consumer (automatic candidates and reviewed ChatGPT proposals): a FortiOS field whose name
 * equals a Stellar field of another meaning or unit. */
export function fortiGateFalseFriend(source:string,events:readonly Record<string,unknown>[]):boolean{
  const leaf=source.slice(source.lastIndexOf('.')+1).toLowerCase();
  return FORTINET_FALSE_FRIENDS.has(leaf)&&events.some(fields=>fortiGateRecord(fields,source));
}
// The official action field describes enforcement/response, not arbitrary
// event verbs such as a VPN negotiation, session close or admin login.
const SECURITY_DISPOSITIONS=new Set(semanticPolicy.securityDispositions);
function incompatibleVendorMeaning(
  source:string,target:string,events:Record<string,unknown>[],
):boolean{
  const leaf=(source.split('.').at(-1)??source).toLowerCase();
  if(target==='action'&&events.some(fields=>{
    const result=lookupFieldValue(fields,source);
    return result.found&&!ignored(result.value)&&
      !SECURITY_DISPOSITIONS.has(String(result.value).trim().toLowerCase());
  }))return true;
  // CEF names spt the source port. Imperva Cloud WAF (Incapsula) writes the client port as cpt and uses spt for the
  // SERVER port (its log file structure reference), with src still the client address: spt mapped to srcport would
  // pair the client address with the server port. A record that carries cpt beside spt follows that usage.
  return target==='srcport'&&leaf==='spt'&&events.some(fields=>
    lookupFieldValue(fields,source).found&&
    lookupFieldValue(fields,source.slice(0,source.lastIndexOf('.')+1)+'cpt').found);
}
export function valueFitsMappingType(type:MappingRule['type'],value:unknown):boolean{
  if(ignored(value))return true;
  // Candidate confidence and whole-sample validation must use the same type
  // semantics as the actual browser/runtime normalization path. This keeps
  // IPv6 and explicit-timezone timestamps from diverging.
  return convertValue(value,type).error===undefined;
}
export function valueFitsNormalizationTarget(
  target:string,type:MappingRule['type'],value:unknown,
):boolean{
  if(ignored(value))return true;
  const converted=convertValue(value,type);
  return converted.error===undefined&&
    meetsStellar7ValueConstraints(target,value,converted.value);
}
// `sport` abbreviates "source port" beside `dport`, and "server port" in records that name their endpoints client
// and server (`cip sip cport sport`; W3C does the same with c-ip, s-ip and s-port). The name alone does not say
// which one it is, and no list of client-side names is complete (client_ip_address, client_hostname, remote/local:
// final audit F-1). So the record itself has to show the source/destination pair: `sport` is approved as the
// official source port only when the same record has a destination port; otherwise it is offered for review.
const plainName=(name:string)=>name.toLowerCase().replace(/[-_]/gu,'');
function serverPortReading(source:string,target:string,events:readonly Record<string,unknown>[]):boolean{
  if(target!=='srcport'||plainName(source.slice(source.lastIndexOf('.')+1))!=='sport')return false;
  return events.some(fields=>{
    if(!lookupFieldValue(fields,source).found)return false;
    // The names beside it, each by its last segment: a literal dotted key ("flow.dport" beside "flow.sport") counts.
    const names=Object.keys(holderOf(fields,source).container).map(name=>name.toLowerCase().split('.').pop()!);
    return !names.some(name=>name==='dstport'||ALIASES[name]==='dstport');
  });
}

function candidateForSource(source:string,events:Record<string,unknown>[],existing:MappingRule[],
 existingGroups:Record<string,FieldGroup>,formats:readonly (string|undefined)[]=[],
 readings:readonly (string|undefined)[]=[]):NormalizationCandidate|null{
  // Generic Structural space_kv lets an unquoted value run up to the next key,
  // so `dport=53 pattern: allow all` stores the whole text under kv.dport and
  // its whitespace-separated pieces under atoms.dport_001... A port or IP never
  // contains whitespace, hence the first piece is the value and the rest is
  // trailing free text. Other targets (timestamps, sizes, messages) can span
  // tokens and therefore never accept an atom.
  const atomKey=firstAtomKeyOf(source);
  const leaf=atomKey===undefined?source.split('.').at(-1)??source:atomKey;
  const exact=findStellarMetadataField(source);
  const leafExact=findStellarMetadataField(leaf);
  let target=exact?.mappable?source:
    leafExact?.mappable?leaf:
    ALIASES[source.toLowerCase()]??ALIASES[leaf.toLowerCase()];
  // Stellar's proto is the IP protocol number and proto_name its name. A source field called proto whose
  // usable values are all documented protocol names (tcp, udp, icmp, igmp) holds the name, not the number.
  if(target==='proto'){
    const observed=events.map(fields=>lookupFieldValue(fields,source))
      .filter(result=>result.found&&!ignored(result.value));
    if(observed.length>0&&observed.every(result=>result.found&&typeof result.value==='string'&&
      DOCUMENTED_PROTO_NAMES.has(result.value.trim().toLowerCase())))target='proto_name';
  }
  if(atomKey!==undefined&&target&&!WHITESPACE_FREE_TARGETS.has(target))return null;
  if(!target||!AUTO_APPROVED_TARGETS.has(target))return null;
  // A name is evidence only where it stands for the record itself: a whole path the dictionary or the alias
  // table lists, a key the format specification defines, or a name at the level of the record. A leaf of an
  // object of the record (xlate.srcip, file.timestamp, referrer.url) names that object, whatever it is. This is
  // also what keeps a translated (NAT) endpoint out: no list of translated names is consulted here, and the
  // policy may not list a whole path that contains one (defaultDenyMapping20261128.test.ts).
  const carrierFormats=events.flatMap((fields,index)=>lookupFieldValue(fields,source).found?[formats[index]]:[]);
  const wholePathListed=Boolean(exact?.mappable)||ALIASES[source.toLowerCase()]!==undefined||
    specDefinedTargets(source,events,readings).includes(target);
  if(!wholePathListed&&!recordLevelSource(recordPathOf(source),carrierFormats))return null;
  if(incompatibleVendorMeaning(source,target,events))return null;
  const catalog=findStellarMetadataField(target);
  if(!catalog?.mappable||!catalog.mappingType||!catalog.group)return null;
  const current=existing.find(rule=>rule.source===source);
  const currentGroup=current?(existingGroups[current.id]??'vendor_fields'):undefined;
  const explicitPort=explicitPortSourceAlias(source,target);
  if(current&&current.target===target&&current.type===catalog.mappingType&&
     currentGroup===catalog.group&&!current.when)return null;
  if(existing.some(rule=>rule.id!==current?.id&&overlaps(rule.target,target)))return null;
  const values=events.map(fields=>lookupFieldValue(fields,source)).filter(result=>result.found);
  if(values.length===0)return null;
  const informativeValues=values.filter(result=>!ignored(result.value));
  const compatibleObserved=informativeValues.filter(result=>
    valueFitsNormalizationTarget(target,catalog.mappingType!,result.value)&&
    (target!=='proto_name'||DOCUMENTED_PROTO_NAMES.has(String(result.value).toLowerCase()))&&
    (target!=='proto'||(Number.isInteger(Number(result.value))&&
      Number(result.value)>=0&&Number(result.value)<=255))).length;
  // Protocol-gate abbreviated/ambiguous names; exact descriptive source
  // labels are an explicit source-identity contract, independent of vendor.
  const nonTransportPort=!explicitPort&&(target==='srcport'||target==='dstport')&&
    events.some(fields=>lookupFieldValue(fields,source).found&&
      unsupportedPortProtocolInEvent(fields,source));
  const method:NormalizationCandidate['method']=target===source?'EXACT_DICTIONARY_NAME':'DOCUMENTED_ALIAS';
  // A source needs at least one usable value, and every usable value must fit the target.
  // It must also be present in every event: in a sample of several record families a name may belong to one
  // family only, so a sparse source stays a "check first" proposal.
  // The exception is a network endpoint or URL field (SPARSE_SAFE_TARGETS) whose source carries the official
  // name itself at the level of the record: the name leaves no other reading, and the value is checked by its
  // form (address, port range with TCP or UDP named by the record, protocol, URL shape). Mixed samples
  // (traffic, web filter and system records of one device) hold such a field in some events only; the mapping
  // writes nothing for an event without it. Other official names (severity, type, icmp_type ...), aliases and
  // explicit port labels keep the full-coverage rule.
  const informative=informativeValues.length;
  const namedAsTarget=SPARSE_SAFE_TARGETS.has(target)&&
    (leaf.toLowerCase()===target||specDefinedTargets(source,events,readings).includes(target))&&
    sparseSafeValues(target,informativeValues);
  // Unknown protocol evidence never authorizes an official port. A port that only some record families carry,
  // or an alias whose meaning depends on the protocol, needs the record itself to name TCP or UDP in every
  // event that has the port: an ICMP record of another family may name its protocol differently, or not at all.
  // An event that carries the port key with a placeholder (`-`, empty) does not make the port "present in every event".
  const needsTransportEvidence=(target==='srcport'||target==='dstport')&&
    (informativeValues.length!==events.length||PROTOCOL_DEPENDENT_PORT_ALIASES.has(source.toLowerCase()));
  const lacksTransportEvidence=needsTransportEvidence&&events.some(fields=>{
    const value=lookupFieldValue(fields,source);
    return value.found&&!ignored(value.value)&&!transportEvidenceInEvent(fields,source);
  });
  const serverPort=serverPortReading(source,target,events);
  const high=!serverPort&&compatibleObserved===informative&&(values.length===events.length||namedAsTarget)&&
    informative>0&&!nonTransportPort&&!lacksTransportEvidence;
  // Auto-generated provenance is explicit; field names and IDs cannot prove
  // that a user has not edited a persisted mapping.
  const replaceIsGenerated=current?.authoring?.version===1&&
    current.authoring.origin==='AUTO';
  return {
    source,target,type:catalog.mappingType,group:catalog.group,
    confidence:high?'HIGH':'REVIEW',method,
    explanation:high&&explicitPort
      ?'The source explicitly names a port. Its validated integer value maps to the published Stellar field; non-TCP/UDP events may carry vendor-specific numeric identifiers rather than L4 transport ports.'
      :high
      ?(method==='EXACT_DICTIONARY_NAME'
        ?'Source name matches the official Stellar metadata field and observed values match its documented type.'
        :'Reviewed source alias maps to an official Stellar metadata field and observed values match its documented type.')
      :nonTransportPort
        ?'An abbreviated port field with unknown or non-transport protocol context needs review before mapping to an L4 port.'
        :values.length!==events.length
        ?'The field is missing from some events; review its event-family scope before applying an official mapping.'
        :informative===0
          ?'The source contains no informative values; a matching name alone is not enough to approve an official mapping.'
          :'The field-name match is plausible, but at least one observed value is incompatible with the documented Stellar field meaning or value type.',
    catalogVerified:true,catalogRelease:'7.0.xs',observed:values.length,
    compatibleObserved,total:events.length,
    eligibleObserved:values.length,skippedForSemantics:0,
    ...(current?{replacesMappingId:current.id,currentTarget:current.target}:{}),
    safeForBulk:high&&(!current||replaceIsGenerated),
  };
}
/** Limit expensive per-event semantic checks without silently sampling input order.
 * Catalog/alias eligibility is a cheap name-only prefilter. If more than the
 * bounded budget qualify, do not infer ANY official field from an incomplete
 * competition set; the UI shows a blocking review warning instead. */
export const MAX_OFFICIAL_CANDIDATE_SCAN=1024;
export function normalizationCandidateScanStatus(suite:SuiteResult|undefined):{
  eligiblePaths:number;limit:number;exceeded:boolean;paths:string[];
  sourceScanTruncated:boolean;
}{
  const sources=new Set<string>();
  let sourceScanTruncated=false;
  // Authoring is separately limited to 100 fields per event, but official
  // mapping competition must inspect ALL safe paths within its own 1024-path
  // budget. A large valid PAN-OS CSV can exceed 100 raw fields; refusing it
  // wholesale would erase independently qualified official source mappings.
  // The 1025th source path is a fail-closed overflow sentinel.
  for(const event of suite?.events??[]){
    const paths=listSafeLeafPaths(event.fields,1025);
    if(paths.length>MAX_OFFICIAL_CANDIDATE_SCAN){
      sourceScanTruncated=true;
      continue;
    }
    for(const path of paths)sources.add(path);
  }
  const eligible=[...sources].filter(source=>{
    const atomKey=firstAtomKeyOf(source);
    const leaf=atomKey===undefined?source.split('.').at(-1)??source:atomKey;
    return Boolean(findStellarMetadataField(source)?.mappable||
      findStellarMetadataField(leaf)?.mappable||
      ALIASES[source.toLowerCase()]||ALIASES[leaf.toLowerCase()]);
  });
  // Preserve the established single-event suggestion order for beginner UX.
  // With multiple event families, deterministic lexical order makes reversed
  // event ordering produce the exact same REVIEW candidate list.
  if((suite?.events.length??0)>1)eligible.sort();
  const exceeded=sourceScanTruncated||eligible.length>MAX_OFFICIAL_CANDIDATE_SCAN;
  return {eligiblePaths:eligible.length,limit:MAX_OFFICIAL_CANDIDATE_SCAN,
    exceeded,sourceScanTruncated,paths:exceeded?[]:eligible};
}
/** The grammar an event was read with: a mixed event is read by that of its family (an RFC 5424 or RFC 3164
 * envelope holds the record under `body`, like a Syslog parser with that body), every other event by its format. */
function readingFormat(event:SuiteResult['events'][number]):string|undefined{
  const family=event.effectiveFormat==='mixed'?event.readingFamily:undefined;
  if(!family)return event.effectiveFormat;
  return family.startsWith('rfc5424_')?'syslog_rfc5424':family.startsWith('rfc3164_')?'syslog_rfc3164':family;
}
export function suggestNormalizationCandidatesFromSuite(
  suite:SuiteResult|undefined,existing:MappingRule[],existingGroups:Record<string,FieldGroup>={},
  options:{skipAmbiguousTargets?:boolean}={},
):NormalizationCandidate[]{
  if(!suite?.events.length)return [];
  const fields=suite.events.map(event=>event.fields);
  const scan=normalizationCandidateScanStatus(suite);
  // An incomplete candidate set could hide a competing official destination.
  // Fail closed instead of marking the first 100 paths as complete.
  if(scan.exceeded)return [];
  const proposed:NormalizationCandidate[]=[];
  const candidatesByTarget=new Map<string,NormalizationCandidate[]>();
  for(const source of scan.paths){
    const candidate=candidateForSource(source,fields,existing,existingGroups,suite.events.map(readingFormat),
      suite.events.map(cefLeefReading));
    if(!candidate)continue;
    candidatesByTarget.set(candidate.target,[...(candidatesByTarget.get(candidate.target)??[]),candidate]);
    proposed.push(candidate);
  }
  // Competing sources are ambiguous only if more than one has actual values
  // compatible with the official target. A standalone Syslog HH:MM:SS is not
  // a competing timestamp to an independently qualified timezone date/time.
  const ambiguousTargets=new Set([...candidatesByTarget.entries()]
    .filter(([,candidates])=>candidates.filter(candidate=>candidate.compatibleObserved>0).length>1)
    .map(([target])=>target));
  // Never silently let insertion order select an official destination when
  // two distinct source paths are plausible. Keep both visible for human
  // review, but neither can be bulk-applied without resolving the conflict.
  const reviewed=proposed.map(candidate=>ambiguousTargets.has(candidate.target)
    ?{...candidate,confidence:'REVIEW' as const,safeForBulk:false,
      explanation:'The multiple source fields map to the same official Stellar destination; review the source meaning and select one manually.'}
    :candidate);
  return options.skipAmbiguousTargets
    ?reviewed.filter(candidate=>!ambiguousTargets.has(candidate.target)):reviewed;
}

/** Single-event helper. `effectiveFormat` names the reader that produced the event: without it only a
 * root-level name and a listed whole path stand for the record. */
export function suggestNormalizationCandidates(
  fields:Record<string,unknown>,existing:MappingRule[],effectiveFormat?:string,
):NormalizationCandidate[]{
  const suite={events:[{fields,...(effectiveFormat?{effectiveFormat}:{})}]} as unknown as SuiteResult;
  return suggestNormalizationCandidatesFromSuite(suite,existing);
}

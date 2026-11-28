"""Optional evidence-backed Stellar Dictionary normalization.

Source extraction remains authoritative. This pass never edits SourceEvent,
never drops unknown vendor fields, and never invents semantic roles. It maps
only exact Stellar field names or explicitly standardized CEF extension keys
whose source role and target type are independently documented.

Authoritative references (retrieved 2026-10-14):
- Stellar Cyber 7.0 Standard Metadata Dictionary:
  https://docs.stellarcyber.ai/7.0.xs/Common/Metadata-Dictionary.htm
- Stellar Cyber Parser Studio normalization:
  https://docs.stellarcyber.ai/7.0.xs/Configure/LogParser/Parser-Studio-Parsers.htm
- OpenText ArcSight Common Event Format extension dictionary:
  https://community.opentext.com/cfs-filesystemfile/__key/communityserver-discussions-components-files/224/3731.CommonEventFormatV25.pdf
"""
from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
import re
from typing import Any

from multipass_contract import CandidateResult
from source_parse import SourceEvent, ValueSpan, assert_source_accounting

# The same reviewed protocol/action vocabulary is consumed by the browser
# contract. Missing data is a fatal source configuration error, not a guess.
_POLICY=json.loads(Path(__file__).with_name(
    "semantic-policy.v1.json").read_text(encoding="utf-8"))
assert _POLICY["contract"]=="parser-studio.semantic-policy.v1"
_L4_NUMERIC=frozenset(_POLICY["transportPortProtocols"]["numeric"])
_L4_NAMES=frozenset(_POLICY["transportPortProtocols"]["names"])
_EXPLICIT_PORT_ALIASES=dict(_POLICY["explicitPortSourceAliases"])
_DOCUMENTED_PROTO_NAMES=frozenset(_POLICY["officialProtocolNames"])
# Default deny: the official fields a name may be proposed for, each with its dictionary definition and basis.
_AUTO_APPROVED_TARGETS=frozenset(_POLICY["autoApprovedTargets"])
DICTIONARY_REVISION="stellar-standard-metadata-7.0.xs-2026-10-14"
OFFICIAL_DICTIONARY_URL_65="https://docs.stellarcyber.ai/prod-docs/6.5.xs/Common/Metadata-Dictionary.htm?TocPath=REFERENCE%7C_____8"
OFFICIAL_DICTIONARY_URL_70="https://docs.stellarcyber.ai/7.0.xs/Common/Metadata-Dictionary.htm"
STELLAR_DICTIONARY_URL=OFFICIAL_DICTIONARY_URL_70
STELLAR_PARSER_NORMALIZATION_URL="https://docs.stellarcyber.ai/7.0.xs/Configure/LogParser/Parser-Studio-Parsers.htm"
CEF_DICTIONARY_URL="https://community.opentext.com/cfs-filesystemfile/__key/communityserver-discussions-components-files/224/3731.CommonEventFormatV25.pdf"

@dataclass(frozen=True)
class DictionaryField:
    name:str
    data_type:str
    evidence_url:str

# The fields this preview can coerce. Which of them may be proposed is decided by the shared policy
# (autoApprovedTargets), the same list the browser mapping proposals read: a field the policy does not list is
# never proposed here, whatever this table holds. Additions require authoritative field/type evidence there.
FIELDS={
    item.name:item for item in (
        DictionaryField("action","string",STELLAR_DICTIONARY_URL),
        DictionaryField("srcip","ip",STELLAR_DICTIONARY_URL),
        DictionaryField("dstip","ip",STELLAR_DICTIONARY_URL),
        DictionaryField("srcport","integer",STELLAR_DICTIONARY_URL),
        DictionaryField("dstport","integer",STELLAR_DICTIONARY_URL),
        DictionaryField("proto","integer",STELLAR_DICTIONARY_URL),
        DictionaryField("proto_name","string",STELLAR_DICTIONARY_URL),
        DictionaryField("username","string",STELLAR_DICTIONARY_URL),
        DictionaryField("url","string",STELLAR_DICTIONARY_URL),
    ) if item.name in _AUTO_APPROVED_TARGETS
}
# The CEF extension keys and the explicit port labels lead to listed fields only.

# Only valid inside a CEF_STANDARD source tree. These are CEF extension roles,
# not guesses from generic aliases appearing in other log formats.
CEF_ALIASES={
    "src":"srcip",
    "dst":"dstip",
    "spt":"srcport",
    "dpt":"dstport",
    "act":"action",
}
assert set(CEF_ALIASES.values())|set(_EXPLICIT_PORT_ALIASES.values())<=set(FIELDS)

@dataclass(frozen=True)
class SourceOccurrenceRef:
    path:str
    occurrence:int
    start_byte:int
    end_byte:int

@dataclass(frozen=True)
class DictionaryProjectionItem:
    source_path:str
    target_field:str
    documented_type:str
    start_byte:int
    end_byte:int

@dataclass(frozen=True)
class DictionaryProjection:
    mapped:tuple[DictionaryProjectionItem,...]
    unmapped_count:int
    issues:tuple[str,...]

@dataclass(frozen=True)
class DictionaryMapping:
    source:SourceOccurrenceRef
    dictionary_field:str
    dictionary_type:str
    normalized_value:Any
    rule_id:str
    evidence_url:str

@dataclass(frozen=True)
class DictionaryNormalization:
    raw_sha256:str
    source_bytes:int
    dictionary_revision:str
    source_fields:dict[str,Any]
    normalized_fields:dict[str,Any]
    mappings:tuple[DictionaryMapping,...]
    unmapped_occurrences:tuple[SourceOccurrenceRef,...]
    issues:tuple[str,...]
    normalization_attempted:bool=True
    native_verified:bool=False
    target_verified:bool=False

    def report(self)->dict[str,Any]:
        """Value-free public evidence only."""
        return {
            "dictionary_revision":self.dictionary_revision,
            "source_bytes":self.source_bytes,
            "source_occurrences":len(self.mappings)+len(self.unmapped_occurrences),
            "mapped_occurrences":len(self.mappings),
            "unmapped_occurrences":len(self.unmapped_occurrences),
            "normalized_fields":len(self.normalized_fields),
            "issues":list(self.issues),
            "normalization_attempted":True,
            "native_verified":False,
            "target_verified":False,
        }

_INTEGER=re.compile(r"^-?(?:0|[1-9][0-9]*)$")

def _segments_value(node:Any,segments:tuple[str|int,...])->Any:
    current=node
    for segment in segments:
        if isinstance(segment,int):
            if not isinstance(current,list) or not 0<=segment<len(current):
                raise ValueError("DICTIONARY_SOURCE_SEGMENT_MISMATCH")
            current=current[segment]
        else:
            if not isinstance(current,dict) or segment not in current:
                raise ValueError("DICTIONARY_SOURCE_SEGMENT_MISMATCH")
            current=current[segment]
    return current

def _display_value(node:Any,path:str)->Any:
    if isinstance(node,list):
        index_text,separator,remainder=path.partition(".")
        if not index_text.isdigit():
            raise ValueError("DICTIONARY_DISPLAY_PATH_MISMATCH")
        index=int(index_text)
        if not 0<=index<len(node):
            raise ValueError("DICTIONARY_DISPLAY_PATH_MISMATCH")
        value=node[index]
        return _display_value(value,remainder) if separator else value
    if not isinstance(node,dict):
        raise ValueError("DICTIONARY_DISPLAY_PATH_MISMATCH")
    if path in node:
        return node[path]
    choices=[key for key in node if isinstance(key,str) and path.startswith(key+".")]
    if not choices:
        raise ValueError("DICTIONARY_DISPLAY_PATH_MISMATCH")
    key=max(choices,key=len)
    return _display_value(node[key],path[len(key)+1:])

def _span_values(event:SourceEvent)->list[tuple[SourceOccurrenceRef,Any]]:
    counts:Counter[tuple[str,tuple[str|int,...]|None]]=Counter()
    rows=[]
    for span in event.value_spans:
        key=(span.path,span.source_segments)
        occurrence=counts[key];counts[key]+=1
        if span.source_segments is not None:
            value=_segments_value(event.vendor_fields,span.source_segments)
        else:
            value=_display_value(event.vendor_fields,span.path)
            if isinstance(value,list):
                if occurrence>=len(value):
                    raise ValueError("DICTIONARY_REPEAT_OCCURRENCE_MISMATCH")
                value=value[occurrence]
        rows.append((SourceOccurrenceRef(span.path,occurrence,span.start_byte,span.end_byte),value))
    return rows

# The reader of a Syslog envelope writes the pairs of the record into `body`; a JSON or key=value log that has
# an object called body does not.
_ENVELOPE_SYNTAX=re.compile(r"^[A-Z0-9_]*(?:SYSLOG|ENVELOPE)[A-Z0-9_]*\+")

def _record_name(path:str,syntax:str,sd_param:bool=False)->str|None:
    """The name a path stands for the record under, or None.

    A name is evidence only where it stands for the record itself (the rule of the browser proposals): at the
    root, or in the body an envelope reader wrote. A member of any other object of the record (xlate.srcip,
    event.source-port) names that object. `sd_param` also takes the SD-PARAM of an RFC 5424 structured-data
    element, which this preview reads for the explicit port labels only.
    """
    if "." not in path:
        return path
    if path.startswith("body.") and "." not in path[5:] and _ENVELOPE_SYNTAX.match(syntax):
        return path[5:]
    if sd_param and syntax.startswith("SYSLOG_RFC5424") and path.startswith("syslog.structured_data."):
        return path.rsplit(".",1)[1]
    return None

def _identity_target(path:str,syntax:str)->str|None:
    name=_record_name(path,syntax)
    return name if name in FIELDS else None

def _excluded_port_path(path:str)->bool:
    excluded=frozenset(_POLICY['excludedPortSourceSegments'])
    for segment in path.split('.'):
        # Mirror the browser's camelCase/underscore/hyphen semantic tokens.
        normalized=re.sub(r'([a-z0-9])([A-Z])',r'\1_\2',segment).lower()
        if normalized in excluded:
            return True
        if any(part in excluded for part in re.split(r'[-_]+',normalized) if part):
            return True
    return False


def _explicit_port_target(path:str,syntax:str)->str|None:
    # Same versioned source-identity rule as the browser: only the literal
    # source label where it stands for the record, never NAT/translated
    # ancestors or ambiguous abbreviations. Keep the source occurrence and
    # let the common integer/range guard apply.
    if _excluded_port_path(path):
        return None
    name=_record_name(path,syntax,sd_param=True)
    return _EXPLICIT_PORT_ALIASES.get(name.lower()) if name else None

def _cef_target(path:str,syntax:str)->str|None:
    # Multi-Pass syntax may preserve a base CEF result or name the accepted
    # qualified candidate as `cef.standard`; require both CEF provenance and
    # the exact CEF extension container, never a generic `src`/`dst` alias.
    if "cef" not in syntax.lower():
        return None
    for prefix in ("cef_extension.","body.cef_extension."):
        if path.startswith(prefix):
            return CEF_ALIASES.get(path[len(prefix):])
    return None

def _coerce(field:str,value:Any)->tuple[bool,Any]:
    spec=FIELDS[field]
    if spec.data_type=="string":
        return (isinstance(value,str) and len(value)<=8192,value)
    if spec.data_type=="ip":
        if not isinstance(value,str) or len(value)>64:return False,value
        try:ipaddress.ip_address(value)
        except ValueError:return False,value
        return True,value
    if spec.data_type=="integer":
        if isinstance(value,bool):return False,value
        if isinstance(value,int):number=value
        elif isinstance(value,str) and _INTEGER.fullmatch(value):number=int(value)
        else:return False,value
        if field in ("srcport","dstport") and not 0<=number<=65535:return False,value
        if field=="proto" and not 0<=number<=255:return False,value
        return True,number
    return False,value

# Only explicitly reviewed enforcement outcomes are safe action suggestions.
# Unknown values remain unchanged in vendor source, never inferred as policy.
SECURITY_DISPOSITIONS=frozenset(_POLICY["securityDispositions"])

def _semantic_rejection(target:str,value:Any,observed:list[tuple[str,Any]],syntax:str)->str|None:
    if target=="action" and (
        not isinstance(value,str) or value.strip().lower() not in SECURITY_DISPOSITIONS
    ):
        return "DICTIONARY_ACTION_NOT_ENFORCEMENT"
    if target=="proto_name" and (
        not isinstance(value,str) or value.strip().lower() not in _DOCUMENTED_PROTO_NAMES
    ):
        return "DICTIONARY_PROTOCOL_NAME_UNSUPPORTED"
    if target not in ("srcport","dstport"):
        return None
    numeric=set()
    names=set()
    for path,observed_value in observed:
        field=_record_name(path,syntax)
        field=field if field in FIELDS else None
        if field=="proto":
            ok,number=_coerce("proto",observed_value)
            if not ok:return "DICTIONARY_PROTOCOL_UNCERTAIN"
            numeric.add(number)
        elif field=="proto_name":
            if not isinstance(observed_value,str):
                return "DICTIONARY_PROTOCOL_UNCERTAIN"
            names.add(observed_value.strip().lower())
    if 1 in numeric or 58 in numeric or names.intersection({"icmp","icmpv6","icmp6"}):
        return "DICTIONARY_ICMP_HAS_NO_L4_PORT"
    # Protocol evidence exists: allow only explicitly reviewed L4 carriers.
    # Unknown/non-transport protocols are never silently treated as TCP/UDP.
    if (numeric and not numeric.issubset(_L4_NUMERIC)) or (
        names and not names.issubset(_L4_NAMES)
    ):
        return "DICTIONARY_NO_L4_PORT_EVIDENCE"
    if numeric and names:
        codes={"tcp":6,"udp":17}
        if any(codes.get(name)!=number for name in names for number in numeric):
            return "DICTIONARY_PROTOCOL_UNCERTAIN"
    # No protocol evidence preserves historical source-specific authoring.
    return None


def project_stellar_dictionary(candidate:CandidateResult)->DictionaryProjection:
    """Value-free exact-key projection for UI preview metadata only.

    This intentionally does not apply CEF/vendor aliases. It answers only
    whether an already extracted native path is itself a documented Stellar
    Dictionary field with a compatible type. Source values are never emitted.
    """
    if candidate.normalization_attempted:
        raise ValueError("DICTIONARY_SOURCE_ALREADY_NORMALIZED")
    proposed=defaultdict(list)
    unmapped=0;issues=[]
    observed=[(item.display_path,item.value) for item in candidate.occurrences]
    for occurrence in candidate.occurrences:
        target=_identity_target(occurrence.display_path,candidate.syntax)
        if target is None:
            unmapped+=1;continue
        ok,_=_coerce(target,occurrence.value)
        if not ok:
            issues.append("DICTIONARY_TYPE_REJECTED:"+target);unmapped+=1;continue
        semantic=_semantic_rejection(target,occurrence.value,observed,candidate.syntax)
        if semantic:
            issues.append(semantic+":"+target);unmapped+=1;continue
        proposed[target].append(occurrence)
    accepted=[]
    for target,items in proposed.items():
        if len(items)!=1:
            issues.append("DICTIONARY_TARGET_AMBIGUOUS:"+target);unmapped+=len(items);continue
        item=items[0]
        accepted.append(DictionaryProjectionItem(
            item.display_path,target,FIELDS[target].data_type,item.start_byte,item.end_byte,
        ))
    return DictionaryProjection(tuple(accepted),unmapped,tuple(dict.fromkeys(issues)))


def normalize_stellar_dictionary(event:SourceEvent)->DictionaryNormalization:
    """Map only authoritative, unambiguous roles; preserve source truth losslessly."""
    assert_source_accounting(event)
    original_tree=deepcopy(event.vendor_fields)
    rows=_span_values(event)
    observed=[(ref.path,value) for ref,value in rows]
    proposed=defaultdict(list)
    unmapped=[]
    issues=[]

    for ref,value in rows:
        target=(_identity_target(ref.path,event.syntax) or _cef_target(ref.path,event.syntax)
                or _explicit_port_target(ref.path,event.syntax))
        if target is None:
            unmapped.append(ref);continue
        ok,normalized=_coerce(target,value)
        if not ok:
            issues.append("DICTIONARY_TYPE_REJECTED:"+target)
            unmapped.append(ref);continue
        semantic=(None if _explicit_port_target(ref.path,event.syntax)==target
                  else _semantic_rejection(target,value,observed,event.syntax))
        if semantic:
            issues.append(semantic+":"+target)
            unmapped.append(ref);continue
        proposed[target].append((ref,normalized))

    normalized_fields={}
    mappings=[]
    for target,candidates in proposed.items():
        if len(candidates)!=1:
            issues.append("DICTIONARY_TARGET_AMBIGUOUS:"+target)
            unmapped.extend(ref for ref,_ in candidates)
            continue
        ref,value=candidates[0]
        rule_id=("cef:"+ref.path+"->"+target
                 if _cef_target(ref.path,event.syntax)==target
                 else "explicit-source:"+ref.path+"->"+target
                 if _explicit_port_target(ref.path,event.syntax)==target
                 else "identity:"+ref.path+"->"+target)
        mappings.append(DictionaryMapping(
            ref,target,FIELDS[target].data_type,value,rule_id,
            CEF_DICTIONARY_URL if rule_id.startswith("cef:") else FIELDS[target].evidence_url,
        ))
        normalized_fields[target]=value

    # This pass must never mutate or replace the source tree.
    if event.vendor_fields!=original_tree:
        raise AssertionError("DICTIONARY_SOURCE_MUTATED")
    mapped_refs={mapping.source for mapping in mappings}
    all_refs={ref for ref,_ in rows}
    if mapped_refs|set(unmapped)!=all_refs or mapped_refs&set(unmapped):
        raise AssertionError("DICTIONARY_OCCURRENCE_ACCOUNTING_FAILED")

    return DictionaryNormalization(
        event.raw_sha256,event.source_bytes,DICTIONARY_REVISION,original_tree,
        normalized_fields,tuple(mappings),tuple(unmapped),tuple(dict.fromkeys(issues)),
    )

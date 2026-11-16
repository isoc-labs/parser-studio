import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { compilePair, validateProject } from "../src/index.js";
import { sampleProject } from "./fixture.js";
test("R1.5 valid synthetic project model", () => { assert.equal(validateProject(sampleProject()).ok,true); });
test("strict invalid slugs, ports, injection, unknown operators", () => {
  const changes = [
    (p:any)=>{p.slug="../etc/passwd";}, (p:any)=>{p.slug="FOO";},
    (p:any)=>{p.receiver.port=0;},(p:any)=>{p.receiver.port=65536;},
    (p:any)=>{p.receiver.protocols=["udp","udp"];},(p:any)=>{p.receiver.protocols=["http"];},
    (p:any)=>{p.receiver.extra="@include /etc/passwd";},(p:any)=>{p.extraction.format="ruby";},
    (p:any)=>{p.receiver.tcpFraming="delimiter";},
    (p:any)=>{p.normalization.topFields.action.data_type="obejct";},
    (p:any)=>{p.unsupportedOpaqueBlocks=[{sourceRef:"opaque"}];}
  ];
  for (const change of changes) {const p:any=sampleProject();change(p);assert.equal(validateProject(p).ok,false,JSON.stringify(p));}
});
test("reject mappings to reserved/duplicate names and unknown classification fields", () => {
  const p=sampleProject();
  p.normalization.nsFields.invalid={normalized_name:"srcip",data_type:"string"};
  assert.ok(validateProject(p).issues.some(x=>x.code==="destination_collision"));
  delete p.normalization.nsFields.invalid;
  p.normalization.topFields["new_source"]={normalized_name:"stellar_log_index",data_type:"string"};
  assert.ok(validateProject(p).issues.some(x=>x.code==="reserved_field"));
  delete p.normalization.topFields["new_source"];
  p.classification.rules[0]!.field="not_extracted";
  assert.ok(validateProject(p).issues.some(x=>x.code==="unmapped_classification_field"));
});
test("files share identity, expected conf sections, and deterministic SHA-256", () => {
 const p=sampleProject();const result=compilePair(p);
 assert.deepEqual(result.files.map(x=>x.name),["customized_sample_firewall.conf","customized_sample_firewall"]);
 assert.equal(result.contract,"host-customized-pair.v0.1");assert.equal(result.manifest.status,"DRAFT");
 assert.equal(result.manifest.engineVerified,false);assert.equal(result.manifest.targetImportVerified,false);
 for(const f of result.files)assert.equal(f.sha256,createHash("sha256").update(f.content).digest("hex"));
 assert.deepEqual(compilePair(p),result);
 const conf=result.files[0]!.content;
 assert.equal((conf.match(/<source>/g)||[]).length,2);
 assert.match(conf,/@type udp/);assert.match(conf,/@type tcp/);
 assert.match(conf,/@type customized_sample_firewall/);
 assert.match(conf,/tag customized_sample_firewall/);
 assert.match(conf,/<match customized_sample_firewall\.\*\*>/);
 assert.match(conf,/key stellar_log_index/);
 assert.match(conf,/pattern \/\^session\$\//);assert.match(conf,/pattern \/\^threat\$\//);
});
test("manufacturer, product and version drive filenames, CONF identity and embedded parser metadata", () => {
 const p=sampleProject();
 p.vendor="Fortinet";p.product="FortiGate";p.productVersion="7.4.5";p.slug="fortinet_fortigate";
 p.projectId="draft-fortinet_fortigate";
 const result=compilePair(p);
 assert.deepEqual(result.files.map(x=>x.name),[
  "customized_fortinet_fortigate.conf","customized_fortinet_fortigate"
 ]);
 const conf=result.files[0]!.content;
 assert.match(conf,/# Vendor: Fortinet/);
 assert.match(conf,/# Product: FortiGate/);
 assert.match(conf,/# Product version: 7\.4\.5/);
 assert.match(conf,/# Parser name: customized_fortinet_fortigate/);
 assert.match(conf,/tag customized_fortinet_fortigate/);
 assert.match(conf,/@type customized_fortinet_fortigate/);
 const ruby=result.files[1]!.content;
 const payload=ruby.match(/Base64\.strict_decode64\('([A-Za-z0-9+/=]+)'\)/)?.[1];
 assert.ok(payload);
 const embedded=JSON.parse(Buffer.from(payload!,"base64").toString("utf8"));
 assert.equal(embedded.vendor,"Fortinet");
 assert.equal(embedded.product,"FortiGate");
 assert.equal(embedded.productVersion,"7.4.5");
});

test("compiler rejects untrusted manufacturer punctuation rather than embedding it", () => {
 const p=sampleProject();p.vendor="Pretend #{Kernel.exit} 'vendor'";
 assert.throws(()=>compilePair(p),/Invalid parser project/);
});

test("fragment includes only one set of markers, safe literal payload, and Ruby callback", () => {
 const p=sampleProject();p.vendor="Pretend Kernel.exit Vendor";
 const ruby=compilePair(p).files[1]!.content;
 for(const marker of ["STELLAR_INIT_BEGIN","STELLAR_INIT_END","STELLAR_PARSE_BEGIN","STELLAR_PARSE_END"])
   assert.equal(ruby.split(marker).length-1,1);
 assert.match(ruby,/def parse\(text\)/);assert.match(ruby,/yield event_time, normalized/);
 const payload=ruby.match(/Base64\.strict_decode64\('([A-Za-z0-9+/=]+)'\)/)?.[1];
 assert.ok(payload);
 assert.equal(JSON.parse(Buffer.from(payload!,"base64").toString("utf8")).vendor,p.vendor);
 assert.equal(ruby.includes("Kernel.exit"),false);
});
test("generated CSV parser reads a row with the generated tokenizer, never with the csv library",()=>{
 const csv=sampleProject();
 csv.extraction={format:"csv",csvColumns:["one","two","three"],csvDelimiter:","};
 const generated=compilePair(csv).files.find(file=>!file.name.endsWith(".conf"))!.content;
 assert.match(generated,/def psg_tokenize_csv_row\(raw, delimiter\)/);
 assert.doesNotMatch(generated,/CSV\.parse_line|require 'csv'/);
 assert.equal(generated.includes("liberal_parsing: true"),false);
});

test("compiler refuses invalid project; canonical map key order doesn't change artifacts", () => {
 const invalid=sampleProject();invalid.slug="x\n@include /etc";assert.throws(()=>compilePair(invalid),/Invalid parser project/);
 const a=sampleProject(),b=sampleProject();
 b.normalization.topFields=Object.fromEntries(Object.entries(b.normalization.topFields).reverse());
 assert.deepEqual(compilePair(a),compilePair(b));
});


test("bounded Syslog Regex body validates only with safe named captures and compiles deterministically",()=>{
 const p=sampleProject();p.receiver.port=7123;
 p.extraction={format:"syslog_rfc3164",syslogBodyFormat:"regex",
  pattern:"^%FTD-\\d-\\d+: Built \\w+ \\w+ connection (?<connection_id>\\d+) for [^:]+:(?<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)/(?<src_port>\\d+) to [^:]+:(?<dst_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)/(?<dst_port>\\d+)$"};
 p.normalization.topFields={
  "body.src_ip":{normalized_name:"srcip",data_type:"ip"},
  "body.src_port":{normalized_name:"srcport",data_type:"port"},
  "body.dst_ip":{normalized_name:"dstip",data_type:"ip"},
  "body.dst_port":{normalized_name:"dstport",data_type:"port"},
 };
 p.normalization.nsFields={};p.normalization.vendorFields={};
 p.classification.rules=[];
 assert.equal(validateProject(p).ok,true,JSON.stringify(validateProject(p)));
 const a=compilePair(p),b=compilePair(structuredClone(p));
 assert.deepEqual(a,b);
 const unsafe=structuredClone(p);
 unsafe.extraction.pattern="(?<x>.*)+";
 assert.equal(validateProject(unsafe).ok,false);
 assert.ok(validateProject(unsafe).issues.some(x=>x.code.startsWith("regex_")));
});


test("Generic Structural compiler is opt-in, bounded and keeps legacy artifact bytes isolated",()=>{
 const legacy=compilePair(sampleProject()).files[1]!.content;
 assert.equal(legacy.includes("parserstudio_generic_structural"),false);
 assert.equal(legacy.includes("parserstudio_source"),false);
 const p=sampleProject();
 p.receiver.port=6801;
 p.extraction={format:"generic_structural"};
 p.normalization.topFields={
  "syslog.pri":{normalized_name:"source_pri",data_type:"string"},
  "generic.kv.AD-Domain":{normalized_name:"ad_domain",data_type:"string"},
  "body.event.id":{normalized_name:"event_id",data_type:"integer"},
  "asa.src_ip":{normalized_name:"srcip",data_type:"ip"},
  "asa.dst_port":{normalized_name:"dstport",data_type:"port"},
 };
 p.normalization.nsFields={};p.normalization.vendorFields={};p.classification.rules=[];
 const validation=validateProject(p);
 assert.equal(validation.ok,true,JSON.stringify(validation));
 const pair=compilePair(p);
 const ruby=pair.files[1]!.content;
 assert.match(ruby,/reading = psg_read_event\(psg_text\(text\), settings\)/);
 assert.match(ruby,/def psg_extract_generic_structural\(raw, profile = nil, familyGrammar = nil\)/);
 assert.match(ruby,/def psg_short_rfc5424_structured\(raw\)/);
 assert.match(ruby,/def psg_prefixed_json\(raw\)/);
 assert.match(ruby,/def psg_iso_pri_mixed\(raw\)/);
 assert.match(ruby,/def psg_junos_rfc5424_sd\(raw\)/);
 assert.match(ruby,/def psg_space_kv\(raw\)/);
 assert.match(ruby,/def psg_watchguard_profile\(raw\)/);
 assert.match(ruby,/def psg_juniper_legacy_profile\(raw\)/);
 assert.match(ruby,/def psg_delimited_comma_kv\(raw\)/);
 assert.match(ruby,/def psg_bracket_colon_kv\(raw\)/);
 assert.match(ruby,/def psg_rfc3164_delimited_comma_kv\(raw\)/);
 assert.match(ruby,/normalized = \{'parserstudio_source' => original\}/);
 assert.match(ruby,/GENERIC STRUCTURAL|Generic Structural|generic structural/i);
 const low=structuredClone(p);low.receiver.port=6799;
 assert.equal(validateProject(low).ok,false);
 assert.ok(validateProject(low).issues.some(x=>x.code==="syslog_port_minimum"));
});

test("the generated grammar is emitted inside the Stellar marker region, nothing after PARSE_END", () => {
  const csv=sampleProject();
  csv.extraction={format:"csv",csvColumns:["one","two","three"],csvDelimiter:","};
  const generated=compilePair(csv).files.find(file=>!file.name.endsWith(".conf"))!.content;
  const end=generated.indexOf("# STELLAR_PARSE_END");
  assert.ok(end>0,"PARSE_END marker present");
  assert.equal(generated.slice(end+"# STELLAR_PARSE_END".length).trim(),"",
    "reference fragments end at STELLAR_PARSE_END; no code may follow it");
  assert.ok(generated.indexOf("def psg_tokenize_csv_row")>0&&generated.indexOf("def psg_tokenize_csv_row")<end,"the grammar belongs to the marker region");
});

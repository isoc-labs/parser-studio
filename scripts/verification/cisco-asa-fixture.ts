/**
 * Cisco ASA 302013 fixture shared by the Ruby 2.4.9 artifact gate and the real
 * Fluentd UDP reception gate. The pattern is authored from Cisco's documented
 * message grammar; raw lines and expected values come from the
 * VENDOR_PUBLISHED_TEXT corpus file, never from generated Ruby.
 */
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';

// Cisco ASA 302013 (Built inbound|outbound ...). Pattern authored from Cisco's
// documented message grammar; the raw lines and expected values come from the
// VENDOR_PUBLISHED_TEXT corpus file, never from generated Ruby.
export const ASA_PATTERN=String.raw`^.*%ASA-\d-(?<event_id>\d+): Built (?<direction>inbound|outbound) (?<protocol>TCP|UDP) connection (?<connection_id>\d+) for \w+:(?<a_ip>[\d.]+)/(?<a_port>\d+) \([\d.]+/\d+\) to \w+:(?<b_ip>[\d.]+)/(?<b_port>\d+) \((?<b_mapped_ip>[\d.]+)/\d+\)$`;
export const ASA_CORPUS=(JSON.parse(readFileSync(resolve(import.meta.dirname,'../../evals/golden-corpus/vendor-published-text-cisco-asa.v1.json'),'utf8')) as {
  cases:{id:string;sampleClass:string;rawSample:string;expectedMatch:boolean;expectedFields:Record<string,string>;expectedStellarFields:Record<string,string>}[];
}).cases.map(({id,sampleClass,rawSample,expectedMatch,expectedFields,expectedStellarFields})=>
  ({id,sampleClass,rawSample,expectedMatch,expectedFields,expectedStellarFields}));
export function applyAsaNormalization(project:import('../../backend/src/types').ParserProject):void{
  project.normalization.topFields={protocol:{normalized_name:'protocol',data_type:'string'}};
  project.normalization.nsFields={event_id:{normalized_name:'log.event_id',data_type:'integer'}};
  project.normalization.vendorFields={};
  // Regex extracts positions, not inferred traffic roles. Route explicitly
  // on the captured direction so the same recipe handles both connections.
  project.normalization.eventProfiles={discriminator:'direction',unknown:'reject',
    variants:[
      {name:'inbound',equals:'inbound',
        topFields:{a_ip:{normalized_name:'srcip',data_type:'ip'},b_ip:{normalized_name:'dstip',data_type:'ip'}},
        nsFields:{a_port:{normalized_name:'srcport',data_type:'port'},b_port:{normalized_name:'dstport',data_type:'port'}},
        vendorFields:{}},
      {name:'outbound',equals:'outbound',
        topFields:{b_ip:{normalized_name:'srcip',data_type:'ip'},a_ip:{normalized_name:'dstip',data_type:'ip'}},
        nsFields:{b_port:{normalized_name:'srcport',data_type:'port'},a_port:{normalized_name:'dstport',data_type:'port'}},
        vendorFields:{}},
    ]};
}

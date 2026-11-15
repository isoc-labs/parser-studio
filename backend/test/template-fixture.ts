import {readFileSync} from 'node:fs';
const read=(name:string):string=>readFileSync(new URL('../templates/'+name,import.meta.url),'utf8');
/** The grammar of a generated parser: the hand written primitives and the Ruby generated from the browser grammar. */
export function grammarSource(genericStructural=true):string{
 return read('grammar-runtime.rb.tpl')+'\n'+read('grammar-core.generated.rb.tpl')+(genericStructural?'\n'+read('grammar-generic.generated.rb.tpl'):'');
}
/**
 * Probe entries (tests only). Probes written before the grammar was generated call one extractor by name; the
 * names are defined here on the generated grammar, so those probes exercise the code a parser really runs.
 */
export const PROBE_ENTRIES=String.raw`
def parserstudio_probe(outcome)
  raise ArgumentError, outcome['errors'][0] unless outcome['errors'].empty?
  psg_export(outcome['fields'])
end
def parserstudio_key_values(text) parserstudio_probe(psg_strict_key_values(psg_text(text))) end
def parserstudio_json_object(text) parserstudio_probe(psg_extract_json_object(psg_text(text))) end
def parserstudio_cef(text) parserstudio_probe(psg_extract_structured_family(psg_text(text), 'cef')) end
def parserstudio_leef(text) parserstudio_probe(psg_extract_structured_family(psg_text(text), 'leef')) end
def parserstudio_syslog_rfc5424(text, settings)
  parserstudio_probe(psg_extract_structured_family(psg_text(text), 'syslog_rfc5424', settings['syslogBodyFormat'] || 'raw', settings['pattern']))
end
def parserstudio_syslog_rfc3164(text, settings)
  parserstudio_probe(psg_extract_structured_family(psg_text(text), 'syslog_rfc3164', settings['syslogBodyFormat'] || 'raw', settings['pattern']))
end
def parserstudio_csv(text, settings)
  parserstudio_probe(psg_extract_csv_row(psg_text(text), settings['csvColumns'], settings['csvDelimiter'] || ','))
end
def parserstudio_mixed(text, settings) parserstudio_probe(psg_extract_mixed(psg_text(text), settings)) end
def parserstudio_generic_leef2_implicit_tab(text) psg_export(psg_extract_leef2_implicit_tab(psg_text(text))) end
def parserstudio_generic_bsd_bracket_pid_message(text) psg_export(psg_bsd_bracket_pid_message_profile(text)) end
def parserstudio_generic_comma_kv(text) psg_export(psg_comma_kv(text)) end
def parserstudio_generic_dual_timestamp_session(text) psg_export(psg_dual_timestamp_session_profile(text)) end
def parserstudio_generic_ip_token(text) psg_ip_token(text) end
def parserstudio_generic_iso_pri_positional(text) psg_export(psg_iso_pri_positional(text)) end
def parserstudio_generic_prefixed_json(text) psg_export(psg_prefixed_json(text)) end
def parserstudio_generic_space_kv(text) psg_export(psg_space_kv(text)) end
def parserstudio_generic_watchguard_message(text) psg_export(psg_watchguard_message_profile(text)) end
def parserstudio_generic_structural(text)
  extraction = @parser_rule_set ? @parser_rule_set['extraction'] : {}
  parserstudio_probe(psg_extract_generic_structural(psg_text(text), extraction['genericStructuralProfile'],
    extraction['genericStructuralFamilyGrammar'] == 'dedicated' ? 'dedicated' : nil))
end
`;
/**
 * Resolve the actual compiler-owned source for standalone probes: the fragment template with the canonical
 * operators and the grammar in place. There is one template; the name of the former forwarder-family variant
 * resolves to it, so a probe that ran on "both templates" still runs.
 */
export function resolvedTemplate(name:string):string{
 if(name!=='ruby-fragment.rb.tpl'&&name!=='ruby-forwarder-family.rb.tpl')throw new Error('Unknown template '+name);
 const source=read('ruby-fragment.rb.tpl');
 for(const marker of ['# __PARSERSTUDIO_CANONICAL_OPERATORS__','# __PARSERSTUDIO_GRAMMAR__'])
  if(source.split(marker).length!==2)throw new Error(marker+' must occur exactly once');
 return source.replace('# __PARSERSTUDIO_CANONICAL_OPERATORS__',()=>read('canonical-operators.rb.tpl'))
  .replace('# __PARSERSTUDIO_GRAMMAR__',()=>grammarSource()+PROBE_ENTRIES);
}

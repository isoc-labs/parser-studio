import {evaluateCanonicalClassificationPredicate,validCanonicalSourcePath} from '../../backend/src/canonical-operator-contract';
import type { EventResult,ParserDraft } from '../model';
import type { EventClass, GuidedOptions } from './contract';
import { lookupFieldValue } from '../fieldPaths';

export interface ClassificationHint {
  index: EventClass | null;
  rule: number | null;
  reason: string;
  status: 'matched' | 'fallback' | 'unresolved';
}

/** Browser-only ordered if/then hint; NOT evidence of real Fluentd rewrite-tag or target upload. */
export function suggestClassification(event: EventResult, options: GuidedOptions,
  draft?:ParserDraft): ClassificationHint {
  if (!event.matched) {
    return { index: null, rule: null, status: 'unresolved', reason: 'Event extraction failed; unable to classify.' };
  }
  // The generated parser classifies an event only after extraction, mapping and enrichment have all succeeded.
  // An event with an error in one of them is a diagnostic record there, in no category (a failed expectation of
  // the test suite, stage "validate", is not an error of the parser).
  if (event.diagnostics.some(issue => issue.severity === 'error' && issue.stage !== 'validate')) {
    return { index: null, rule: null, status: 'unresolved',
      reason: 'A field of this event has an error; the generated parser reports the event as a diagnostic record and does not classify it.' };
  }
  for (let i = 0; i < options.classification.rules.length; i++) {
    const rule = options.classification.rules[i];
    if (!rule.sourceField.trim() || !rule.equals.trim()) continue;
    // The destination the generated parser classifies on (toBackendProject in backendAdapter.ts): the one
    // common destination of the source when it has any, otherwise its manufacturer field; two candidates
    // decide nothing.
    const mapped=draft?.mappings.filter(candidate=>candidate.source===rule.sourceField)??[];
    const inVendor=(id:string)=>(options.groups[id]??'vendor_fields')==='vendor_fields';
    const common=mapped.filter(candidate=>!inVendor(candidate.id));
    const eligible=common.length?common:mapped;
    const only=eligible.length===1?eligible[0]:undefined;
    // The export refuses a destination it cannot address (CLASSIFICATION_FIELD_PATH_UNSUPPORTED), for example
    // a manufacturer name with a space: no generated parser classifies on it.
    const mapping=only&&draft&&validCanonicalSourcePath(
      inVendor(only.id)?draft.vendor.trim()+'.'+only.target:only.target)?only:undefined;
    // In the real Native parser, classification runs AFTER typed mapping.
    // A missing or non-string mapped destination cannot satisfy a string
    // equality rule, even if String(originalNumber) would have matched.
    const vendorRecord=draft?event.normalized[draft.vendor.trim()]:undefined;
    const scope=mapping&&inVendor(mapping.id)
      ?(vendorRecord!==null&&typeof vendorRecord==='object'&&!Array.isArray(vendorRecord)?vendorRecord as Record<string,unknown>:{})
      :event.normalized;
    const match=draft
      ?(mapping?.type==='string'
          ?lookupFieldValue(scope,mapping.target)
          :{found:false,value:undefined})
      :lookupFieldValue(event.fields,rule.sourceField.trim());
    if(match.found&&evaluateCanonicalClassificationPredicate('equals',match.value,rule.equals)){
      return { index: rule.index, rule: i, status: 'matched', reason: rule.sourceField + ' = ' + rule.equals + ' · Condition ' + (i + 1) };
    }
  }
  return { index: options.classification.defaultIndex, rule: null, status: 'fallback', reason: 'No condition matched · Applied default event category' };
}

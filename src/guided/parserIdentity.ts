import type {ParserDraft} from '../model';
import {defaultGuidedOptions} from './contract';

const SAFE_PART=/[^a-z0-9]+/g;

function slugPart(value:string):string{
  return value.normalize('NFKD').toLowerCase()
    .replace(/[\u0300-\u036f]/g,'')
    .replace(SAFE_PART,'_').replace(/^_+|_+$/g,'');
}

/** Matches the parser-project schema maximum for vendor and product (128 characters). */
export const MAX_PARSER_IDENTITY_TEXT=128;
const MAX_SLUG=48;
const MAX_PRODUCT_PART=24;

/** Match Stellar custom-parser naming convention: customized_<vendor>_<product>. */
export function parserIdentitySlug(vendor:string,product:string):string{
  let vendorPart=slugPart(vendor),productPart=slugPart(product);
  if(vendorPart&&productPart&&vendorPart.length+1+productPart.length>MAX_SLUG){
    // Keep the product recognisable: a very long manufacturer must not erase it.
    productPart=productPart.slice(0,MAX_PRODUCT_PART).replace(/_+$/,'');
    vendorPart=vendorPart.slice(0,MAX_SLUG-1-productPart.length).replace(/_+$/,'');
  }
  const combined=[vendorPart,productPart].filter(Boolean).join('_');
  let slug=combined||'parser_product';
  if(!/^[a-z]/.test(slug))slug='parser_'+slug;
  slug=slug.replace(/_+/g,'_').slice(0,48).replace(/_+$/,'');
  if(slug.length<2)slug=(slug+'_parser').slice(0,48);
  return slug;
}

export function parserArtifactBaseName(vendor:string,product:string):string{
  return 'customized_'+parserIdentitySlug(vendor,product);
}

/** Plain-language reason when the manufacturer or product is blank (the project schema requires both). */
export function missingParserIdentityMessage(vendor:string,product:string):string|null{
  const noVendor=!vendor.trim(),noProduct=!product.trim();
  if(noVendor&&noProduct)return 'Enter the manufacturer and product name first. They are used in the parser file names.';
  if(noVendor)return 'Enter the manufacturer first. It is used in the parser file names.';
  if(noProduct)return 'Enter the product name first. It is used in the parser file names.';
  return null;
}

/** The parser details the identity card edits: manufacturer (the vendor namespace of the output), product,
 * version, the customized_<slug> file name and the .conf receiving port. They name and address the created files.
 * They are not parsing or mapping rules: work that depends only on the logs and the rules stays valid when they
 * change, and created files do not. */
export interface ParserExportSettings{vendor:string;name:string;version:string|undefined;slug:string;port:number}
export function parserExportSettings(draft:ParserDraft):ParserExportSettings{
  const guided=draft.guided??defaultGuidedOptions();
  return {vendor:draft.vendor,name:draft.name,version:draft.version,slug:guided.slug,port:guided.receiver.port};
}
/** The same parsing and mapping rules with the given parser details. */
export function withParserExportSettings(draft:ParserDraft,settings:ParserExportSettings):ParserDraft{
  const guided=draft.guided??defaultGuidedOptions();
  return {...draft,vendor:settings.vendor,name:settings.name,version:settings.version,
    guided:{...guided,slug:settings.slug,receiver:{...guided.receiver,port:settings.port}}};
}
const NO_EXPORT_SETTINGS:ParserExportSettings={vendor:'',name:'',version:undefined,slug:'',port:0};
/** Equal for two drafts that differ only in their parser details. */
export function parsingRulesKey(draft:ParserDraft):string{
  return JSON.stringify(withParserExportSettings(draft,NO_EXPORT_SETTINGS));
}

export {PLACEHOLDER_PARSER_VENDOR,PLACEHOLDER_PARSER_PRODUCT,placeholderParserIdentityParts,
  parserExportIdentityIssue} from '../../backend/src/parser-export-identity';

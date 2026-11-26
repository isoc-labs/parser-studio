/** Demo identity is for local authoring only; it must never become a real parser namespace. */
export const PLACEHOLDER_PARSER_VENDOR='Demo Local Draft';
export const PLACEHOLDER_PARSER_PRODUCT='Untitled parser';

export function placeholderParserIdentityParts(vendor:string,product:string):('manufacturer'|'product')[]{
  const parts:('manufacturer'|'product')[]=[];
  const normalized=(value:string)=>value.trim().toLowerCase();
  if(!vendor.trim()||normalized(vendor)===normalized(PLACEHOLDER_PARSER_VENDOR))parts.push('manufacturer');
  if(!product.trim()||normalized(product)===normalized(PLACEHOLDER_PARSER_PRODUCT))parts.push('product');
  return parts;
}

export function parserExportIdentityIssue(vendor:string,product:string){
  const parts=placeholderParserIdentityParts(vendor,product);
  return parts.length?{code:'PARSER_IDENTITY_REQUIRED',path:parts.includes('manufacturer')?'/vendor':'/product',
    message:'Enter the actual '+parts.join(' and ')+' before creating parser files. Placeholder names cannot be exported.'}:null;
}

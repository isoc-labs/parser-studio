// A generated parser's failure record keeps the event's original text in parser_raw_msg, the
// Stellar Cyber 7.0 dictionary field for the raw unparsed message. No other field may repeat it.
export function diagnosticsOf(record:Record<string,unknown>):Record<string,unknown>{
  const rest={...record};
  delete rest.parser_raw_msg;
  return rest;
}

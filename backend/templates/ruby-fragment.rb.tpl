# STELLAR_INIT_BEGIN
require 'json'
require 'base64'
require 'ipaddr'
require 'time'
require 'date'
require 'zlib'

def initialize()
  @parser_rule_set = JSON.parse(Base64.strict_decode64('__PARSER_PROJECT_B64__'))
  @parserstudio_case_map = JSON.parse(Zlib::Inflate.inflate(Base64.strict_decode64('__PARSERSTUDIO_UNICODE_CASE_B64__')))
  @parserstudio_official_types = JSON.parse('__STELLAR7_ENRICH_TYPES_JSON__')
end
# STELLAR_INIT_END

# STELLAR_PARSE_BEGIN
# The grammar of this parser is not written in this file. Every event is read by psg_read_event, the Ruby
# translation of readEvent in src/grammar/readEvent.ts: the same function the browser preview executes.
# scripts/grammar/ts2rb generates the translation (inserted at the grammar marker below) and CI verifies that it
# is in step with its source; the psg_* primitives it uses are the grammar runtime. What stays here is the
# transport contract of the receiver (message limit, blank message, line framing) and the hand-over of the
# result.
def parserstudio_extract(text)
  raise ArgumentError, 'Record is longer than the configured message limit' if text.bytesize > @parser_rule_set['receiver']['messageLengthLimit']
  raise ArgumentError, 'Blank event' if parserstudio_blank_event?(text)
  settings = @parser_rule_set['extraction']
  # Only bounded TCP LF LF framed Java and JSON source modes can contain LF.
  # Every other source is strictly one line, never implicit reconstruction.
  framing = @parser_rule_set['receiver']['tcpFraming']
  if settings['format'] == 'java_stacktrace'
    raise ArgumentError, 'Java stack trace requires explicit LF LF TCP framing' unless
      framing == 'blank_line_java'
  elsif settings['format'] != 'json' && (text.include?("\n") || text.include?("\r"))
    raise ArgumentError, 'Multiline unframed event is unsupported'
  end
  reading = psg_read_event(psg_text(text), settings)
  # Parsing Success Contract at run time: only a FULL reading is a parsed event. A Generic Structural reading
  # that is PARTIAL is still handed over (owner policy D-2 keeps the legacy route working); it is marked by
  # parserstudio_normalize and never loses its original text.
  unless reading['status'] == 'FULL' || (reading['status'] == 'PARTIAL' && settings['format'] == 'generic_structural')
    raise ArgumentError, (reading['reasons'][0] || 'The event is not completely parsed')
  end
  result = psg_export(reading['fields'])
  @parserstudio_reading_status = reading['status']
  unless reading['forwarderHops'].empty?
    result['__parserstudio_forwarder_hops'] = reading['forwarderHops'].map do |hop|
      {'relay_host'=>hop['relayHost'], 'relay_timestamp'=>hop['relayTimestamp'], 'envelope'=>hop['format'],
       'prefix_start_byte'=>hop['prefixStartByte'], 'payload_start_byte'=>hop['payloadStartByte']}
    end
  end
  result
end

# A blank line is not an event. The browser never offers one as a sample (blank lines separate samples there,
# by String#trim), so a message that is nothing but white space is declined instead of becoming, for example,
# a TAB-separated row of empty fields. The Unicode blanks are tested on a UTF-8 view of the text, so that a
# binary-tagged message with high bytes cannot raise an encoding error.
def parserstudio_blank_event?(text)
  return true if text.match?(/\A[ \t\n\v\f\r]*\z/)
  view = text.dup.force_encoding('UTF-8')
  view.valid_encoding? && view.match?(/\A[ \t\n\v\f\r\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]*\z/)
end

# A Regex extraction is the one grammar that is not shared text: the pattern is the user's and it is executed
# by the regular expression engine of this runtime (parserstudio_regex, emitted for Regex projects only).
def psg_x_portable_regex_fields(text, pattern)
  {'fields'=>parserstudio_regex(text, {'pattern'=>pattern}), 'errors'=>[]}
rescue ArgumentError => e
  {'fields'=>{}, 'errors'=>[e.message]}
end

# __PARSERSTUDIO_GRAMMAR__
# __PARSERSTUDIO_CANONICAL_OPERATORS__
# STELLAR_PARSE_END

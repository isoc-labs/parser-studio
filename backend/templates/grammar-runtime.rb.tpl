# Parser Studio grammar runtime: the primitives of the generated grammar.
#
# The grammar itself (grammar-core.generated.rb.tpl) is generated from the TypeScript the browser executes.
# This file is the only hand written part: each psg_* method gives one ECMAScript operation the meaning it has
# in the browser, on Ruby values. Strings are valid UTF-8; every string length and offset is counted in UTF-16
# code units, as in the browser, so a bound or an index means the same in both. The primitive conformance test
# (scripts/verification/translation-conformance.ts, probes in translation-probes.ts) runs both sides on the same inputs.
#
# Values: undefined is nil and null is :psg_null, always, so the two stay as distinct as they are in the
# browser; a record is a Hash with String keys; a Set or Map is a Hash; a match is a MatchData.

# The event text as the grammar reads it: UTF-8. Text that is not valid UTF-8 is declined; the browser cannot
# hold such text either (a decoder replaces the bytes before the grammar sees them).
def psg_text(text)
  view = text.encoding == Encoding::UTF_8 ? text : text.dup.force_encoding('UTF-8')
  raise ArgumentError, 'Event text is not valid UTF-8' unless view.valid_encoding?
  view
end

# The UTF-16 code units of a text that is not ASCII, as an array: a character of the BMP is one entry, a
# character beyond it is two (the character itself, then ''), so that an offset of the browser addresses the
# same place here, in constant time. The array is kept for the texts in use, found by identity (the grammar
# never changes a string in place). The texts were kept in a list of eight that was searched one by one; that
# search was the largest single cost of a JSON event with text beyond ASCII (39% of its CPU time in a profile
# on Ruby 2.4.9, 2026-11-16).
def psg_units(text)
  cache = (@psg_unit_cache ||= {}.compare_by_identity)
  units = cache[text]
  return units unless units.nil?
  units = []
  text.each_char do |char|
    units << char
    units << '' if char.ord > 0xffff
  end
  cache[text] = units
  @psg_unit_cache_units = @psg_unit_cache_units.to_i + units.length
  # The kept arrays are bounded by their total size, not only by their number: every entry is a String of its
  # own, so 256 arrays of 60 KB events held several hundred megabytes. The oldest go first and the eight newest
  # always stay: one event is read through a few texts of its own size (the line, its body, a value), and a
  # text dropped while it was in use was built again on every read (delta audit of 2026-11-16).
  while cache.length > 8 && (cache.length > 64 || @psg_unit_cache_units > 131_072)
    dropped, dropped_units = cache.shift
    @psg_unit_cache_units -= dropped_units.length
    @psg_offset_cache.delete(dropped) unless @psg_offset_cache.nil?
  end
  units
end

# The two offset tables of a text with a character beyond the BMP, or false for a text in which a character
# offset and a code unit offset are the same thing. The first table holds the character offset of every code
# unit (-1 for the second unit of a character), the second the code unit offset of every character; each has
# one more entry, for the end of the text. They are kept beside the units and dropped with them. Without them
# every conversion counted the units before the offset, so the cost of one read grew with its distance from
# the start of the text: a CSV row with one such character and 15,000 doubled quotes took 26 s (delta audit
# of 2026-11-16).
def psg_offsets(text)
  cache = (@psg_offset_cache ||= {}.compare_by_identity)
  offsets = cache[text]
  return offsets unless offsets.nil?
  units = psg_units(text)
  if units.length == text.length
    offsets = false
  else
    chars = []
    starts = []
    units.each_with_index do |unit, index|
      if unit == ''
        chars << -1
      else
        chars << starts.length
        starts << index
      end
    end
    chars << starts.length
    starts << units.length
    offsets = [chars, starts]
  end
  cache[text] = offsets
end

# True when a character offset and a code unit offset are the same thing in this text.
def psg_plain?(text)
  text.ascii_only? || !psg_offsets(text)
end

def psg_len(value)
  return value.length unless value.is_a?(String)
  value.ascii_only? ? value.length : psg_units(value).length
end

# UTF-16 code unit offset -> character offset. An offset between the two units of one character has no
# counterpart in a UTF-8 string: the event is declined instead of being cut inside a character.
def psg_unit_to_char(text, unit)
  return unit if unit <= 0 || text.ascii_only?
  offsets = psg_offsets(text)
  return unit unless offsets
  chars = offsets[0]
  return chars[-1] if unit >= chars.length - 1
  char = chars[unit]
  raise ArgumentError, 'String offset inside a surrogate pair' if char < 0
  char
end

def psg_char_to_unit(text, char)
  return char if char <= 0 || text.ascii_only?
  offsets = psg_offsets(text)
  return char unless offsets
  starts = offsets[1]
  char < starts.length ? starts[char] : char + starts[-1] - (starts.length - 1)
end

def psg_int(value)
  return value if value.is_a?(Integer)
  return 0 if value.nil?
  if value.is_a?(Float)
    return 0 if value.nan?
    return value > 0 ? (1 << 62) : -(1 << 62) if value.infinite?
    return value.truncate
  end
  psg_int(psg_num(value))
end

def psg_slice(value, from = nil, to = nil)
  size = psg_len(value)
  from = from.nil? ? 0 : psg_int(from)
  to = to.nil? ? size : psg_int(to)
  from = from < 0 ? [size + from, 0].max : [from, size].min
  to = to < 0 ? [size + to, 0].max : [to, size].min
  return (value.is_a?(String) ? '' : []) if to <= from
  return value[from, to - from] unless value.is_a?(String) && !value.ascii_only?
  # A short piece is put together from the units. Reading it out of the text costs a walk from the start of
  # the text to the piece (a UTF-8 string has no index of its characters), so a text read in many short
  # pieces cost the square of its length (delta audit of 2026-11-16).
  if to - from <= 32
    units = psg_units(value)
    raise ArgumentError, 'String offset inside a surrogate pair' if units[from] == '' || units[to] == ''
    return units[from, to - from].join
  end
  return value[from, to - from] if psg_plain?(value)
  first = psg_unit_to_char(value, from)
  value[first, psg_unit_to_char(value, to) - first]
end

def psg_substring(value, from = nil, to = nil)
  size = psg_len(value)
  from = [[from.nil? ? 0 : psg_int(from), 0].max, size].min
  to = [[to.nil? ? size : psg_int(to), 0].max, size].min
  from, to = to, from if from > to
  psg_slice(value, from, to)
end

# value[index]. A string yields the code unit at the offset; for a character outside the BMP the first unit
# yields the character and the second the empty string, so that unit by unit copying rebuilds the text.
def psg_at(value, index)
  return nil if value.nil? || value.equal?(:psg_null) || !index.is_a?(Integer) || index < 0
  return value[index] unless value.is_a?(String) && !value.ascii_only?
  psg_units(value)[index]
end

def psg_char_code_at(text, index)
  index = psg_int(index)
  return Float::NAN if index < 0
  return text.getbyte(index) || Float::NAN if text.ascii_only?
  units = psg_units(text)
  unit = units[index]
  return Float::NAN if unit.nil?
  return 0xdc00 + ((units[index - 1].ord - 0x10000) & 0x3ff) if unit == ''
  code = unit.ord
  code > 0xffff ? 0xd800 + ((code - 0x10000) >> 10) : code
end

def psg_code_point_at(text, index)
  index = psg_int(index)
  return nil if index < 0
  return text.getbyte(index) if text.ascii_only?
  units = psg_units(text)
  unit = units[index]
  return nil if unit.nil?
  unit == '' ? 0xdc00 + ((units[index - 1].ord - 0x10000) & 0x3ff) : unit.ord
end

def psg_from_code_point(code)
  raise ArgumentError, 'A lone surrogate is not a character' if code >= 0xd800 && code <= 0xdfff
  [code].pack('U')
end

def psg_index(value, item, from = nil)
  return value.index(item) || -1 unless value.is_a?(String)
  start = from.nil? ? 0 : [[psg_int(from), 0].max, psg_len(value)].min
  found = value.index(item, psg_unit_to_char(value, start))
  found.nil? ? -1 : psg_char_to_unit(value, found)
end

def psg_rindex(value, item)
  found = value.rindex(item)
  return -1 if found.nil?
  value.is_a?(String) ? psg_char_to_unit(value, found) : found
end

def psg_split(text, separator, limit = nil)
  parts =
    if separator.is_a?(String) && separator.empty?
      raise ArgumentError, 'Split into code units of a character outside the BMP' unless psg_plain?(text)
      text.chars
    elsif separator.is_a?(Regexp)
      raise ArgumentError, 'Split on an expression that matches the empty string' if separator.match?('')
      text.empty? ? [''] : text.split(separator, -1)
    elsif text.empty?
      ['']
    else
      # String#split(' ') is the awk mode of Ruby; a one-space separator must be literal.
      text.split(separator == ' ' ? / / : separator, -1)
    end
  limit.nil? ? parts : parts.first(psg_int(limit))
end

def psg_expand_replacement(text, match)
  return text unless text.include?('$')
  text.gsub(/\$(?:\$|&|([1-9][0-9]?))/) do
    token = Regexp.last_match
    if token[1].nil?
      token[0] == '$$' ? '$' : match[0]
    elsif token[1].to_i < match.size
      match[token[1].to_i].to_s
    elsif token[1].length == 2 && token[1][0].to_i < match.size
      match[token[1][0].to_i].to_s + token[1][1]
    else
      token[0]
    end
  end
end

def psg_replace(text, pattern, all, replacement)
  render = lambda do |match|
    if replacement.respond_to?(:call)
      arguments = [match[0]] + match.captures + [psg_char_to_unit(text, match.begin(0)), text]
      psg_str(replacement.call(*arguments.first(replacement.parameters.length)))
    else
      psg_expand_replacement(replacement, match)
    end
  end
  all ? text.gsub(pattern) { render.call(Regexp.last_match) } : text.sub(pattern) { render.call(Regexp.last_match) }
end

def psg_match_all(text, pattern)
  text.to_enum(:scan, pattern).map { Regexp.last_match }
end

# A match of a text beyond ASCII carries the text it was made on: MatchData#string is a copy of a text that is
# not frozen, a new one for every match, and the units of that copy were built again for every match of a
# scan (an RFC 3164 event of 60 KB with key=value pairs took 1.9 s, 73% of it there; profile on Ruby 2.4.9,
# 2026-11-16).
def psg_match_at(pattern, text, position)
  position = psg_int(position)
  return pattern.match(text, position) || :psg_null if text.ascii_only?
  match = pattern.match(text, psg_unit_to_char(text, position))
  return :psg_null if match.nil?
  match.instance_variable_set(:@psg_text, text)
  match
end

def psg_match_end(match)
  text = match.string
  return match.end(0) if text.ascii_only?
  psg_char_to_unit(match.instance_variable_get(:@psg_text) || text, match.end(0))
end

def psg_match_index(match)
  psg_null?(match) ? nil : psg_char_to_unit(match.string, match.begin(0))
end

def psg_starts_with(text, prefix, position)
  psg_slice(text, [psg_int(position), 0].max).start_with?(prefix)
end

def psg_group(match, name)
  return nil if match.nil? || match.equal?(:psg_null)
  raise NoMethodError, 'psg_group reads a match' unless match.is_a?(MatchData)
  return nil unless name.is_a?(String)
  begin
    match[name]
  rescue IndexError
    nil
  end
end

def psg_named_groups(match)
  match.names.each_with_object({}) { |name, groups| groups[name] = match[name] }
end

def psg_get(record, key)
  psg_null?(record) ? nil : record[key]
end

def psg_set_tag(target, name, value)
  target.instance_variable_set("@psg_tag_#{name}", value)
  target
end

def psg_get_tag(target, name)
  variable = "@psg_tag_#{name}"
  target.instance_variable_defined?(variable) ? target.instance_variable_get(variable) : nil
end

def psg_is_well_formed(text)
  text.valid_encoding?
end

def psg_null?(value)
  value.nil? || value.equal?(:psg_null)
end

def psg_t(value)
  !(value.nil? || value == false || value == '' || value == 0 || value.equal?(:psg_null) ||
    (value.is_a?(Float) && value.nan?))
end

def psg_typeof(value)
  case value
  when nil then 'undefined'
  when String then 'string'
  when Numeric then 'number'
  when true, false then 'boolean'
  when Proc, Method then 'function'
  else 'object'
  end
end

def psg_normal_number(value)
  value.is_a?(Float) && value.finite? && value == value.floor && value.abs < 9007199254740992.0 ? value.to_i : value
end

def psg_num(value)
  return psg_normal_number(value) if value.is_a?(Numeric)
  return value ? 1 : 0 if value == true || value == false
  return 0 if value.equal?(:psg_null)
  return Float::NAN unless value.is_a?(String)
  text = value.gsub(/\A[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+|[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+\z/, '')
  return 0 if text.empty?
  if text.match?(/\A[+-]?[0-9]+\z/)
    number = text.to_i
    return number.abs < 9007199254740992 ? number : number.to_f
  end
  if text.match?(/\A[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\z/)
    mantissa, exponent = text.split(/[eE]/, 2)
    mantissa = mantissa.sub(/\A([+-]?)\./, '\10.').sub(/\.\z/, '')
    return psg_normal_number(Float(exponent ? "#{mantissa}e#{exponent}" : mantissa))
  end
  return text.to_i(16) if text.match?(/\A0[xX][0-9A-Fa-f]+\z/)
  return text[2..-1].to_i(8) if text.match?(/\A0[oO][0-7]+\z/)
  return text[2..-1].to_i(2) if text.match?(/\A0[bB][01]+\z/)
  return Float::INFINITY if text == 'Infinity' || text == '+Infinity'
  return -Float::INFINITY if text == '-Infinity'
  Float::NAN
end

def psg_parse_int(text, radix)
  match = /\A[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]*([+-]?)(.*)\z/m.match(psg_str(text))
  digits = match[2]
  digits = digits[2..-1] if radix == 16 && digits.match?(/\A0[xX]/)
  allowed = '0123456789abcdefghijklmnopqrstuvwxyz'[0, radix]
  taken = digits.downcase[/\A[#{allowed}]+/]
  return Float::NAN if taken.nil?
  number = taken.to_i(radix)
  number = number.to_f if number >= 9007199254740992
  match[1] == '-' ? -number : number
end

def psg_str(value)
  case value
  when String then value
  when Integer then value.to_s
  when Float
    return 'NaN' if value.nan?
    return value > 0 ? 'Infinity' : '-Infinity' if value.infinite?
    psg_float_text(value)
  when true then 'true'
  when false then 'false'
  when nil then 'undefined'
  when Array then psg_join(value, ',')
  when Symbol then 'null'
  else '[object Object]'
  end
end

# Number::toString of a finite double: the shortest digits that read back as the same double (Float#to_s
# finds them), laid out by the ECMAScript rules (plain digits from 1e-6 up to 1e21, an exponent beyond).
def psg_float_text(value)
  return '0' if value == 0
  mantissa, exponent = value.abs.to_s.split('e')
  whole, fraction = mantissa.split('.')
  digits = whole + fraction.to_s
  point = whole.length + exponent.to_i
  leading = digits[/\A0*/].length
  digits = digits[leading..-1].sub(/0+\z/, '')
  point -= leading
  size = digits.length
  body =
    if size <= point && point <= 21 then digits + '0' * (point - size)
    elsif point > 0 && point <= 21 then digits[0, point] + '.' + digits[point..-1]
    elsif point > -6 && point <= 0 then '0.' + '0' * -point + digits
    else
      power = point - 1
      (size == 1 ? digits : digits[0] + '.' + digits[1..-1]) + 'e' + (power < 0 ? '-' : '+') + power.abs.to_s
    end
  (value < 0 ? '-' : '') + body
end

def psg_add(left, right)
  return psg_normal_number(left + right) if left.is_a?(Numeric) && right.is_a?(Numeric)
  psg_str(left) + psg_str(right)
end

# Numbers: an Integer below 2^53 in magnitude, a Float beyond (the nearest double, as in the browser), so that
# arithmetic on a large value rounds as it does there.
def psg_mul(left, right)
  product = left * right
  product.is_a?(Integer) && product.abs >= 9007199254740992 ? left.to_f * right.to_f : psg_normal_number(product)
end

def psg_div(left, right)
  left = psg_num(left)
  right = psg_num(right)
  return Float::NAN if (left.is_a?(Float) && left.nan?) || (right.is_a?(Float) && right.nan?)
  if right == 0
    return Float::NAN if left == 0
    return left > 0 ? Float::INFINITY : -Float::INFINITY
  end
  psg_normal_number(left.fdiv(right))
end

def psg_mod(left, right)
  left = psg_num(left)
  right = psg_num(right)
  return Float::NAN if right == 0 || (left.is_a?(Float) && !left.finite?) || (right.is_a?(Float) && right.nan?)
  return left if right.is_a?(Float) && right.infinite?
  psg_normal_number(left.remainder(right))
end

def psg_floor(value)
  value.is_a?(Float) && !value.finite? ? value : value.floor
end

def psg_floor_div(left, right)
  psg_floor(psg_div(left, right))
end

def psg_finite?(value)
  value.is_a?(Integer) || (value.is_a?(Float) && value.finite?)
end

# A number beyond 2^53 is a Float here (the nearest double, as in the browser) and still an integer.
def psg_integer?(value)
  value.is_a?(Integer) || (value.is_a?(Float) && value.finite? && value == value.floor)
end

def psg_safe_integer?(value)
  psg_integer?(value) && value.abs <= 9007199254740991
end

def psg_nan?(value)
  value.is_a?(Float) && value.nan?
end

def psg_pad_start(text, size, pad = ' ')
  return text if pad.empty?
  text.rjust(psg_int(size) - (psg_len(text) - text.length), pad)
end

# side: 1 start, 2 end, 3 both. The white space of String.prototype.trim.
def psg_trim(text, side)
  text = text.sub(/\A[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+/, '') if side & 1 == 1
  text = text.sub(/[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+\z/, '') if side & 2 == 2
  text
end

def psg_lower(text)
  raise ArgumentError, 'Case conversion of non ASCII text is outside the shared grammar' unless text.ascii_only?
  text.tr('A-Z', 'a-z')
end

def psg_upper(text)
  raise ArgumentError, 'Case conversion of non ASCII text is outside the shared grammar' unless text.ascii_only?
  text.tr('a-z', 'A-Z')
end

def psg_join(list, separator)
  list.map { |item| psg_null?(item) ? '' : psg_str(item) }.join(separator)
end

def psg_set(list)
  list.each_with_object({}) { |item, set| set[item] = true }
end

# Object.keys / values / entries of a value that is not known to be a record.
def psg_keys(value)
  case value
  when Hash then value.keys
  when Array then (0...value.length).map(&:to_s)
  when String then (0...psg_len(value)).map(&:to_s)
  else []
  end
end

def psg_values(value)
  case value
  when Hash then value.values
  when Array then value.dup
  when String then psg_keys(value).map { |index| psg_at(value, index.to_i) }
  else []
  end
end

def psg_entries(value)
  psg_keys(value).zip(psg_values(value))
end

def psg_spread(value)
  psg_null?(value) ? {} : value
end

def psg_assign(target, *sources)
  sources.each { |source| target.merge!(source) unless psg_null?(source) }
  target
end

# A callback of the browser receives (item, index); a Ruby lambda is strict about its argument count. Whether
# the callback takes the index is asked once per list: Proc#parameters builds an array on every call, and
# asking per item was a measurable part of the cost of an event (Ruby 2.4.9, 2026-11-15).
# A list without items does not ask: its callback is never looked at, as it never was.
def psg_with_index?(list, function)
  !list.empty? && function.parameters.length >= 2
end

def psg_map(list, function)
  out = []
  with_index = psg_with_index?(list, function)
  list.each_with_index { |item, index| out << (with_index ? function.call(item, index) : function.call(item)) }
  out
end

def psg_flat_map(list, function)
  out = []
  with_index = psg_with_index?(list, function)
  list.each_with_index do |item, index|
    result = (with_index ? function.call(item, index) : function.call(item))
    result.is_a?(Array) ? out.concat(result) : out << result
  end
  out
end

def psg_filter(list, function)
  out = []
  with_index = psg_with_index?(list, function)
  list.each_with_index { |item, index| out << item if psg_t((with_index ? function.call(item, index) : function.call(item))) }
  out
end

def psg_some(list, function)
  with_index = psg_with_index?(list, function)
  list.each_with_index { |item, index| return true if psg_t((with_index ? function.call(item, index) : function.call(item))) }
  false
end

def psg_every(list, function)
  with_index = psg_with_index?(list, function)
  list.each_with_index { |item, index| return false unless psg_t((with_index ? function.call(item, index) : function.call(item))) }
  true
end

def psg_for_each(list, function)
  with_index = psg_with_index?(list, function)
  list.each_with_index { |item, index| (with_index ? function.call(item, index) : function.call(item)) }
  nil
end

def psg_find(list, function)
  with_index = psg_with_index?(list, function)
  list.each_with_index { |item, index| return item if psg_t((with_index ? function.call(item, index) : function.call(item))) }
  nil
end

def psg_find_index(list, function)
  with_index = psg_with_index?(list, function)
  list.each_with_index { |item, index| return index if psg_t((with_index ? function.call(item, index) : function.call(item))) }
  -1
end

def psg_reduce(list, function, initial)
  list.each_with_index.reduce(initial) { |memo, (item, index)| function.parameters.length >= 3 ? function.call(memo, item, index) : function.call(memo, item) }
end

# JSON text -> values, as JSON.parse reads it: one number type (an integral value is an Integer, a value beyond
# 2^53 is the nearest double), and null is :psg_null. The text rule (RFC 8259 tokens only) is applied
# first because the json library of Ruby 2.4 accepts more than JSON.
def psg_json_parse(text)
  raise ArgumentError, 'JSON text is outside RFC 8259' unless psg_json_strict_text?(text)
  psg_json_import(JSON.parse(text, allow_nan: false, create_additions: false))
end

def psg_json_strict_text?(text)
  text.match?(/\A(?>[^"\/]|"(?>[^"\\\x00-\x1f]|\\["\\\/bfnrt]|\\u(?:[0-9A-Ca-cE-Fe-f][0-9A-Fa-f]{3}|[Dd][0-7][0-9A-Fa-f]{2})|\\u[Dd][89ABab][0-9A-Fa-f]{2}\\u[Dd][C-Fc-f][0-9A-Fa-f]{2})*")*\z/)
end

def psg_json_import(value)
  case value
  when nil then :psg_null
  when Hash then value.each_with_object({}) { |(key, item), record| record[key] = psg_json_import(item) }
  when Array then value.map { |item| psg_json_import(item) }
  when Integer then value.abs < 9007199254740992 ? value : value.to_f
  when Float then psg_normal_number(value)
  else value
  end
end

# The result of a grammar entry point as plain Ruby data, as JSON.stringify would write it: a property whose
# value is undefined is absent, and null is nil.
def psg_export(value)
  case value
  when Hash
    value.each_with_object({}) { |(key, item), record| record[key] = psg_export(item) unless item.nil? }
  when Array then value.map { |item| psg_export(item) }
  when Symbol then value.equal?(:psg_null) ? nil : value
  else value
  end
end

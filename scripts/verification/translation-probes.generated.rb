# GENERATED FILE - DO NOT EDIT.
# Probes of the translation itself (scripts/verification/translation-conformance.ts).
# Source: scripts/verification/translation-probes.ts (probeString), scripts/verification/translation-probes.ts (probeScan), scripts/verification/translation-probes.ts (probeRegex), scripts/verification/translation-probes.ts (probeNumber), scripts/verification/translation-probes.ts (probeValue), scripts/verification/translation-probes.ts (probeCollections) and the functions they reach.
# Regenerate with: node scripts/grammar/ts2rb/generate.mjs --write
# CI runs the generator with --verify, so a hand edit of this file fails the gate.

# scripts/verification/translation-probes.ts: KNOWN
def psg_k_known
  @psg_k_known ||= {'a' => true, 'bb' => true, '' => true}
end

# scripts/verification/translation-probes.ts: LIMITS
def psg_k_limits
  @psg_k_limits ||= {'low' => 2, 'high' => 5, 'names' => ['a', 'b'], 'nested' => {'flag' => true}}
end

# scripts/verification/translation-probes.ts: counter
def psg_counter(start, step = nil, label = nil)
  step = 2 if step.nil?
  return ((psg_null?(psg_t1 = label) ? 'n' : psg_t1) + psg_str((start + step)))
end

# scripts/verification/translation-probes.ts: probeCollections
def psg_probe_collections(items, record)
  copy = popped = merged = assigned = seen = index = total = lengths = tagged = head = second = caught = add = post = before = nil
  copy = [*items, 'tail']
  popped = copy.pop
  copy.push('x', 'y')
  merged = {'first' => 1}.merge!(record).merge!({'last' => items.length})
  assigned = psg_assign({}, record, {'extra' => true})
  seen = {}
  index = {}
  total = 0
  psg_map(items, lambda { |item_2, position_2| [position_2, item_2] }).each do |(position, item)|
    if seen.key?(item)
      next
    end
    seen[item] = true
    index[item] = position
    total += position
  end
  lengths = psg_map(items, lambda { |item_3| psg_len(item_3) })
  tagged = psg_set_tag({'value' => 1}, 'kind', 'kv')
  head, second, _ = items
  caught = 'none'
  begin
    psg_json_parse((psg_null?(psg_t1 = items[0]) ? '' : psg_t1))
  rescue StandardError
    caught = 'invalid'
  end
  add = lambda { |x, y| (x + y) }
  post = 0
  before = ((post += 1) - 1)
  return [copy, popped, copy.length, psg_slice(items, 1), psg_slice(items, (-2)), psg_slice(items, 1, 2), psg_index(items, 'b'), items.include?('b'), psg_join(items, '|'), psg_join(items, ','), psg_filter(items, lambda { |item_4| (item_4 != '') }), psg_some(items, lambda { |item_5| (item_5 == 'b') }), psg_every(items, lambda { |item_6| (psg_len(item_6) < 3) }), psg_find(items, lambda { |item_7| (psg_len(item_7) > 1) }), psg_find_index(items, lambda { |item_8| (psg_len(item_8) > 1) }), psg_reduce(lengths, lambda { |sum, value| (sum + value) }, 0), (items + ['z']), psg_map(items, lambda { |item_9, position_3| (item_9 + psg_str(position_3)) }), merged, merged.keys, assigned, seen.length, index['b'], index.key?('zz'), total, psg_get_tag(tagged, 'kind'), psg_get_tag(tagged, 'none'), psg_get_tag({}.merge!(tagged), 'kind'), head, second, caught, add.call(2, 3), before, post, psg_counter(1), psg_counter(1, 5), psg_counter(1, nil, 'k'), 5, psg_k_limits['names'].include?((psg_null?(psg_t2 = items[0]) ? '' : psg_t2)), true, psg_at(items, (items.length - 1)), psg_at(items, (-1)), items[99], record['missing'], {'empty' => :psg_null, 'absent' => nil, 'zero' => 0, 'text' => ''}, (psg_t(items.length) ? 'some' : 'none'), psg_map([1, 2, 3], lambda { |value_2| psg_str(value_2) })]
end

# scripts/verification/translation-probes.ts: probeNumber
def psg_probe_number(s, a, b)
  n = nil
  n = psg_num(s)
  return [psg_str(n), psg_integer?(n), psg_finite?(n), psg_safe_integer?(n), psg_nan?(n), (n > 5), (n <= 5), (n == 0), psg_str(psg_parse_int(s, 10)), psg_str(psg_parse_int(s, 16)), psg_str((a + b)), (a - b), psg_mul(a, b), psg_str(psg_mod(a, 3)), psg_str(psg_mod((-a), 3)), psg_str(psg_mod(a, b)), psg_str(psg_floor_div(a, 3)), psg_str(psg_div(a, 2)), psg_str(psg_div(a, b)), [a, b].max, [a, b].min, psg_str(psg_div(a, 4)), a.to_s(16), psg_str((n + 1)), (s + psg_str(a)), (psg_str(a) + s), psg_str(psg_mul(n, 1000000)), psg_str(psg_div(n, 1000000)), psg_str((0.1 + 0.2)), psg_str(1.0e+21), psg_str(1.0e-7), psg_str(123456789012345680000.0), psg_str(psg_div(a, 3))]
end

# scripts/verification/translation-probes.ts: probeRegex
def psg_probe_regex(s)
  word = named = sticky = numbers = nil
  word = (/[A-Za-z_]+/.match(s) || :psg_null)
  named = (/\A(?<head>[a-z]+)(?:-(?<tail>[0-9]+))?/.match(s) || :psg_null)
  sticky = psg_match_at(/\G(?:[A-Za-z]+)/, s, (psg_t(word) ? (psg_match_end(word) - 1) : 0))
  numbers = []
  psg_match_all(s, /[0-9]+/).each do |match|
    numbers.push([match[0], psg_match_index(match)])
  end
  return [/\Aa[^\n\r\u2028\u2029]c\z/.match?(s), /\A[^\n\r\u2028\u2029]*\z/.match?(s), /\A(?m:.)*\z/.match?(s), /[\t\n\x0b\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]/.match?(s), psg_at((/[^\t\n\x0b\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+/.match(s) || :psg_null), 0), (psg_null?(psg_t1 = (/[0-9]+/.match(s) || :psg_null)) ? nil : psg_match_index(psg_t1)), /[A-Za-z0-9_]+\z/.match?(s), /(?:(?<=[A-Za-z0-9_])(?![A-Za-z0-9_])|(?<![A-Za-z0-9_])(?=[A-Za-z0-9_]))ab(?:(?<=[A-Za-z0-9_])(?![A-Za-z0-9_])|(?<![A-Za-z0-9_])(?=[A-Za-z0-9_]))/.match?(s), psg_at((/\A[^,]{2,4}?,/.match(s) || :psg_null), 0), /\A(?:ab){2}/.match?(s), /[\[\]\x26\#\/\-]/.match?(s), /\A[a-c\x26]+\z/.match?(s), /\A[^ \t\n\r\f\x0b]{1,3}\z/.match?(s), /\A[^\n\r\u2028\u2029]{1,3}\z/.match?(s), /[\u{e9}\u{1f600}]/.match?(s), /\A(a|b)(?:\1)\z/.match?(s), /a\z/.match?(s), /\A\z/.match?(s), (psg_null?(psg_t2 = word) ? nil : psg_match_index(psg_t2)), psg_at(word, 0), (psg_t(word) ? psg_match_end(word) : :psg_null), (psg_t(named) ? psg_named_groups(named) : :psg_null), psg_group(named, 'tail'), psg_at(named, 1), (psg_t(sticky) ? [sticky[0], psg_match_index(sticky), psg_match_end(sticky)] : :psg_null), psg_at(psg_match_at(/\G(?:[A-Za-z]+)/, s, 0), 0), psg_split(s, /,[\t\n\x0b\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]*/), psg_split(s, /(;)/), psg_replace(s, /[0-9]+/, false, 'N'), psg_replace(s, /[0-9]+/, true, 'N'), psg_replace(s, /([a-z])([0-9])/, true, lambda { |_whole, letter, digit| psg_add(digit, letter) }), psg_replace(s, /[A-Z]/, true, lambda { |upper| (upper + upper) }), numbers, (psg_null?(psg_t3 = (/\A([A-Za-z0-9_])([A-Za-z0-9_])?/.match(s) || :psg_null)) ? nil : psg_slice(psg_t3.to_a, 1)), psg_group((/\A(?<x>x)?y/.match(s) || :psg_null), 'x')]
end

# scripts/verification/translation-probes.ts: probeScan
def psg_probe_scan(s)
  units = quoted = count = index = unit = characters = cursor = tokens = v_next = v_end = nil
  units = ''
  quoted = false
  count = 0
  index = 0
  psg_t1 = true
  while true
    if psg_t1 then psg_t1 = false else index += 1 end
    break unless (index < psg_len(s))
    unit = psg_at(s, index)
    if (unit == '"')
      quoted = !quoted
      next
    end
    if ((unit == ';') && !quoted)
      break
    end
    units += (((unit == ' ') && !quoted) ? '_' : unit)
    count += 1
  end
  characters = []
  s.each_char do |character|
    if (character == ' ')
      next
    end
    characters.push(character)
    if (characters.length >= 6)
      break
    end
  end
  cursor = 0
  tokens = []
  while (cursor < psg_len(s))
    v_next = psg_index(s, ',', cursor)
    v_end = ((v_next < 0) ? psg_len(s) : v_next)
    tokens.push(psg_slice(s, cursor, v_end))
    cursor = (v_end + 1)
  end
  return [units, count, characters, tokens, cursor]
end

# scripts/verification/translation-probes.ts: probeString
def psg_probe_string(s, t, a, b)
  return [psg_len(s), psg_slice(s, a), psg_slice(s, a, b), psg_slice(s, (-a)), psg_slice(s, a, (-b)), psg_substring(s, a, b), psg_substring(s, b, a), psg_index(s, t), psg_index(s, t, a), psg_rindex(s, t), s.include?(t), s.start_with?(t), psg_starts_with(s, t, a), s.end_with?(t), psg_split(s, ((t == '') ? ',' : t)), psg_split(s, ','), psg_split(s, ' '), psg_split(s, ',', 2), psg_str(psg_char_code_at(s, a)), psg_code_point_at(s, a), psg_at(s, a), (psg_at(s, a) || ''), psg_pad_start(s, b, '0'), psg_pad_start(s, b), psg_trim(s, 3), psg_trim(s, 1), psg_trim(s, 2), psg_replace(s, ',', false, ';'), psg_replace(s, ',', true, ';'), psg_replace(s, 'a', false, t), (s * 2), [*s.chars].length, (s + t), (s + ':' + psg_str(a)), (s == t), (s != t), psg_is_well_formed(s), s.bytesize, psg_k_known.key?(s)]
end

# scripts/verification/translation-probes.ts: probeValue
def psg_probe_value(v)
  out = record = nil
  out = [!psg_t(v), psg_typeof(v), v.equal?(:psg_null), v.nil?, psg_null?(v), v.is_a?(Array), (psg_null?(psg_t1 = v) ? 'default' : psg_t1), psg_str(((psg_typeof(v) == 'object') ? 'object' : v))]
  if v.is_a?(String)
    out.push(psg_len(v), (psg_t(v) ? 'non-empty' : 'empty'))
  end
  if v.is_a?(Numeric)
    out.push((v + 1), (psg_t(v) ? 'non-zero' : 'zero'), psg_integer?(v))
  end
  if (!v.equal?(:psg_null) && (psg_typeof(v) == 'object'))
    out.push(psg_keys(v), psg_entries(v), psg_values(v).length)
  end
  if ((psg_t(v) && (psg_typeof(v) == 'object')) && !v.is_a?(Array))
    record = v
    out.push(record.key?('a'), record.key?('a'), record['a'].equal?(:psg_null), record['a'].nil?, psg_null?(record['a']), (psg_null?(psg_t2 = record['a']) ? 'd' : psg_t2), !psg_t(record['a']))
  end
  return out
end

/**
 * Guard original numeric lexemes before JSON.parse can round large event IDs.
 * The caller validates JSON syntax first. This scanner ignores JSON strings,
 * including escaped quotation marks, and examines every nested number.
 *
 * Large/inexact integer tokens are not reviewer-safe in JavaScript Number.
 *
 * A number in decimal or exponent spelling is read as a double. It is safe when the double stands for exactly the
 * number that was written: printed again in its shortest form (the form the browser and the generated Ruby both
 * emit) it gives the same decimal number. That holds for every number of up to 15 significant digits in the
 * normal range and for a number that was itself printed from a double - an epoch time with microseconds such as
 * 1731719701.123456, the `ts` of every Zeek JSON record. It does not hold for a number with more digits than a
 * double identifies, such as 0.1234567890123456789, which is declined. Counting digits (more than 15) declined both.
 */
/**
 * The decimal number a spelling stands for: its digits without leading and trailing zeros and the power of ten of
 * the last digit. "1731719701.123456", "1.731719701123456e9" and "1731719701.1234560" all give
 * "1731719701123456e-6"; every spelling of zero gives "0". The sign is not part of it.
 */
function decimalIdentity(spelling: string): string {
  const parts = spelling.split(/[eE]/u);
  const mantissa = parts[0]!.replace(/^[+-]/u, '');
  const exponent = parts.length > 1 ? Number(parts[1]!) : 0;
  const point = mantissa.indexOf('.');
  const whole = point < 0 ? mantissa : mantissa.slice(0, point);
  const fraction = point < 0 ? '' : mantissa.slice(point + 1);
  const digits = (whole + fraction).replace(/^0+/u, '');
  const trimmed = digits.replace(/0+$/u, '');
  if (trimmed === '') return '0';
  return trimmed + 'e' + String(exponent - fraction.length + (digits.length - trimmed.length));
}
export function hasUnsafeJsonNumbers(source: string): boolean {
  let index = 0;
  while (index < source.length) {
    const current = source[index]!;
    if (current === '"') {
      index++;
      while (index < source.length) {
        if (source[index] === '\\') { index += 2; continue; }
        if (source[index++] === '"') break;
      }
      continue;
    }
    if (current === '-' || (current >= '0' && current <= '9')) {
      const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u.exec(source.slice(index));
      if (!match) return true;
      const token = match[0];
      const value = Number(token);
      if (!Number.isFinite(value)) return true;
      if (Number.isInteger(value) && !Number.isSafeInteger(value)) return true;
      // A decimal or exponent spelling that the double does not stand for exactly would be emitted as another
      // number: more digits than a double identifies, or a value below the smallest step of a double.
      if (/[.eE]/u.test(token)) {
        const mantissa = token.split(/[eE]/u, 1)[0]!;
        if (decimalIdentity(token) !== decimalIdentity(String(value))) return true;
        // Don't silently treat a nonzero decimal as zero after underflow.
        if (value === 0 && /[1-9]/u.test(mantissa)) return true;
      }
      index += token.length;
      continue;
    }
    index++;
  }
  return false;
}

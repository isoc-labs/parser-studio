// Independent audit of 2026-11-15 (A1): `filePath=C:\Users\bob\ suser=bob` was read as ONE value and reported as
// completely read, in the browser and in the generated Ruby (same on main): the backslash took the separator
// with it. A backslash never takes SP or TAB with it, and the run-time check sees a pair inside a value.
import { describe, expect, it } from 'vitest';
import { readEvent } from './readEvent';
import { cefEventUnaccounted } from './lossGuard';

const B = '\\';
const HEAD = 'CEF:0|Microsoft|Windows|10|4663|File access|5|';
const HEADER = { cef_version: '0', cef_device_vendor: 'Microsoft', cef_device_product: 'Windows', cef_device_version: '10', cef_signature_id: '4663', cef_name: 'File access', cef_severity: '5' };
const PATH = 'C:' + B + 'Users' + B + 'bob' + B;

describe('a CEF value that ends in a backslash the sender did not double', () => {
  it.each([
    ['filePath=' + PATH + ' suser=bob src=10.1.1.1'],
    ['suser=bob filePath=' + PATH + ' src=10.1.1.1'],
    ['suser=bob src=10.1.1.1 filePath=' + PATH + '\t'],
    ['filePath=' + PATH + '\tsuser=bob src=10.1.1.1'],
  ])('keeps every pair of %j', (extension) => {
    const read = readEvent(HEAD + extension, { format: 'cef' });
    expect(read.status).toBe('FULL');
    expect(read.fields).toMatchObject({ filePath: PATH, suser: 'bob', src: '10.1.1.1' });
  });

  it('reads the doubled backslash of a conforming sender as before, and still declines a backslash at the end', () => {
    expect(readEvent(HEAD + 'filePath=C:' + B + B + 'Users' + B + B + ' suser=bob', { format: 'cef' }).fields).toMatchObject({ filePath: 'C:' + B + 'Users' + B, suser: 'bob' });
    expect(readEvent(HEAD + 'suser=bob filePath=' + PATH, { format: 'cef' }).status).toBe('UNKNOWN');
  });

  it('the run-time check reports a value that ran into the next pair, whatever the extractor returned', () => {
    const text = HEAD + 'filePath=' + PATH + ' suser=bob';
    expect(cefEventUnaccounted(text, { ...HEADER, filePath: PATH + ' suser=bob' })).toMatch(/inside an extracted value/);
    expect(cefEventUnaccounted(text, { ...HEADER, filePath: PATH, suser: 'bob' })).toBeNull();
    // An escaped "=" and a URL query are value data, not a pair.
    expect(cefEventUnaccounted(HEAD + 'msg=a b' + B + '=c request=http://x/?a=b&c=d', { ...HEADER, msg: 'a b=c', request: 'http://x/?a=b&c=d' })).toBeNull();
  });
});

import {describe,expect,it} from 'vitest';
import {hasUnsafeJsonNumbers} from '../jsonNumberSafety';
import {jsonObjectOfEvent,unsafeJsonNumberExplanation,unsafeJsonNumberLexemes} from './unsafeJsonNumbers';

describe('the reason shown for a JSON number the grammar declines',()=>{
  it('names the number as written and nothing the grammar accepts',()=>{
    const event='{"Keywords":-9218868437227405312,"EventID":4625,"note":"id 1731719701123456789 in text","ratio":0.25,"ts":1731719701123456789}';
    expect(unsafeJsonNumberLexemes(event)).toEqual(['-9218868437227405312','1731719701123456789']);
    expect(hasUnsafeJsonNumbers(event)).toBe(true);
    const safe='{"EventID":4625,"ratio":0.25,"id":"1731719701123456789","big":9007199254740991}';
    expect(unsafeJsonNumberLexemes(safe)).toEqual([]);
    expect(hasUnsafeJsonNumbers(safe)).toBe(false);
    expect(unsafeJsonNumberExplanation(safe)).toBeNull();
  });
  it('agrees with the grammar on every number of a mixed list',()=>{
    const numbers=['0','-1','9007199254740991','9007199254740992','-9007199254740993','1e400','0.1','1731719701.5',
      '123456789012345.6','1.7976931348623157e308','12345678901234567890','4.9e-324','1e-400'];
    for(const number of numbers){
      const text='{"n":'+number+'}';
      expect(unsafeJsonNumberLexemes(text).length>0,number).toBe(hasUnsafeJsonNumbers(text));
    }
  });
  it('reads the JSON object behind a Syslog header and explains it in one sentence',()=>{
    const raw='<134>1 2026-11-16T01:15:01Z host app - - - {"EdgeStartTimestamp":1731719701123456789,"ClientIP":"203.0.113.77"}';
    expect(jsonObjectOfEvent(raw)).toBe('{"EdgeStartTimestamp":1731719701123456789,"ClientIP":"203.0.113.77"}');
    const text=unsafeJsonNumberExplanation(raw)!;
    expect(text).toContain('1731719701123456789');
    expect(text).toContain('Nothing was discarded');
    expect(unsafeJsonNumberExplanation('srcip=10.1.1.1 id=1731719701123456789')).toBeNull();
    expect(unsafeJsonNumberExplanation('{"a":1')).toBeNull();
    // A brace in the structured data of the header is not the object of the event.
    const withSd='<134>1 2026-11-16T01:15:01Z host app - - [meta@1 note="{x}"] {"id":1731719701123456789}';
    expect(jsonObjectOfEvent(withSd)).toBe('{"id":1731719701123456789}');
    expect(unsafeJsonNumberExplanation(withSd)).toContain('1731719701123456789');
  });
});

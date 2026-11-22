/**
 * Loss guard: pairs behind a list delimiter (Issue #315, Phase 3 P1).
 *
 * The key=value grammar separates pairs at SP and TAB only (contract KV_GAP), so it reads
 * "src=10.0.0.1,dst=10.0.0.2,action=allow" as ONE pair whose value is the rest of the line. The independent
 * reader of the Parsing Success Contract cut its tokens at white space as well, saw the same single pair, and
 * the event was reported FULL with two fields missing. Evidence that shares the grammar's idea of a separator
 * is not independent of it: the reader also sees a pair that starts behind a list delimiter (, ; |).
 */
import { describe, expect, it } from 'vitest';
import { classifyStructuredParse, independentKeyValuePairs } from './parseStatus';

const written = (raw: string) => independentKeyValuePairs(raw).map(pair => [pair.key, pair.rawValue]);
const THREE = [['src', '10.0.0.1'], ['dst', '10.0.0.2'], ['action', 'allow']];

describe('independent pair evidence behind a list delimiter', () => {
  it.each([',', ';', '|'])('sees every pair of a line whose pairs are separated by %j alone', delimiter => {
    expect(written(['src=10.0.0.1', 'dst=10.0.0.2', 'action=allow'].join(delimiter))).toEqual(THREE);
  });

  it('sees the pairs behind a Syslog header as well', () => {
    expect(written('<134>Nov 13 10:00:00 fw01 src=10.0.0.1,dst=10.0.0.2,action=allow')).toEqual(THREE);
  });

  it.each([', ', ';  ', '|\t'])('does not take the delimiter of %j into the value before it', separator => {
    expect(written(['src=10.0.0.1', 'dst=10.0.0.2', 'action=allow'].join(separator))).toEqual(THREE);
  });

  it('sees a pair behind a delimiter that follows a quoted value', () => {
    expect(written('a="x y",b=2;c=\'z=1\'|d=4, e="5"')).toEqual([['a', 'x y'], ['b', '2'], ['c', 'z=1'], ['d', '4'], ['e', '5']]);
  });

  it('keeps a value that is a list of pairs of its own whole (a distinguished name, a cookie)', () => {
    expect(written('dn=CN=John,OU=Users,DC=corp srcip=10.1.1.1 cookie=a=1;b=2'))
      .toEqual([['dn', 'CN=John,OU=Users,DC=corp'], ['srcip', '10.1.1.1'], ['cookie', 'a=1;b=2']]);
  });

  it('keeps a URL with a query string whole', () => {
    expect(written('url=http://x/?a=1,b=2 action=allow')).toEqual([['url', 'http://x/?a=1,b=2'], ['action', 'allow']]);
  });

  it('keeps a delimiter that no key follows as value data', () => {
    expect(written('list=a,b,c ports=1;2|3 note=x,=y last=1,')).toEqual([['list', 'a,b,c'], ['ports', '1;2|3'], ['note', 'x,=y'], ['last', '1,']]);
    expect(written('a=1, stray b=2')).toEqual([['a', '1,'], ['b', '2']]);
  });

  it('leaves white-space separated pairs exactly as before', () => {
    expect(written('src=10.0.0.1 dst=10.0.0.2\taction=allow')).toEqual(THREE);
  });
});

describe('Parsing Success Contract for a delimiter separated line', () => {
  const RAW = 'src=10.0.0.1,dst=10.0.0.2,action=allow';

  it('is not FULL when the grammar kept the whole line as the value of the first key', () => {
    const verdict = classifyStructuredParse(RAW, { fields: { src: '10.0.0.1,dst=10.0.0.2,action=allow' }, errors: [] }, 'kv');
    expect(verdict.status).toBe('PARTIAL');
    expect(verdict.lostPairs.map(pair => pair.key)).toEqual(['src', 'dst', 'action']);
  });

  it('is not FULL when a value kept the delimiter that followed it', () => {
    const verdict = classifyStructuredParse('src=10.0.0.1, dst=10.0.0.2', { fields: { src: '10.0.0.1,', dst: '10.0.0.2' }, errors: [] }, 'kv');
    expect(verdict.status).toBe('PARTIAL');
    expect(verdict.lostPairs.map(pair => pair.key)).toEqual(['src']);
  });

  it('is FULL when every pair is a field with its own value', () => {
    const verdict = classifyStructuredParse(RAW, { fields: { src: '10.0.0.1', dst: '10.0.0.2', action: 'allow' }, errors: [] }, 'kv');
    expect(verdict).toEqual({ status: 'FULL', lostPairs: [], reasons: [] });
  });
});

// Independent audit of 2026-11-22. G-05: the reader split every unquoted value at a delimiter that a key
// follows, so an ordinary white-space separated line whose value holds ";charset=" or ",uid=" was no longer
// FULL (a regression of the first guard). G-01, G-02: in a line that is one token, a first value that holds
// "=" and a key written with other characters still hid the pairs behind them.
describe('a list delimiter inside a value of a white-space separated line is value data', () => {
  it.each([
    ['src=10.0.0.1 content_type=text/html;charset=utf-8 status=200',
      [['src', '10.0.0.1'], ['content_type', 'text/html;charset=utf-8'], ['status', '200']]],
    ['src=10.0.0.1 url=/app/login;jsessionid=AB12 status=200',
      [['src', '10.0.0.1'], ['url', '/app/login;jsessionid=AB12'], ['status', '200']]],
    ['dev=sda1 opts=rw,uid=1000,gid=1000 action=mount',
      [['dev', 'sda1'], ['opts', 'rw,uid=1000,gid=1000'], ['action', 'mount']]],
    ['<134>Nov 13 10:00:00 fw01 app: a=1 b=2;c=3', [['a', '1'], ['b', '2;c=3']]],
    ['msg="mounted" opts=rw,uid=1000', [['msg', 'mounted'], ['opts', 'rw,uid=1000']]],
  ])('%s', (raw, expected) => {
    expect(written(raw)).toEqual(expected);
  });

  it('is FULL when the grammar read each white-space separated pair', () => {
    const raw = 'src=10.0.0.1 content_type=text/html;charset=utf-8 status=200';
    const fields = { src: '10.0.0.1', content_type: 'text/html;charset=utf-8', status: '200' };
    expect(classifyStructuredParse(raw, { fields, errors: [] }, 'kv')).toEqual({ status: 'FULL', lostPairs: [], reasons: [] });
  });

  it('still takes a delimiter that ends a value before the next pair out of that value', () => {
    expect(written('src=10.0.0.1, dst=10.0.0.2 action=allow')).toEqual(THREE);
    expect(written('cookie=a=1; next=2')).toEqual([['cookie', 'a=1'], ['next', '2']]);
  });

  it('reads a line whose only gaps follow a delimiter as a list', () => {
    expect(written('src=10.0.0.1, opts=rw,uid=1000')).toEqual([['src', '10.0.0.1'], ['opts', 'rw'], ['uid', '1000']]);
  });
});

describe('pairs behind a list delimiter in a line that is one token', () => {
  it('are seen although the value before them holds "="', () => {
    expect(written('url=/login?user=bob,src=10.0.0.1,dst=10.0.0.2,action=allow'))
      .toEqual([['url', '/login?user=bob'], ...THREE]);
    expect(written('token=YWJjZA==,user=bob,src=10.0.0.1')).toEqual([['token', 'YWJjZA=='], ['user', 'bob'], ['src', '10.0.0.1']]);
    expect(written('<134>Nov 13 10:00:00 fw01 url=/login?user=bob;src=10.0.0.1')).toEqual([['url', '/login?user=bob'], ['src', '10.0.0.1']]);
  });

  it('are seen whatever characters their key is written with', () => {
    expect(written('src=10.0.0.1,사용자=bob,dst=10.0.0.2')).toEqual([['src', '10.0.0.1'], ['사용자', 'bob'], ['dst', '10.0.0.2']]);
    expect(written('a="x",사용자="y"|b[0]=4')).toEqual([['a', 'x'], ['사용자', 'y'], ['b[0]', '4']]);
  });

  it('reports a value that may be a list of its own as its pairs: one token does not say which it is', () => {
    expect(written('dn=CN=John,OU=Users,DC=corp')).toEqual([['dn', 'CN=John'], ['OU', 'Users'], ['DC', 'corp']]);
  });

  it('makes the event PARTIAL when the grammar kept the line as the value of the first key', () => {
    const raw = 'url=/login?user=bob,src=10.0.0.1,dst=10.0.0.2,action=allow';
    const verdict = classifyStructuredParse(raw, { fields: { url: raw.slice(4) }, errors: [] }, 'kv');
    expect(verdict.status).toBe('PARTIAL');
    expect(verdict.lostPairs.map(pair => pair.key)).toEqual(['url', 'src', 'dst', 'action']);
  });
});

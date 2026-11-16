/**
 * `ruby -e` arguments for a script of any size. One command line argument cannot exceed 128 KiB on Linux and a
 * generated parser is larger than that, so a long script is passed as several -e options at line breaks (Ruby
 * joins the -e options with line breaks, so the program is the same). A long Base64 literal on one line (a
 * parser embedded in a probe) is written as adjacent literals on continued lines, which Ruby concatenates.
 */
export function rubyE(script: string): string[] {
  const LIMIT = 60000;
  const wrapped = script.replace(/(['"])([A-Za-z0-9+/=]{30000,})\1/g, (_whole, quote: string, body: string) => {
    const parts: string[] = [];
    for (let at = 0; at < body.length; at += 30000) parts.push(quote + body.slice(at, at + 30000) + quote);
    return parts.join(' \\\n');
  });
  const args: string[] = [];
  let chunk: string[] = [];
  let size = 0;
  for (const line of wrapped.split('\n')) {
    const bytes = Buffer.byteLength(line, 'utf8') + 1;
    if (size + bytes > LIMIT && chunk.length) { args.push('-e', chunk.join('\n')); chunk = []; size = 0; }
    chunk.push(line);
    size += bytes;
  }
  args.push('-e', chunk.join('\n'));
  return args;
}

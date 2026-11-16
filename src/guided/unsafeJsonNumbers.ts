import {hasUnsafeJsonNumbers} from '../jsonNumberSafety';

/**
 * The numbers of a JSON text that the grammar declines to read (src/jsonNumberSafety.ts), as written, in source
 * order. The decision is taken by that module for each number; this function only finds the numbers, so the
 * explanation shown to a user can never name a number the grammar accepts.
 */
export function unsafeJsonNumberLexemes(source:string,limit=3):string[]{
  const found:string[]=[];
  let index=0;
  while(index<source.length&&found.length<limit){
    const current=source[index]!;
    if(current==='"'){
      index++;
      while(index<source.length){
        if(source[index]==='\\'){index+=2;continue;}
        if(source[index++]==='"')break;
      }
      continue;
    }
    if(current==='-'||(current>='0'&&current<='9')){
      const match=/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u.exec(source.slice(index));
      if(match){
        if(hasUnsafeJsonNumbers(match[0]))found.push(match[0]);
        index+=match[0].length;
        continue;
      }
    }
    index++;
  }
  return found;
}

/** The JSON object of an event: the whole event, or the text after a Syslog header. Null when there is none. */
export function jsonObjectOfEvent(raw:string):string|null{
  // The object may follow a header that itself holds a brace (structured data): try each opening brace in turn.
  let start=raw.indexOf('{');
  for(let tries=0;start>=0&&tries<8;tries++,start=raw.indexOf('{',start+1)){
    const text=raw.slice(start);
    try{
      const value:unknown=JSON.parse(text);
      if(value!==null&&typeof value==='object'&&!Array.isArray(value))return text;
    }catch{/* not the object of the event */}
  }
  return null;
}

/** One sentence for a user, or null when the event has no such number. */
export function unsafeJsonNumberExplanation(raw:string):string|null{
  const json=jsonObjectOfEvent(raw);
  if(json===null)return null;
  const numbers=unsafeJsonNumberLexemes(json);
  if(!numbers.length)return null;
  return 'This event holds '+(numbers.length===1?'a number':'numbers')+' that cannot be kept digit for digit: '+numbers.join(', ')+
    '. A browser and the parser runtime store such a number as the nearest value they can hold, so Parser Studio does not build a parser that would change it. '+
    'Nothing was discarded. A parsing rule cannot repair this; a sender that writes the number as text (in quotes) does not have the problem.';
}

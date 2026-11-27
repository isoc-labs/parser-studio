import {useState} from 'react';
import {describe,it,expect,vi} from 'vitest';
import {render,screen,fireEvent} from '@testing-library/react';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import ChatGPTAssist from './ChatGPTAssist';
import {parserExportSettings,parserIdentitySlug,withParserExportSettings} from './parserIdentity';

// The manufacturer, product, version and .conf port name and address the created files. They are not parsing
// rules: editing them must not discard the pasted ChatGPT result or its checks. The prompt embeds the names and
// the version, so it is withdrawn while they differ from what it was prepared with; it does not embed the port.
// The original logs are a parsing input: editing them still starts over.
const sample='date=2026-10-15 time=00:04:12 devname="FGT-EDGE01" action="blocked" srcip=10.0.0.10 dstip=10.0.0.20 dstport=443';

const unnamed=():ParserDraft=>({...createDraft(),format:'kv' as const});
/** A draft named the way the identity card names it (the file name follows the names). */
const named=(vendor:string,name:string):ParserDraft=>withParserExportSettings(unnamed(),
  {...parserExportSettings(unnamed()),vendor,name,slug:parserIdentitySlug(vendor,name)});

function Harness({initial}:{initial:ParserDraft}){
  const [draft,setDraft]=useState(initial);
  const [source,setSource]=useState(sample);
  return <ChatGPTAssist draft={draft} setDraft={setDraft} sample={source}
    setSample={setSource} namedLogTypes={null}
    onEnableNamedLogTypes={vi.fn()} onChangeNamedLogTypes={vi.fn()}
    onExitNamedLogTypes={vi.fn()} suite={preview(source,draft)} pending={false}
    runPreview={async(next,text)=>preview(text??source,next)} onAutoParser={vi.fn()}/>;
}
const response=()=>screen.getByLabelText('ChatGPT result JSON') as HTMLTextAreaElement;
const apply=()=>screen.getByRole('button',{name:'Apply Fix & Create Parser Files'}) as HTMLButtonElement;
/** One change event per character, as a keyboard produces them; the field is looked up again each time. */
function typeInto(label:string,text:string){
  for(let length=1;length<=text.length;length++)
    fireEvent.change(screen.getByLabelText(label),{target:{value:text.slice(0,length)}});
}
async function acceptBaselineRecipe(){
  fireEvent.click(screen.getByRole('button',{name:'Prepare ChatGPT Prompt'}));
  const prompt=await screen.findByLabelText('ChatGPT copyable prompt') as HTMLTextAreaElement;
  const begin='----- BEGIN VALIDATED BASELINE RECIPE -----',end='----- END VALIDATED BASELINE RECIPE -----';
  const recipe=prompt.value.slice(prompt.value.indexOf(begin)+begin.length,prompt.value.indexOf(end)).trim();
  fireEvent.change(response(),{target:{value:recipe}});
  fireEvent.click(screen.getByRole('button',{name:'Check ChatGPT Result'}));
  await screen.findByText(/ChatGPT result accepted for testing/i);
  return {prompt:prompt.value,recipe};
}

describe('ChatGPT Assisted Parser: parser details are not parsing inputs',()=>{
  it('keeps the pasted result and its acceptance while the real names are typed afterwards',async()=>{
    render(<Harness initial={unnamed()}/>);
    const before=await acceptBaselineRecipe();
    expect(apply().disabled).toBe(true);
    expect(screen.getByRole('note',{name:/placeholder/i})).toHaveTextContent('Demo Local Draft');

    typeInto('Parser manufacturer','Fortinet');
    typeInto('Parser product','FortiGate');
    typeInto('Parser product version','7.4.5');

    expect((screen.getByLabelText('Parser manufacturer') as HTMLInputElement).value).toBe('Fortinet');
    expect((screen.getByLabelText('Parser product') as HTMLInputElement).value).toBe('FortiGate');
    // The prompt was prepared without these names: it is no longer offered, and says why.
    expect(screen.queryByLabelText('ChatGPT copyable prompt')).toBeNull();
    expect(screen.getByRole('note',{name:'ChatGPT prompt out of date'})).toHaveTextContent(/result you already pasted and its checks are kept/i);
    expect(response().value).toBe(before.recipe);
    expect(screen.getByText(/ChatGPT result accepted for testing/i)).toBeInTheDocument();
    expect(screen.queryByRole('note',{name:/placeholder/i})).toBeNull();
    expect(apply().disabled).toBe(false);
  });
  it('keeps the session when only the .conf port changes',async()=>{
    render(<Harness initial={named('Fortinet','FortiGate')}/>);
    const before=await acceptBaselineRecipe();
    fireEvent.change(screen.getByRole('spinbutton',{name:'Parser listener port'}),{target:{value:'7514'}});
    expect((screen.getByLabelText('ChatGPT copyable prompt') as HTMLTextAreaElement).value).toBe(before.prompt);
    expect(response().value).toBe(before.recipe);
    expect(screen.getByText(/ChatGPT result accepted for testing/i)).toBeInTheDocument();
    expect(apply().disabled).toBe(false);
  });
  it('blocks file creation again, without discarding the result, when a name is cleared',async()=>{
    render(<Harness initial={named('Fortinet','FortiGate')}/>);
    const before=await acceptBaselineRecipe();
    fireEvent.change(screen.getByLabelText('Parser product'),{target:{value:''}});
    expect(apply().disabled).toBe(true);
    expect(screen.getByRole('note',{name:/placeholder/i})).toHaveTextContent(/product/i);
    expect(response().value).toBe(before.recipe);
    expect(screen.queryByLabelText('ChatGPT copyable prompt')).toBeNull();
    typeInto('Parser product','FortiGate');
    expect(apply().disabled).toBe(false);
    // The names are again the ones the prompt was prepared with: the same prompt is offered again.
    expect((screen.getByLabelText('ChatGPT copyable prompt') as HTMLTextAreaElement).value).toBe(before.prompt);
  });
  it('still starts over when the original logs change',async()=>{
    render(<Harness initial={named('Fortinet','FortiGate')}/>);
    await acceptBaselineRecipe();
    fireEvent.change(screen.getByLabelText('ChatGPT local sample logs'),{target:{value:sample+'\n'+sample.replace('443','8443')}});
    expect(screen.queryByLabelText('ChatGPT copyable prompt')).toBeNull();
    expect(response().value).toBe('');
    expect(screen.queryByText(/ChatGPT result accepted for testing/i)).toBeNull();
  });
  it('keeps the prompt editor on the page while its text is cleared and typed again',async()=>{
    render(<Harness initial={named('Fortinet','FortiGate')}/>);
    await acceptBaselineRecipe();
    fireEvent.change(screen.getByLabelText('ChatGPT copyable prompt'),{target:{value:''}});
    expect(screen.getByLabelText('ChatGPT copyable prompt')).toBeInTheDocument();
    typeInto('ChatGPT copyable prompt','redacted prompt');
    expect((screen.getByLabelText('ChatGPT copyable prompt') as HTMLTextAreaElement).value).toBe('redacted prompt');
  });
});

describe('parser export settings',()=>{
  it('carries exactly the details the identity card edits onto another draft and leaves its rules alone',()=>{
    const rules={...createDraft(),format:'kv' as const,vendor:'Demo Local Draft',name:'Untitled parser'};
    const named={...createDraft(),vendor:'Fortinet',name:'FortiGate',version:'7.4.5'};
    named.guided={...named.guided!,slug:'fortinet_fortigate',receiver:{...named.guided!.receiver,port:7514}};
    const merged=withParserExportSettings(rules,parserExportSettings(named));
    expect(parserExportSettings(merged)).toEqual({vendor:'Fortinet',name:'FortiGate',version:'7.4.5',
      slug:'fortinet_fortigate',port:7514});
    expect({...merged,vendor:rules.vendor,name:rules.name,version:rules.version,guided:rules.guided})
      .toEqual(rules);
    expect({...merged.guided,slug:rules.guided!.slug,receiver:rules.guided!.receiver}).toEqual(rules.guided);
    expect({...merged.guided!.receiver,port:rules.guided!.receiver.port}).toEqual(rules.guided!.receiver);
  });
});

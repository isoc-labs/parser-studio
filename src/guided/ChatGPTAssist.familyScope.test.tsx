import {describe,expect,it,vi} from 'vitest';
import {useState} from 'react';
import {render,screen,fireEvent,act,waitFor} from '@testing-library/react';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';
import ChatGPTAssist from './ChatGPTAssist';

// ChatGPT Assisted on a draft with event profiles: the user picks one event type, the prompt is prepared from
// that type's original lines only, and the other types keep their parsing. SYNTHETIC lines after documented formats.
const PAN='<14>Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51514,443,62001,443,0x400053,tcp,allow,1840,1200,640,12,2026/10/15 00:03:01,20,any,0,987654321,0x0,10.0.0.0-10.255.255.255,United States,0,7,5,aged-out,0,0,0,0,vsys1,PA-FW01,from-policy';
const PAN2=PAN.replace('10.10.20.15','10.10.20.16');
const CEF='CEF:0|Vendor|Product|1.0|100|Login|5|src=10.0.0.7 dst=10.0.0.8 spt=51234 dpt=443 act=allow';
const CEF2=CEF.replace('10.0.0.7','10.0.0.9');
const OTHER='<14>Oct 15 00:03:22 PA-FW01 {"srcip":"10.9.9.9","action":"allow"}';

function routed():ParserDraft{
  const built=buildAutomaticGenericStructuralDraft([PAN,CEF,PAN2,CEF2].join('\n'),createDraft());
  expect(built?.draft.eventProfiles).toBeDefined();
  return built!.draft;
}

describe('ChatGPT Assisted on a draft with event profiles',()=>{
  it('offers each event type as a scope and prepares the prompt from the selected type only',async()=>{
    const source=[PAN,CEF,OTHER,PAN2].join('\n');
    const draft=routed();
    function Harness(){
      const [current,setCurrent]=useState<ParserDraft>(draft);
      return <ChatGPTAssist draft={current} setDraft={setCurrent} sample={source} setSample={vi.fn()}
        suite={preview(source,current)} pending={false}
        runPreview={async(candidate,text)=>preview(text??source,candidate)} onAutoParser={vi.fn()}/>;
    }
    await act(async()=>{render(<Harness/>);});
    const scope=screen.getByLabelText('ChatGPT event type scope') as HTMLSelectElement;
    expect([...scope.options].map(option=>option.value))
      .toEqual(['panos_traffic_csv','structured_family_cef','unrecognized']);
    // The first type that is not read completely is selected first.
    expect(scope.value).toBe('unrecognized');
    expect((screen.getByLabelText('ChatGPT local sample logs') as HTMLTextAreaElement).value).toBe(OTHER);
    expect(screen.queryByText(/does not represent type-specific mappings/)).toBeNull();
    fireEvent.change(scope,{target:{value:'structured_family_cef'}});
    expect((screen.getByLabelText('ChatGPT local sample logs') as HTMLTextAreaElement).value).toBe(CEF);
    const prepareButton=await screen.findByRole('button',{name:'Prepare ChatGPT Prompt'});
    await waitFor(()=>expect((prepareButton as HTMLButtonElement).disabled).toBe(false));
    await act(async()=>{fireEvent.click(prepareButton);});
    const prompt=await screen.findByLabelText('ChatGPT copyable prompt') as HTMLTextAreaElement;
    expect(prompt.value).toContain(CEF);
    expect(prompt.value).not.toContain(PAN);
    expect(prompt.value).not.toContain(OTHER);
    // The prompt describes every event type of the parser and the types still to support.
    expect(prompt.value).toContain('Improve only event type structured_family_cef');
    expect(prompt.value).toContain('Event types still to support: unrecognized (1 record)');
    // The routed parser for every event type stays available for generation.
    expect(screen.getByLabelText('Approved conditional parser')).toBeTruthy();
  });
});

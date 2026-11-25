import {describe,expect,it} from 'vitest';
import {useState} from 'react';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';
import JsonataMappingAssistant from './JsonataMappingAssistant';

// P4: ChatGPT mapping on a parser with event profiles works on one event type and changes only that type.
// The pasted reply is written by this test, not by ChatGPT. SYNTHETIC lines after documented formats.
const PAN='<14>Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51514,443,62001,443,0x400053,tcp,allow,1840,1200,640,12,2026/10/15 00:03:01,20,any,0,987654321,0x0,10.0.0.0-10.255.255.255,United States,0,7,5,aged-out,0,0,0,0,vsys1,PA-FW01,from-policy';
const CEF='CEF:0|Vendor|Product|1.0|100|Login|5|src=10.0.0.7 dst=10.0.0.8 spt=51234 dpt=443 act=allow';
const FULL=[PAN,CEF,PAN.replace('10.10.20.15','10.10.20.16'),CEF.replace('10.0.0.7','10.0.0.9')].join('\n');

describe('ChatGPT JSONata mapping on a parser with event profiles',()=>{
  it('maps a field of the selected event type only',async()=>{
    const routed=buildAutomaticGenericStructuralDraft(FULL,createDraft())!.draft;
    let latest:ParserDraft=routed;
    function Harness(){
      const [draft,setDraft]=useState(routed);
      latest=draft;
      return <JsonataMappingAssistant draft={draft} setDraft={setDraft} suite={preview(FULL,draft)} pending={false}/>;
    }
    render(<Harness/>);
    fireEvent.click(screen.getByRole('button',{name:'Improve mappings with ChatGPT JSONata'}));
    const scope=screen.getByLabelText('ChatGPT mapping event type scope') as HTMLSelectElement;
    expect([...scope.options].map(option=>option.value)).toEqual(['panos_traffic_csv','structured_family_cef']);
    fireEvent.change(scope,{target:{value:'structured_family_cef'}});
    fireEvent.click(screen.getByRole('button',{name:'Prepare Mapping Prompt'}));
    const area=await screen.findByLabelText('ChatGPT JSONata mapping prompt') as HTMLTextAreaElement;
    expect(area.value).toContain('Improve only event type structured_family_cef');
    // The source fields offered for mapping are those of the selected type only.
    const fields=area.value.split('\n\n').find(part=>part.startsWith('Available parsed source field names'))!;
    expect(fields).toContain('body.cef_name');
    expect(fields).not.toContain('generic.fields.natsrc');
    const sha=/"sha256": "([a-f0-9]{64})"/.exec(area.value)![1]!;
    fireEvent.change(screen.getByLabelText('Paste ChatGPT JSONata mapping response'),{target:{value:JSON.stringify(
      {contract:'parser-studio.mapping-jsonata.v0.1',sample:{sha256:sha,events:2},mappings:[{expression:'body.cef_name',target:'event_name'}]})}});
    fireEvent.click(screen.getByRole('button',{name:'Check JSONata Mappings'}));
    await waitFor(()=>expect(screen.getByLabelText('Reviewed ChatGPT JSONata mappings')).toHaveTextContent('event_name'));
    const row=screen.getByLabelText('Approve JSONata mapping body.cef_name to event_name') as HTMLInputElement;
    if(!row.checked)fireEvent.click(row);
    fireEvent.click(screen.getByLabelText('I reviewed the selected JSONata mappings'));
    const uncertain=screen.queryByLabelText('I confirm uncertain mapping meanings');
    if(uncertain)fireEvent.click(uncertain);
    fireEvent.click(screen.getByRole('button',{name:'Apply 1 Reviewed Mapping'}));
    await waitFor(()=>expect(screen.getByRole('status')).toHaveTextContent('structured_family_cef'));
    const variants=latest.eventProfiles!.variants;
    const cef=variants.find(variant=>variant.name==='structured_family_cef')!;
    expect(cef.mappings.filter(rule=>rule.source==='body.cef_name').map(rule=>rule.target)).toEqual(['event_name']);
    expect(variants.find(variant=>variant.name==='panos_traffic_csv')!.mappings)
      .toEqual(routed.eventProfiles!.variants.find(variant=>variant.name==='panos_traffic_csv')!.mappings);
    expect(latest.mappings).toEqual(routed.mappings);
    const after=preview(FULL,latest).events.map(event=>(event.normalized as Record<string,unknown>).event_name);
    expect(after).toEqual([undefined,'Login',undefined,'Login']);
  });
});

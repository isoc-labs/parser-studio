import {useState} from 'react';
import {act,fireEvent,render,screen} from '@testing-library/react';
import {describe,it,expect,vi} from 'vitest';
import {preview} from '../parser';
import {createDraft,type MappingRule,type ParserDraft} from '../model';
import {defaultGuidedOptions} from './contract';
import NormalizationMappingReview from './NormalizationMappingReview';

function build(vendorCount:number){
  const record:Record<string,string|number>={src_ip:'192.0.2.10'};
  const mappings:MappingRule[]=[{id:'m-ip',source:'src_ip',target:'srcip',type:'ip'}];
  const groups:Record<string,'top_fields'|'vendor_fields'>={'m-ip':'top_fields'};
  for(let i=0;i<vendorCount;i++){
    record['vf_'+i]='v'+i;
    mappings.push({id:'m-'+i,source:'vf_'+i,target:'vf_'+i,type:'string'});
    groups['m-'+i]='vendor_fields';
  }
  const sample=JSON.stringify(record);
  const draft:ParserDraft={...createDraft(),format:'json',mappings,guided:{...defaultGuidedOptions(),groups}};
  return {sample,draft};
}

function Harness({vendorCount}:{vendorCount:number}){
  const built=build(vendorCount);
  const [draft,setDraft]=useState(built.draft);
  const suite=preview(built.sample,draft);
  return <NormalizationMappingReview draft={draft} setDraft={setDraft} suite={suite}
    selected={0} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>;
}

describe('Map Fields vendor-only list',()=>{
  it('folds a long vendor-only list behind one summary and keeps the matched field visible',()=>{
    const {container}=render(<Harness vendorCount={14}/>);
    const details=container.querySelector('details.normalization-vendor-list') as HTMLDetailsElement;
    expect(details).not.toBeNull();
    expect(details.open).toBe(false);
    expect(details.querySelector('summary')).toHaveTextContent('Vendor-only fields (14)');
    // the Stellar-matched row sits outside the folded list
    expect(details.querySelector('[aria-label="Field mapping 1"]')).toBeNull();
    expect(screen.getByLabelText('Source field 0')).toHaveValue('src_ip');
    // folded rows are still in the page, with their original numbering
    expect(details.querySelector('[aria-label="Field mapping 15"]')).not.toBeNull();
  });

  it('keeps the list open once the user opened it, even after a row is left out',()=>{
    const {container}=render(<Harness vendorCount={14}/>);
    const details=container.querySelector('details.normalization-vendor-list') as HTMLDetailsElement;
    details.open=true;
    fireEvent(details,new Event('toggle'));
    fireEvent.click(screen.getByRole('button',{name:'Remove normalization 3'}));
    const after=container.querySelector('details.normalization-vendor-list') as HTMLDetailsElement;
    expect(after.open).toBe(true);
    expect(after.querySelector('summary')).toHaveTextContent('Vendor-only fields (13)');
  });

  // The list a row is shown in follows its destination (matched fields first, vendor-only fields folded). While
  // the destination is being typed the row must stay where it is: "dstip" is an official name on the way to
  // "dstip_host", and "srcip_" is not one on the way to "srcip_host".
  it('keeps a vendor row in place while an official name is typed key by key, then lists it with the matched fields',()=>{
    const {container}=render(<Harness vendorCount={14}/>);
    const details=container.querySelector('details.normalization-vendor-list') as HTMLDetailsElement;
    details.open=true;
    fireEvent(details,new Event('toggle'));
    const input=screen.getByLabelText('Stellar field 3') as HTMLInputElement;
    act(()=>input.focus());
    const text='dstip_host';
    for(let length=1;length<=text.length;length++){
      fireEvent.change(input,{target:{value:text.slice(0,length)}});
      expect(input.isConnected,text.slice(0,length)).toBe(true);
      expect(document.activeElement,text.slice(0,length)).toBe(input);
    }
    expect(input).toHaveValue('dstip_host');
    expect(details.contains(input)).toBe(true);
    act(()=>input.blur());
    const listed=screen.getByLabelText('Stellar field 3');
    expect(listed).toHaveValue('dstip_host');
    expect(container.querySelector('details.normalization-vendor-list')!.contains(listed)).toBe(false);
    expect(container.querySelector('details.normalization-vendor-list summary')).toHaveTextContent('Vendor-only fields (13)');
  },30_000);

  it('keeps a matched row in place while its name passes through text that is not an official name',()=>{
    const {container}=render(<Harness vendorCount={14}/>);
    const input=screen.getByLabelText('Stellar field 0') as HTMLInputElement;
    act(()=>input.focus());
    for(const text of ['srcip_','srcip_h','srcip_ho','srcip_hos','srcip_host']){
      fireEvent.change(input,{target:{value:text}});
      expect(input.isConnected,text).toBe(true);
      expect(document.activeElement,text).toBe(input);
      expect(container.querySelector('details.normalization-vendor-list')!.contains(input),text).toBe(false);
    }
    expect(input).toHaveValue('srcip_host');
  },30_000);

  it('does not fold a short list, so small samples look exactly as before',()=>{
    const {container}=render(<Harness vendorCount={5}/>);
    expect(container.querySelector('details.normalization-vendor-list')).toBeNull();
    expect(screen.getByLabelText('Source field 5')).toHaveValue('vf_4');
  });
});

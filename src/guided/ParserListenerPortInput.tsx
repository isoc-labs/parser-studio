import {useState,type Dispatch,type SetStateAction} from 'react';
import type {ParserDraft} from '../model';
import {DEFAULT_PARSER_LISTENER_PORT,defaultGuidedOptions} from './contract';

interface Props {
  draft:ParserDraft;
  setDraft:Dispatch<SetStateAction<ParserDraft>>;
}

/** One user-selected receiving port is shared by both creation methods and the compiled CONF. */
export default function ParserListenerPortInput({draft,setDraft}:Props){
  const minimum=['syslog_rfc3164','syslog_rfc5424','generic_structural'].includes(draft.format)||
    (draft.format==='mixed'&&draft.mixedFormats?.some(format=>
      format.startsWith('rfc5424_')||format.startsWith('rfc3164_')))?6800:1024;
  const port=draft.guided?.receiver.port??DEFAULT_PARSER_LISTENER_PORT;
  const valid=Number.isInteger(port)&&port>=minimum&&port<=65535;
  // While the field is edited it shows the text as typed. The port is a number, so an emptied field cannot be
  // shown from it (it would read "0" and the next digits would follow that zero); the number is derived from
  // the text, never the other way round, until the field is left or the port is changed from elsewhere.
  const [typed,setTyped]=useState<string|null>(null);
  return <label>Parser listener port (.conf)
    <input aria-label="Parser listener port" type="number" min={minimum} max={65535} step={1}
      value={typed!==null&&Number(typed)===port?typed:port} aria-invalid={!valid}
      onBlur={()=>setTyped(null)}
      onChange={event=>{
        const text=event.currentTarget.value;
        setTyped(text);
        const changed=Number(text);
        setDraft(old=>{
          const guided=old.guided??defaultGuidedOptions();
          return {...old,guided:{...guided,receiver:{...guided.receiver,port:changed}}};
        });
      }}/>
    <small>Default 6801. Shared sensor destination and generated .conf receiving port. Check availability before deployment.</small>
    {!valid&&<small role="alert">Enter an integer port from {minimum} to 65535 before creating parser files.</small>}
  </label>;
}

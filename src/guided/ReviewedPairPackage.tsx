import {useLayoutEffect,useRef,useState} from 'react';
import {FileArchive} from 'lucide-react';
import type {GeneratedPair} from './backendClient';
import type {BackendCapabilities} from './backendCapabilities';
import {packageGeneratedPair,type CheckedArtifactZip} from './artifactPackageClient';

/** A package is derived from the already verified pair, never a new compilation.
 * Mount with a key tied to the current reviewed artifact and source identity.
 */
export default function ReviewedPairPackage({pair,capabilities,port,disabled=false,showChecksum=false}:{
  pair:GeneratedPair;capabilities:BackendCapabilities;port:number;disabled?:boolean;showChecksum?:boolean;
}){
  const [busy,setBusy]=useState(false);
  const [result,setResult]=useState<CheckedArtifactZip|null>(null);
  const [error,setError]=useState('');
  const epoch=useRef(0);
  useLayoutEffect(()=>{setBusy(false);setResult(null);setError('');return ()=>{epoch.current++;};},[pair,capabilities,port]);
  async function save(){
    if(busy||disabled)return;
    const token=++epoch.current;
    setBusy(true);setError('');setResult(null);
    try{
      const archive=await packageGeneratedPair(pair,'1.0.0',capabilities,port);
      if(token!==epoch.current)return;
      const url=URL.createObjectURL(new Blob([archive.bytes],{type:'application/zip'}));
      const link=document.createElement('a');
      link.href=url;link.download=archive.filename;
      document.body.append(link);link.click();link.remove();
      window.setTimeout(()=>URL.revokeObjectURL(url),1000);
      setResult(archive);
    }catch{
      if(token===epoch.current)setError('ZIP verification failed; the two original DRAFT files remain available.');
    }finally{if(token===epoch.current)setBusy(false);}
  }
  return <>
    <button type="button" className="auto-parser-secondary" disabled={busy||disabled}
      onClick={()=>{void save();}}><FileArchive size={16}/> {busy?'Verifying package…':'Download Parser Package'}</button>
    {error&&<p role="alert">{error}</p>}
    {showChecksum&&result&&<details className="auto-parser-recipe">
      <summary>Package checksum</summary><small>ZIP SHA-256: {result.sha256} · {result.filename}</small>
    </details>}
  </>;
}

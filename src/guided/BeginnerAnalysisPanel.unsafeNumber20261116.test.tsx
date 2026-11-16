import {describe,it,expect,vi} from 'vitest';
import {render,screen} from '@testing-library/react';
import BeginnerAnalysisPanel from './BeginnerAnalysisPanel';
import type {MultiPassSourcePreview} from './multipassPreviewClient';

// A JSON event with a number that cannot be kept exactly is declined by the grammar. The step must say which
// number and must not send the user to a parsing rule, which cannot repair it.
const preview=(source:string,status:MultiPassSourcePreview['status'],issues:string[]):MultiPassSourcePreview=>({
  contract:'parser-studio.multipass-source-preview.v0.1',
  status,syntax:'JSON',sourceSha256:'0'.repeat(64),sourceBytes:new TextEncoder().encode(source).byteLength,
  fields:status==='SOURCE_PARSED'?{EventID:4625}:{},spans:[],residuals:[],issues,
  nativeVerified:false,targetVerified:false,
});
const bytes=(text:string)=>new TextEncoder().encode(text).byteLength;

describe('Add Logs names the JSON number the grammar declines',()=>{
  it('when the source preview read the event and the browser grammar declines it',()=>{
    const source='{"EventID":4625,"Keywords":-9218868437227405312,"Hostname":"DC01"}';
    render(<BeginnerAnalysisPanel source={source}
      events={[{startByte:0,endByte:bytes(source),preview:preview(source,'SOURCE_PARSED',[])}]}
      onOpenAssisted={vi.fn()} parserRuleReviewRequired parserRuleReviewEventIndexes={[0]}/>);
    const summary=screen.getByLabelText('Beginner analysis summary');
    expect(summary).toHaveTextContent('an event holds a number that cannot be kept exactly');
    expect(summary).not.toHaveTextContent('Use Fix with ChatGPT');
    expect(screen.getByText(/cannot be kept digit for digit: -9218868437227405312\./)).toBeTruthy();
    expect(screen.getByText(/A parsing rule cannot repair this/)).toBeTruthy();
  });
  it('when the source preview itself reports the number',()=>{
    const source='{"ts":1731719701.12345678,"uid":"C1"}';
    render(<BeginnerAnalysisPanel source={source}
      events={[{startByte:0,endByte:bytes(source),
        preview:preview(source,'RAW_ONLY',['SOURCE_SYNTAX_ERROR:JSON_NUMBER_PRECISION_UNSAFE'])}]}
      onOpenAssisted={vi.fn()}/>);
    expect(screen.getByText(/cannot be kept digit for digit: 1731719701\.12345678\./)).toBeTruthy();
  });
  it('keeps the general wording for an event without such a number',()=>{
    const source='{"EventID":4625,"Hostname":"DC01"}';
    render(<BeginnerAnalysisPanel source={source}
      events={[{startByte:0,endByte:bytes(source),preview:preview(source,'SOURCE_PARSED',[])}]}
      onOpenAssisted={vi.fn()} parserRuleReviewRequired parserRuleReviewEventIndexes={[0]}/>);
    expect(screen.getByLabelText('Beginner analysis summary')).toHaveTextContent('Use Fix with ChatGPT');
    expect(screen.queryByText(/cannot be kept digit for digit/)).toBeNull();
    expect(screen.getByText(/has not yet validated a downloadable parser rule/)).toBeTruthy();
  });
});

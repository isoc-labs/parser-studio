import {enterSyntheticParserIdentity} from './support/parserIdentity';
import {test,expect} from './support/downloadSink';
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
const root='tests/fixtures/vendor-holdout-20261116';
const dispositions=JSON.parse(readFileSync('contracts/vendor-holdout-disposition.v1.json','utf8')) as Record<string,string>;
test.describe.configure({mode:'parallel'});
for(const [id,status] of Object.entries(dispositions)){
  const title=status==='AUTO_DOWNLOAD'?'holdout actual parser download ':'holdout explicit incomplete outcome ';
  test(title+id,async({page})=>{
    test.setTimeout(60000);
    const raw=readFileSync(join(root,id,'raw.log'),'utf8').replace(/\n+$/u,'');
    await page.goto('/');
    if(id!=='h_checkpoint_logexporter')await enterSyntheticParserIdentity(page);
    const input=page.getByLabel('Auto Parser raw logs');
    await input.fill(raw);
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    const review=page.getByRole('button',{name:'Review Fields',exact:true});
    if(status==='AUTO_DOWNLOAD'){
      await expect(review).toBeEnabled({timeout:20000});
      await review.click();
      await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
      await page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser'}).click();
      const create=page.getByRole('button',{name:'Create Parser Files'});
      if(id==='h_checkpoint_logexporter'){
        await expect(create).toBeDisabled();
        await expect(page.getByLabel('Placeholder parser name')).toContainText('Downloaded files are blocked');
        await expect(page.getByLabel('Generated parser files')).toHaveCount(0);
        await enterSyntheticParserIdentity(page);
        await expect(create).toBeEnabled({timeout:20000});
      }
      await create.click();
      const files=page.getByLabel('Generated parser files');
      await expect(files).toContainText('Parser files created successfully',{timeout:20000});
      const download=page.waitForEvent('download');
      await files.getByRole('button',{name:/customized_[a-z0-9_]+$/}).click();
      expect(readFileSync((await (await download).path())!,'utf8').length).toBeGreaterThan(0);
    }else{
      // These cases are explicitly not counted as successful parser generation.
      // Precision refusal and currently unsupported grammar must remain visible,
      // with the full source still available for the user's next step.
      if(id==='h_pfsense_filterlog'){
        await expect(review).toBeEnabled({timeout:20000});
        await review.click();
        await expect(page.getByRole('alert',{name:'Parser draft not ready'})).toBeVisible();
      }else{
        await expect(page.getByLabel('Beginner analysis summary')).toBeVisible({timeout:20000});
        await expect(review).toBeDisabled();
      }
      if(status==='PRECISION_REFUSAL')
        await expect(page.getByLabel('Beginner analysis summary')).toContainText('cannot be kept exactly');
      else
        await expect(page.getByText(/Fix with ChatGPT|Use ChatGPT Assisted Parser/).first()).toBeVisible();
      await expect(input).toHaveValue(raw);
      await expect(page.getByLabel('Generated parser files')).toHaveCount(0);
    }
  });
}


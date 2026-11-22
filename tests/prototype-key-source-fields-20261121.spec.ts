import {test,expect} from '@playwright/test';

// Issue #315: valid tagged Syslog key=value events whose field is named like an
// Object.prototype member used to end in "could not complete analysis".
const KEYS=['toString','valueOf','hasOwnProperty','normalKey'];

for(const key of KEYS){
  test('tagged Syslog KV with a source field named '+key+' is analyzed, reviewed and mapped',async({page})=>{
    const raw=[
      '<134>Nov 16 10:15:04 web01 portal: '+key+'="x",src="203.0.113.5",dst="10.1.1.9",port="443",result="ok",user="bob"',
      '<134>Nov 16 10:15:05 web01 portal: '+key+'="y",src="203.0.113.6",dst="10.1.1.9",port="443",result="ok",user="eve"',
    ].join('\n');
    await page.goto('/');
    await page.getByLabel('Auto Parser raw logs').fill(raw);
    await page.getByRole('button',{name:'Analyze Logs'}).click();
    await expect(page.getByLabel('Beginner analysis summary'))
      .toContainText('2 of 2 log events structurally parsed',{timeout:15_000});
    await expect(page.getByText('Parser Studio could not complete analysis')).toHaveCount(0);

    const review=page.getByRole('button',{name:'Review Fields',exact:true});
    await expect(review).toBeEnabled({timeout:10_000});
    await review.click();
    await expect(page.getByLabel('Review Fields stage')).toBeVisible();
    const map=page.getByRole('button',{name:'Map Fields',exact:true});
    await expect(map).toBeEnabled({timeout:10_000});
    await map.click();
    await expect(page.getByLabel('Map Fields stage')).toBeVisible();

    const editor=page.getByLabel('Field mapping editor');
    const row=(source:string)=>editor.locator('article.normalization-map-row[data-source-path="'+source+'"]');
    // The quoted comma list is read by the key=value list grammar, so the fields are the fields of the Syslog
    // body (until 88c0768 the bounded compiler read the line and they were generic.fields.*).
    // The source key keeps its own name; it is neither renamed nor dropped.
    await expect(row('body.'+key)).toHaveCount(1);
    await expect(row('body.'+key).locator('input[aria-label^="Stellar field "]')).toHaveValue(key);
    // Neighbouring fields keep their official meaning.
    await expect(row('body.src').locator('input[aria-label^="Stellar field "]')).toHaveValue('srcip');
    await expect(row('body.dst').locator('input[aria-label^="Stellar field "]')).toHaveValue('dstip');

    // Both values of the field reach the browser output preview under the unchanged name.
    const preview=page.getByLabel('Final event preview');
    await expect(preview).toContainText('"'+key+'": "x"');
    await page.getByLabel('Source field event').selectOption({index:1});
    await expect(preview).toContainText('"'+key+'": "y"');
  });
}

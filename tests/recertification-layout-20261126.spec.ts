import {test,expect,type Page} from '@playwright/test';

// The application is max-width constrained: viewport width alone cannot
// determine the space available to a mapping editor inside three columns.
const SUPPORTED='<166>Nov 26 2026 09:12:01 fw01 : %ASA-6-302013: Built outbound TCP connection 7345 for outside:203.0.113.10/443 (203.0.113.10/443) to inside:10.1.1.5/52044 (198.51.100.7/61012)';
const UNSUPPORTED='kernel panic - not syncing: fatal exception in interrupt '+ 'long_value_'.repeat(80);

test.skip(process.env.PARSER_STUDIO_LIVE_BACKEND!=='1'||process.env.PARSER_STUDIO_TEST_MULTIPASS!=='1',
  'Requires the same-head authoring backend and analysis service.');

async function assertLayout(page:Page, selector:string){
  const issues=await page.evaluate(selector=>{
    const result:string[]=[];
    const visible=(e:Element)=>{
      const r=e.getBoundingClientRect(),s=getComputedStyle(e);
      return r.width>2&&r.height>2&&s.display!=='none'&&s.visibility!=='hidden';
    };
    if(document.documentElement.scrollWidth>innerWidth+2)result.push('page-horizontal-overflow');
    for(const el of document.querySelectorAll(selector)){
      if(!visible(el))continue;
      const r=el.getBoundingClientRect();
      if(r.left< -2||r.right>innerWidth+2)result.push('viewport escape '+el.className);
      const kids=[...el.children].filter(child=>visible(child)&&!['absolute','fixed'].includes(getComputedStyle(child).position));
      for(const child of kids){
        const c=child.getBoundingClientRect();
        if(c.left<r.left-2||c.right>r.right+2)result.push('child escape '+el.className+' / '+child.tagName);
      }
      const css=getComputedStyle(el);
      if(/grid|flex/.test(css.display))for(let i=0;i<kids.length;i++)for(let j=i+1;j<kids.length;j++){
        const a=kids[i]!.getBoundingClientRect(),b=kids[j]!.getBoundingClientRect();
        if(Math.min(a.right,b.right)-Math.max(a.left,b.left)>3&&Math.min(a.bottom,b.bottom)-Math.max(a.top,b.top)>3)
          result.push('overlap '+el.className+' / '+kids[i]!.tagName+' / '+kids[j]!.tagName);
      }
    }
    return result;
  },selector);
  expect(issues).toEqual([]);
}

for(const width of [1024,1280,1440,1920]){
  test('responsive recovery and mapping workspace '+width,async({page})=>{
    test.setTimeout(90000);
    await page.setViewportSize({width,height:900});
    await page.goto('/');
    await page.getByLabel('Parser manufacturer').fill('Cisco');
    await page.getByLabel('Parser product',{exact:true}).fill('ASA');
    await page.getByLabel('Auto Parser raw logs').fill(SUPPORTED+'\n'+UNSUPPORTED);
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    const offer=page.getByLabel('Readable events',{exact:true});
    await expect(offer).toContainText('1 of 2 events were read completely');
    await assertLayout(page,'.parser-identity-card,.auto-parser-warning,.beginner-problem-source');
    // Headline, explanation and action are stacked, not squeezed into columns.
    const boxes=await offer.evaluate(el=>[...el.children].map(c=>{const r=c.getBoundingClientRect();return {top:r.top,bottom:r.bottom};}));
    expect(boxes[1]!.top).toBeGreaterThanOrEqual(boxes[0]!.bottom-2);
    expect(boxes[2]!.top).toBeGreaterThanOrEqual(boxes[1]!.bottom-2);
    await offer.getByRole('button',{name:'Continue with readable events'}).click();
    const review=page.getByRole('button',{name:'Review Fields',exact:true}).last();
    await expect(review).toBeEnabled();
    await review.click();
    await expect(page.getByLabel('Review Fields stage')).toBeVisible();
    await assertLayout(page,'.auto-parser-preview,.auto-parser-warning');
    await page.getByRole('button',{name:'Map Fields',exact:true}).last().click();
    await expect(page.getByLabel('Source to output mapping workspace')).toBeVisible();
    const vendors=page.locator('.normalization-vendor-list > summary');
    if(await vendors.count())await vendors.click();
    await assertLayout(page,'.normalization-review,.normalization-three-column,.normalization-map-row,.normalization-candidate,.normalization-map-actions,.normalization-map-row label');
    await expect(page.getByRole('button',{name:'Create Parser',exact:true}).last()).toBeEnabled();
    await page.getByRole('button',{name:'Create Parser',exact:true}).last().click();
    await assertLayout(page,'.auto-parser-warning,.auto-parser-download,.auto-parser-preview');
  });
}

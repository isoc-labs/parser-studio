import {test,expect} from 'playwright/test';

// Phase 3, P2 (owner decision of 2026-11-22): events that cannot be read do not stop the creation of a parser
// for the events that can. They are named with their kind and their number and are never shown as parsed.
const KV=(n:number)=>'<134>Nov 21 10:00:0'+n+' fw1 traffic: srcip=10.0.0.'+n+' dstip=10.0.1.'+n+' srcport=5123'+n+' dstport=443 proto=6 action=accept';
const UNCLOSED='<134>Nov 21 10:00:04 fw1 traffic: srcip=10.0.0.9 dstip=10.0.0.10 msg="unterminated action=accept';
const FREE='kernel panic - not syncing: fatal exception in interrupt';

test('events that cannot be read do not stop the parser for the events that can',async({page})=>{
  const raw=[KV(1),UNCLOSED,KV(2),FREE,KV(3)].join('\n');
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(raw);
  await page.getByRole('button',{name:'Analyze Logs'}).click();

  const offer=page.getByLabel('Readable events',{exact:true});
  await expect(offer).toContainText('3 of 5 events were read completely',{timeout:15_000});
  await expect(offer).toContainText('1 × RFC 3164 Syslog with a key=value body that could not be read');
  await expect(offer).toContainText('1 × unrecognized format');
  // The sample as a whole still cannot go on: nothing is shown as parsed that was not.
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();

  await offer.getByRole('button',{name:'Continue with readable events'}).click();
  const context=page.getByLabel('Events not covered by this parser');
  await expect(context).toContainText('This parser covers 3 of your 5 events');
  await expect(context).toContainText('1 × unrecognized format');
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue([KV(1),KV(2),KV(3)].join('\n'));
  await expect(page.getByLabel('Beginner analysis summary'))
    .toContainText('3 of 3 log events structurally parsed',{timeout:15_000});
  await expect(page.getByLabel('Readable events',{exact:true})).toHaveCount(0);

  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:10_000});
  await review.click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();
  // The events left out stay on the screen in the later steps.
  await expect(context).toContainText('2 events could not be read and are not parsed by this parser');

  await context.getByRole('button',{name:'Return to all 5 logs'}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(raw);
  await expect(page.getByLabel('Events not covered by this parser')).toHaveCount(0);
});

test('a sample in which no event can be read gets no offer to go on',async({page})=>{
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill([FREE,UNCLOSED].join('\n'));
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await expect(page.getByText('Some events could not be understood safely')).toBeVisible({timeout:15_000});
  await expect(page.getByLabel('Readable events',{exact:true})).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
});

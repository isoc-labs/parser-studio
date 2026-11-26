import type {Page} from '@playwright/test';

/** Explicit synthetic product identity for export tests. Not a product default. */
export async function enterSyntheticParserIdentity(page:Page){
  await page.getByLabel('Parser manufacturer',{exact:true}).fill('Demo');
  await page.getByLabel('Parser product',{exact:true}).fill('Firewall');
}

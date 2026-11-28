import {readFileSync} from 'node:fs';
import {expect,type Locator} from '@playwright/test';

/** The official fields a name may be proposed for (shared Semantic Policy, default deny). */
export const LISTED_OFFICIAL_FIELDS:readonly string[]=Object.keys((JSON.parse(readFileSync(
  'runtime/multipass/semantic-policy.v1.json','utf8')) as {autoApprovedTargets:Record<string,unknown>}).autoApprovedTargets);

/** The Stellar fields the Map Fields stage shows as official ("Matched to Stellar" rows), by source field. A row
 * that keeps a vendor field under a name that happens to equal a Stellar field name is not one of them: the
 * earlier check compared destination texts only and took such a row for an official mapping. */
export async function officialMappings(map:Locator):Promise<Record<string,string>>{
  const rows=await map.locator('article.normalization-map-row.verified').evaluateAll(nodes=>nodes.map(node=>[
    (node.querySelector('input[aria-label^="Source field "]') as HTMLInputElement|null)?.value??'',
    (node.querySelector('input[aria-label^="Stellar field "]') as HTMLInputElement|null)?.value??'']));
  return Object.fromEntries(rows);
}

/** The automatic journey of a sample. `targets` are the Stellar meanings the sample holds: each one the policy
 * lists must be official after the recommended matches are applied; each one the policy does not list must NOT be
 * official (default deny) while its source field is still there to map with ChatGPT or by hand. Nothing else is
 * official either. */
export async function verifyOfficialMappings(
  map:Locator,
  targets:readonly string[],
  family:string,
):Promise<void>{
  await expect(map.getByLabel('Recommended field matches')).toBeVisible();
  const bulk=map.getByRole('button',{name:/Apply \d+ recommended match/});
  if(await bulk.isEnabled())await bulk.click();
  const official=Object.values(await officialMappings(map));
  for(const target of targets){
    if(LISTED_OFFICIAL_FIELDS.includes(target))
      expect(official,family+' must have an official '+target+' mapping').toContain(target);
    else expect(official,family+': '+target+' is not a listed field and must stay a vendor field').not.toContain(target);
  }
  expect(official.filter(target=>!LISTED_OFFICIAL_FIELDS.includes(target)),family+': official fields outside the policy').toEqual([]);
  expect([...official].sort(),family+': official fields of the sample').toEqual(
    targets.filter(target=>LISTED_OFFICIAL_FIELDS.includes(target)).sort());
  await expect(map.getByLabel('Field mapping checks')).toContainText(
    'All current field mappings passed the sample checks',
  );
  await expect(map.getByLabel('Field changes only')).toBeVisible();
  await expect(map.getByRole('button',{name:'Create Parser'})).toBeEnabled();
}


/** Inspect the actual accepted destination, not only a recommendation label. */
export async function requireSourceMapping(
  map:Locator,
  source:string,
  target:string,
):Promise<void>{
  const names=await map.locator('input[aria-label^="Source field "]')
    .evaluateAll(nodes=>nodes.map(node=>(node as HTMLInputElement).value));
  const index=names.indexOf(source);
  expect(index, 'source field '+source+' must be retained for review').toBeGreaterThanOrEqual(0);
  await expect(map.getByLabel('Stellar field '+index)).toHaveValue(target);
}

/** Negative boundary: a risky suggestion must never be silently accepted. */
export async function requireUnappliedSourceMapping(
  map:Locator,
  source:string,
  unsafeTarget:string,
):Promise<void>{
  const names=await map.locator('input[aria-label^="Source field "]')
    .evaluateAll(nodes=>nodes.map(node=>(node as HTMLInputElement).value));
  const index=names.indexOf(source);
  expect(index, 'source field '+source+' must be retained for manual review').toBeGreaterThanOrEqual(0);
  await expect(map.getByLabel('Stellar field '+index)).not.toHaveValue(unsafeTarget);
}

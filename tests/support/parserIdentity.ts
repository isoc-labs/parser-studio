import {expect,type Page} from '@playwright/test';

/** Type a parser detail with real key presses, one character at a time, as a user does. The field must still be
 * on the page, focused and holding the whole text afterwards: a control that leaves the page while its value is
 * being typed fails here, where a single programmatic fill() would hide it. */
export async function typeParserDetail(page:Page,label:string,text:string){
  const field=page.getByLabel(label,{exact:true});
  await field.click();
  await page.keyboard.press('ControlOrMeta+A');
  await page.keyboard.type(text);
  await expect(field).toBeFocused();
  await expect(field).toHaveValue(text);
}

/** Explicit synthetic product identity for export tests. Not a product default. */
export async function enterSyntheticParserIdentity(page:Page){
  await typeParserDetail(page,'Parser manufacturer','Demo');
  await typeParserDetail(page,'Parser product','Firewall');
}

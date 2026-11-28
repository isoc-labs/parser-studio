import playwrightCore from 'playwright-core';

/**
 * Real key presses for Locator.fill() on single-line inputs, for every spec of this configuration.
 *
 * fill() sets the whole value in one step, so it cannot see what a person typing meets: a control that is removed,
 * replaced or moved after the first valid character (the 2026-11-27 final audit, D-1), or a value that is cut or
 * rewritten while it is typed. With this installed, fill() on a text-like <input> focuses the control, deletes its
 * content, types the text key by key and requires, after the deletion and after the typing, that the very same DOM
 * node still holds focus and, at the end, holds the typed text. Everything else (textareas, long or multi-line text, read-only and non-text controls) keeps the
 * original fill().
 *
 * The check is behavioural: it does not depend on how a component decides to render, so a new control gets it as
 * soon as any journey types into it.
 */
const TEXT_INPUT_TYPES=new Set(['text','search','url','tel','email','password','number','']);
const MAX_TYPED_LENGTH=120;
const INSTALLED='__parserStudioKeyboardFill';

type Described={tag:string;type:string;locked:boolean};

function installOnLocator(page:{locator(selector:string):object}):void{
  const prototype=Object.getPrototypeOf(page.locator('body')) as Record<string,unknown>&{fill:Function};
  if(prototype[INSTALLED])return;
  prototype[INSTALLED]=true;
  const fill=prototype.fill;
  prototype.fill=async function(this:any,value:string,options?:{timeout?:number}){
    const text=String(value);
    let described:Described|null=null;
    try{
      described=await this.evaluate((element:any)=>({tag:element.tagName,type:String(element.type||'').toLowerCase(),
        locked:Boolean(element.readOnly||element.disabled)}),null,{timeout:options?.timeout});
    }catch{return fill.call(this,value,options);}
    const typed=described!==null&&described.tag==='INPUT'&&TEXT_INPUT_TYPES.has(described.type)&&!described.locked&&
      text.length<=MAX_TYPED_LENGTH&&!/[\r\n]/u.test(text);
    if(!typed)return fill.call(this,value,options);
    const page=this.page();
    const token='edit-'+Math.random().toString(36).slice(2);
    await this.focus(options);
    await this.evaluate((element:any,mark:string)=>{element.__parserStudioEditToken=mark;},token);
    const read=():Promise<string|null>=>page.evaluate((mark:string)=>{
      const active=document.activeElement as any;
      return active&&active.__parserStudioEditToken===mark?String(active.value):null;
    },token);
    // Clear first, then type: the value passes through "empty" as it does for a person who replaces it.
    await page.keyboard.press('ControlOrMeta+A');
    await page.keyboard.press('Delete');
    if(await read()===null)throw new Error('EDITING_CONTROL_LOST: when its content was deleted, the control '+
      'being edited was removed, replaced or lost focus: '+String(this));
    if(text!=='')await page.keyboard.type(text);
    const held=await read();
    if(held===null)throw new Error('EDITING_CONTROL_LOST: while '+JSON.stringify(text)+
      ' was typed, the control being edited was removed, replaced or lost focus: '+String(this));
    if(held!==text)throw new Error('TYPED_VALUE_DIFFERS: typed '+JSON.stringify(text)+
      ' but the control holds '+JSON.stringify(held)+': '+String(this));
  };
}

function after(prototype:Record<string,any>,name:string,then:(result:any)=>void):void{
  const original=prototype[name];
  if(typeof original!=='function'||original[INSTALLED])return;
  const wrapped=async function(this:unknown,...args:unknown[]){
    const result=await original.apply(this,args);
    then(result);
    return result;
  };
  (wrapped as any)[INSTALLED]=true;
  prototype[name]=wrapped;
}

/** Call once from the Playwright configuration; the configuration is loaded in every worker. */
export function installKeyboardFill():void{
  const state=globalThis as Record<string,unknown>;
  if(state[INSTALLED])return;
  state[INSTALLED]=true;
  const chromium=(playwrightCore as any).chromium;
  after(Object.getPrototypeOf(chromium),'launch',browser=>{
    const browserPrototype=Object.getPrototypeOf(browser);
    const onContext=(context:object)=>after(Object.getPrototypeOf(context),'newPage',installOnLocator);
    after(browserPrototype,'newContext',onContext);
    after(browserPrototype,'_newContextForReuse',onContext);
  });
}

import {expect,test} from '@playwright/test';

// The harness of tests/support/keyboardFill.ts must really be active: if a Playwright upgrade turned it into a
// no-op, every journey would silently go back to one-step fill(). These two tests are its own proof.
const page_=(body:string)=>'data:text/html,'+encodeURIComponent('<!doctype html><title>harness</title>'+body);

test('fill() on a text input is carried out with one key press per character',async({page})=>{
  await page.goto(page_(`<input aria-label="name"><script>
    window.keys=0;document.querySelector('input').addEventListener('keydown',e=>{if(e.key.length===1&&!e.ctrlKey&&!e.metaKey)window.keys++;});
  </script>`));
  await page.getByLabel('name').fill('Fortinet');
  await expect(page.getByLabel('name')).toHaveValue('Fortinet');
  expect(await page.evaluate(()=>(window as any).keys)).toBe('Fortinet'.length);
  await page.getByLabel('name').fill('');
  await expect(page.getByLabel('name')).toHaveValue('');
});

test('fill() fails when the control being edited is replaced or removed by its own value, and when the value is cut',async({page})=>{
  // The same defect class as a card that is unmounted after the first valid character.
  await page.goto(page_(`<div id="host"><input aria-label="name"></div><script>
    const host=document.getElementById('host');
    host.addEventListener('input',event=>{
      if(event.target.value.length===1)host.innerHTML='<input aria-label="name" value="'+event.target.value+'">';
    });
  </script>`));
  await expect(page.getByLabel('name').fill('Fortinet')).rejects.toThrow(/EDITING_CONTROL_LOST/u);
  await page.goto(page_(`<input aria-label="name"><script>
    document.querySelector('input').addEventListener('input',event=>{event.target.value=event.target.value.slice(0,3);});
  </script>`));
  await expect(page.getByLabel('name').fill('Fortinet')).rejects.toThrow(/TYPED_VALUE_DIFFERS/u);
  // A control that exists only while it has content (an editor that is unmounted when it is cleared).
  await page.goto(page_(`<div id="host"><input aria-label="name" value="old"></div><script>
    const host=document.getElementById('host');
    host.addEventListener('input',event=>{if(event.target.value==='')host.innerHTML='';});
  </script>`));
  await expect(page.getByLabel('name').fill('Fortinet')).rejects.toThrow(/EDITING_CONTROL_LOST/u);
});

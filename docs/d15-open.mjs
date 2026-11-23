// Real offline browser opening of D15 delivery files; no server, model, or API.
import {chromium, expect} from '../apps/web/node_modules/@playwright/test/index.mjs';
import {readFile, writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const [folder, output] = process.argv.slice(2).map(x => resolve(x));
if (!folder || !output) throw new Error('Expected extracted folder and output directory');
const browser = await chromium.launch({headless:true});
const context = await browser.newContext({viewport:{width:1280,height:900}});
const page = await context.newPage();
const errors=[];
page.on('pageerror', error=>errors.push(String(error)));
await context.route('**/*', route=>route.request().url().startsWith('file:') ? route.continue() : route.abort());
const opened=[];
async function visit(relative, text, screenshot){
  await page.goto(pathToFileURL(resolve(folder,relative)).href);
  await expect(page.locator('body')).toContainText(text);
  await page.screenshot({path:resolve(output,screenshot),fullPage:false});
  opened.push({file:relative,loaded:true});
}
try {
  await visit('START-HERE.html','完整P0未通过','entry.png');
  await page.getByRole('link',{name:'展示页',exact:true}).click();
  await expect(page.locator('body')).toContainText('七项P1');
  await page.screenshot({path:resolve(output,'showcase.png')});
  opened.push({file:'materials/docs/d14-showcase.html',loaded:true,clicked_from_entry:true});
  for (const index of ['01','02']) {
    const video='materials/media/d14-rehearsal-'+index+'.webm';
    await page.goto(pathToFileURL(resolve(folder,video)).href);
    await expect.poll(()=>page.locator('video').evaluate(el=>el.duration)).toBeCloseTo(479.2,1);
    await page.locator('video').evaluate(async el=>{el.muted=true; await el.play();});
    await expect.poll(()=>page.locator('video').evaluate(el=>el.currentTime)).toBeGreaterThan(0.3);
    await page.locator('video').evaluate(el=>{el.pause();el.currentTime=477;});
    await expect.poll(()=>page.locator('video').evaluate(el=>el.readyState)).toBeGreaterThan(1);
    await page.screenshot({path:resolve(output,'video-'+index+'.png')});
    opened.push({file:video,decoded:true,played:true,duration_seconds:479.2});
    await visit('materials/rehearsal-'+index+'/S1.html','deterministic_fallback','report-'+index+'.png');
  }
  await visit('evaluation/artifacts/d12-check-04/analysis/index.html','无正式标签','analysis.png');
  const images=await page.locator('img').evaluateAll(elements=>elements.map(el=>({loaded:el.complete&&el.naturalWidth>0,src:el.getAttribute('src')})));
  if (!images.every(image=>image.loaded)) throw new Error('Analysis image failed');
  const manifest=JSON.parse(await readFile(resolve(folder,'release-manifest.json'),'utf8'));
  const pngs=Object.keys(manifest.files).filter(name=>name.endsWith('.png'));
  for(const file of pngs){
    await page.goto(pathToFileURL(resolve(folder,file)).href);
    await expect.poll(()=>page.locator('img').first().evaluate(el=>el.complete&&el.naturalWidth>0)).toBe(true);
  }
  if(errors.length)throw new Error(errors.join('\n'));
  await writeFile(resolve(output,'browser.json'),JSON.stringify({verified:true,opened,pngs_decoded:pngs.length,
    browser_page_errors:errors,external_requests_allowed:false,real_llm_accepted:false},null,2));
} finally {await context.close();await browser.close();}

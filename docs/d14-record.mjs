// Real UI evidence, no test labels or report answers supplied to the application.
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { writeFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
const { D14_ROOT: root, D14_TARGET: target, D14_OUTPUT: out, D14_URL: url, D14_TOKEN: token } = process.env;
const smoke = process.env.D14_SMOKE === '1';
const { chromium, expect } = await import(pathToFileURL(resolve(root, 'apps/web/node_modules/@playwright/test/index.mjs')).href);
const browser = await chromium.launch({headless: true});
const context = await browser.newContext({viewport:{width:1280,height:800}, recordVideo:{dir:out,size:{width:1280,height:800}}});
const page = await context.newPage();
page.setDefaultTimeout(30000);
const start = performance.now();
const events = [], requests = [], datasets = [];
async function focus(locator){await locator.evaluate(el=>el.scrollIntoView({block:'start'}));}
let complete = false;
page.on('response', response => {const u=new URL(response.url()); if(u.protocol.startsWith('http'))requests.push({path:u.pathname,status:response.status()});});
await context.route('**/*', route => { const u=new URL(route.request().url()); return u.protocol==='file:'||u.origin===url ? route.continue() : route.abort(); });
async function caption(text) {
  await page.evaluate(text => {let el=document.getElementById('d14-caption');if(!el){el=document.createElement('div');el.id='d14-caption';document.body.appendChild(el);}el.style.cssText='position:fixed;z-index:99999;bottom:0;left:0;right:0;background:#071629f5;color:#f3f8ff;border-top:3px solid #68dfbe;padding:16px 28px;font:18px/1.5 system-ui;pointer-events:none';el.textContent='预录 · 自动操作 · 合成数据 · 本地故障注入 / 非真实LLM ｜ '+text;document.body.style.paddingBottom='130px';},text);
  events.push({elapsed_seconds:(performance.now()-start)/1000,caption:text});
}
async function until(seconds){if(!smoke){const delay=seconds*1000-(performance.now()-start);if(delay< -3000)throw new Error('CHAPTER_DEADLINE_EXCEEDED');if(delay>0)await page.waitForTimeout(delay);}else await page.waitForTimeout(200);}
async function connect(){await page.goto(url);await page.getByLabel('角色令牌').fill(token);await page.getByRole('button',{name:'连接 / 刷新'}).click();}
async function scene(name, sources){
  await page.getByRole('button',{name:/概览与导入/}).click();
  await page.getByLabel('新数据集名称').fill(`D14 ${name} synthetic ${Date.now()}`);
  await page.getByRole('button',{name:'创建合成数据集'}).click();
  await expect(page.getByRole('combobox',{name:'数据集',exact:true}).locator('option:checked')).toContainText(`D14 ${name}`);
  datasets.push({scenario:name,id:await page.getByRole('combobox',{name:'数据集',exact:true}).inputValue()});
  const folder=resolve(target,'app/data/fixtures/d9',name==='S1'?'S1':'S2');
  await page.getByLabel('上下文 JSON').setInputFiles(resolve(folder,'context.json'));
  await page.getByRole('button',{name:'配置上下文',exact:true}).click();
  await expect(page.getByText(/上下文已封存/)).toBeVisible();
  for(const [source,sensor,file,count] of sources){
    await page.getByRole('combobox',{name:'来源',exact:true}).selectOption(source);
    await page.getByLabel('传感器',{exact:true}).fill(sensor);
    await page.getByLabel('JSONL 文件').setInputFiles(resolve(folder,file+'.jsonl'));
    await page.getByRole('button',{name:'上传日志',exact:true}).click();
    await expect(page.getByText(new RegExp(`succeeded · 新增 ${count}`))).toBeVisible();
  }
  await page.screenshot({path:resolve(out,name+'-ingest.png')});
  await page.getByRole('button',{name:/安全事件/}).click();
  await page.getByRole('button',{name:'刷新检测事件',exact:true}).click();
}
async function investigate(){
  await page.getByRole('combobox',{name:'调查模式',exact:true}).selectOption('live');
  await page.getByRole('button',{name:'开始调查',exact:true}).first().click();
  const report=page.getByRole('region',{name:'报告与人工复核'});
  await expect(report).toContainText('deterministic_fallback');
  await expect(page.getByRole('region',{name:'缺证与校验'})).toContainText('调查未完成');
  return report;
}
try {
  await page.goto(pathToFileURL(resolve(root,'docs/d14-showcase.html')).href);
  await caption('从分散日志到可回溯证据：本次演示连接中断与坏引用；同机自动化，不代替物理断网或真人彩排。');
  await page.screenshot({path:resolve(out,'showcase.png')});
  await until(45);
  await connect();
  await caption('S1：先配置不可变上下文，再导入网络、认证、审计、告警格式。全部为开发合成材料。');
  await scene('S1',[['zeek','net-a','network',26],['linux_auth','auth-a','auth_a',6],['linux_audit','audit-a','audit',3],['linux_auth','auth-b','auth_b',1],['suricata','alert-a','alerts',1]]);
  await until(90);
  await caption('规则只产生调查候选。现在实际创建调查；回环模型连接被故意中断，真实传输失败后降级；不是真实LLM。');
  const report=await investigate();
  await expect(page.getByRole('region',{name:'缺证与校验'})).toContainText('MODEL_UNAVAILABLE_OR_TIMEOUT');
  await focus(report);
  await page.screenshot({path:resolve(out,'S1-report.png')});
  await until(135);
  await focus(page.getByRole('heading',{name:'证据关系图',exact:true}));
  await caption('实线为记录关系，虚线为有约束推断。缺socket或严格时序就留断点；链内覆盖不是完整攻击链覆盖。');
  await page.screenshot({path:resolve(out,'S1-graph.png')});
  await until(175);
  await focus(page.getByRole('heading',{name:'冻结快照时间线',exact:true}));
  await caption('固定快照中的事件时间线。事件ID、源对象和引用可回溯；IP、PID和时间接近不等于真实身份或因果。');
  await until(210);
  await focus(page.getByRole('region',{name:'缺证与校验'}));
  await caption('本地协议连接中断触发partial/fallback。预算、工具白名单和引用约束仍保留；没有执行的工具不会出现在补证结果中。');
  await until(250);
  await focus(report);
  await caption('事实、假设和未知分别呈现。校验passed只说明保留结论通过有限检查，不能宣称完整调查。');
  await until(285);
  await report.getByRole('button',{name:'证据 1',exact:true}).first().click();
  await focus(page.getByRole('heading',{name:'证据抽屉 · 已核验哈希的脱敏投影',exact:true}));
  await caption('点击真实报告引用，查看哈希核验后的脱敏投影。原始账号、命令和密钥不进入公开展示。');
  await page.screenshot({path:resolve(out,'S1-evidence.png')});
  for(const format of ['JSON','HTML']){
    const downloadEvent=page.waitForEvent('download');
    await report.getByRole('button',{name:`导出 ${format}`,exact:true}).click();
    const download=await downloadEvent;await download.saveAs(resolve(out,'S1.'+format.toLowerCase()));
  }
  await report.getByRole('button',{name:'读取匹配缓存',exact:true}).click();
  await expect(report).toContainText('模式：cached');
  await caption('读取匹配缓存：保留原生成时间和source_mode，本次没有调用模型。下载报告保留原模式。');
  await until(330);
  const switchMode=await fetch(process.env.D14_FAULT_ORIGIN+'/control/bad-reference',{method:'POST',headers:{'X-D14-Control':process.env.D14_FAULT_CONTROL}});if(!switchMode.ok)throw new Error('FAULT_CONTROL_FAILED');
  await scene('S3',[['zeek','net-a','network',9]]);
  const partial=await investigate();await focus(partial);
  await expect(page.getByRole('region',{name:'缺证与校验'})).toContainText('DRAFT_REFERENCE_OUT_OF_SCOPE');
  await caption('S3缺主机证据；协议桩注入不存在的引用，实际校验拒绝并降级，原始日志没有修改。');
  await page.screenshot({path:resolve(out,'S3-partial.png')});
  await focus(page.getByRole('region',{name:'缺证与校验'}));
  await page.screenshot({path:resolve(out,'S3-rejected.png')});
  const exportEvent=page.waitForEvent('download');await partial.getByRole('button',{name:'导出 JSON',exact:true}).click();await (await exportEvent).saveAs(resolve(out,'S3.json'));
  await until(375);
  await page.goto(pathToFileURL(resolve(root,'docs/d14-showcase.html')).href+'#evidence');
  await caption('以下为已归档的D11/D12历史证据。失败轮次保留；不是D14新性能测量，正式F1和真实LLM账单未知。');
  await until(415);
  await focus(page.locator('#limits'));
  await caption('D14交付依赖离线包、空目标恢复与回退手册。新venv不等于干净机器，自动操作不等于非作者独立验收。');
  await until(450);
  await caption('七项P1仍阻断完整P0。待验收：独立备机、物理断网、真人两次彩排、真实模型与正式资料。');
  await until(479);
  complete=true;
} finally {
  if(!complete) await page.screenshot({path:resolve(out,'failed.png')});
  const elapsed=(performance.now()-start)/1000;
  await writeFile(resolve(out,'recording.json'),JSON.stringify({version:'d14-recording@1.0.0',recorded_at:new Date().toISOString(),complete,smoke,elapsed_seconds:elapsed,automated:true,prerecorded:true,model_provider:'compatible',model_execution:'protocol_test_stub',fault_injection:true,physical_disconnect_accepted:false,real_llm_accepted:false,non_author_accepted:false,base_freeze_sha256:'9110dae9674ddedb75f08e538466df68ec9ff6e4b38eac5720f64fcd8ca11673',events,datasets,requests},null,2));
  await page.close();await context.close();await browser.close();
}

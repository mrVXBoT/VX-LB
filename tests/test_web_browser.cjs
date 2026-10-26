const assert = require('node:assert/strict');
const { chromium } = require('playwright');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const screenshots = process.env.UI_SCREENSHOTS || '/tmp/vxlb-ui';
fs.mkdirSync(screenshots, {recursive:true});
let browser;
(async () => {
 browser = await chromium.launch({...(process.env.CHROMIUM_PATH ? {executablePath:process.env.CHROMIUM_PATH} : {}),headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
 const page = await browser.newPage({viewport:{width:390,height:844},deviceScaleFactor:1});
 const errors=[];page.on('pageerror',error=>errors.push(error.message));
 const nodes=Array.from({length:4},(_,i)=>({name:'نود تهران '+(i+1),ip:'192.0.2.'+(i+1),status:i===2?'DOWN':'HEALTHY',reason:i===2?'SSH unreachable; current health cannot be verified':'Tunnel verified',latency_ms:28+i,engine:'backpack',transport:'pck',tunnel_port:22001+i}));
 const state={daemon_running:true,iran_count:4,kharej_count:1,last_check:'2026-10-26 12:00:00',global_cloudflare:{},private_links:{},link_tasks:{},pools:[
 {name:'tehran-production',engine:'backpack',transport:'pck',client_ports:['443','8443'],kharej_ip:'198.51.100.1',nodes,creation_job:{id:'create',status:'running',phase:'configuring',started_at:Date.now()/1000-12,message:'در حال پیکربندی تونل و رله',completed:2,total:4,updated_at:Date.now()/1000}},
 {name:'edge-fallback',engine:'wireguard',transport:'wireguard',client_ports:['443'],kharej_ip:'198.51.100.2',nodes:[nodes[0]],operation_task:{id:'delete',kind:'delete',status:'failed',message:'عملیات کامل نشد؛ جزئیات را بررسی کنید',error:'اتصال SSH به سرور خارج برقرار نشد؛ سرویس قبلی حفظ شده است'}}]};
 await page.addInitScript(() => {
  window.eventStreams=[];
  window.EventSource=class {
   constructor() { this.listeners={};window.eventStreams.push(this);setTimeout(()=>this.emit('ready'),0); }
   addEventListener(name,fn) { this.listeners[name]=fn; }
   emit(name) { this.listeners[name]?.({}); }
   close() { this.closed=true; }
  };
 });
 let deleteRequests=0;
 await page.route('**/*',async route=>{
  const url=new URL(route.request().url());
  if(url.pathname==='/api/pools/delete') {deleteRequests++;return route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({success:false,error:'سرور در دسترس نیست؛ دوباره تلاش کنید'})});}
  if(url.pathname.startsWith('/api/')) return route.fulfill({contentType:'application/json',body:JSON.stringify(url.pathname==='/api/status'?state:url.pathname==='/api/servers'?{iran:[],kharej:[]}:{success:true,logs:[]})});
  const filename=path.join(path.join(root, 'web'),url.pathname==='/'?'index.html':url.pathname.replace(/^\//,''));
  if(!fs.existsSync(filename))return route.fulfill({status:404,body:''});
  const ext=path.extname(filename);return route.fulfill({contentType:({'.html':'text/html','.js':'application/javascript','.css':'text/css','.svg':'image/svg+xml','.png':'image/png'})[ext]||'application/octet-stream',body:fs.readFileSync(filename)});
 });
 await page.goto('http://vxlb.test/',{waitUntil:'networkidle'});
 await page.locator('#app-view').waitFor({state:'visible'});
 const measurements=[];
 for (const width of [360,390,768,1440]) {
  await page.setViewportSize({width,height:width<768?844:1000});
  await page.screenshot({path:path.join(screenshots,`after-${width}.png`),fullPage:true});
  const measure=await page.evaluate(()=>({width:innerWidth,scrollWidth:document.documentElement.scrollWidth,cards:document.querySelectorAll('.pool-card').length}));
  assert.equal(measure.scrollWidth,width,`horizontal overflow at ${width}px`);
  assert.equal(measure.cards,2);
  measurements.push(measure);
 }
 const first=page.locator('.pool-card').first();
 const technical=first.locator('.node-technical-details').first();
 assert.equal(await technical.getAttribute('open'),null);
 await technical.locator('summary').click();
 await technical.locator('summary').focus();
 assert.ok(await first.evaluate(card => card.querySelector('.pool-live-operations').compareDocumentPosition(card.querySelector('.node-technical-details')) & Node.DOCUMENT_POSITION_FOLLOWING));
 await page.evaluate(()=>{window.unchangedCard=document.querySelectorAll('.pool-card')[1];});
 state.pools[0].creation_job.message='در حال بررسی نهایی مسیر';
 state.pools[0].creation_job.phase='verifying';
 await page.evaluate(()=>window.eventStreams.at(-1).emit('change'));
 await page.waitForFunction(()=>document.querySelector('.op-msg')?.textContent.includes('بررسی نهایی'));
 assert.equal(await technical.getAttribute('open'),'');
 assert.equal(await page.evaluate(()=>document.activeElement.matches('.node-technical-details summary')),true);
 assert.equal(await page.evaluate(()=>window.unchangedCard===document.querySelectorAll('.pool-card')[1]),true);
 const failure=page.locator('.pool-card').nth(1).locator('.operation-item');
 assert.equal(await failure.getAttribute('role'),'alert');
 assert.equal(await failure.locator('.operation-advanced').getAttribute('open'),null);
 assert.ok(await failure.getByRole('button',{name:'تلاش دوباره برای حذف استخر',exact:true}).isVisible());
 state.pools[0].creation_job.status='succeeded';
 state.pools[0].creation_job.message='ساخت استخر پایان یافت';
 await page.evaluate(()=>window.eventStreams.at(-1).emit('change'));
 await page.waitForFunction(()=>!document.querySelector('.pool-card .operation-item.is-active'));
 assert.equal(await technical.getAttribute('open'),'');
 // Closing confirmation must release the guard and allow a later retry.
 await failure.getByRole('button',{name:'تلاش دوباره برای حذف استخر',exact:true}).click();
 await page.locator('#confirm-modal').waitFor({state:'visible'});
 await page.keyboard.press('Escape');
 await page.locator('#confirm-modal').waitFor({state:'hidden'});
 await failure.getByRole('button',{name:'تلاش دوباره برای حذف استخر',exact:true}).click();
 await page.locator('#confirm-modal-ok').click();
 await page.waitForFunction(()=>document.querySelector('.pool-action-error')?.textContent.includes('سرور در دسترس نیست'));
 assert.equal(deleteRequests,1);
 // Preserve completion feedback after a deleted card has disappeared.
 state.recent_operations=[{name:'deleted-pool',status:'succeeded',message:'حذف استخر پایان یافت'}];
 await page.evaluate(()=>window.eventStreams.at(-1).emit('change'));
 await page.waitForFunction(()=>document.querySelector('#recent-pool-operations')?.textContent.includes('deleted-pool'));
 // Streaming failure falls back to polling and resumes live state after reconnect.
 state.pools[0].creation_job.status='running';
 await page.evaluate(()=>window.eventStreams.at(-1).emit('change'));
 await page.waitForFunction(()=>document.querySelector('.operation-item.is-active'));
 state.pools[0].creation_job.message='وضعیت از بررسی جایگزین دریافت شد';
 await page.evaluate(()=>{window.eventStreams.at(-1).onerror();lastStatusPoll=0;});
 await page.waitForFunction(()=>document.querySelector('.op-msg')?.textContent.includes('بررسی جایگزین'),{},{timeout:5000});
 // A hidden busy pool must still lock mutations in a filtered visible pool.
 await page.evaluate(()=>{
  poolSearch='edge-fallback';
  renderPools([{name:'hidden',creation_job:{status:'running'},nodes:[]},{name:'edge-fallback',nodes:[]}]);
 });
 assert.equal(await page.locator('.pool-card').count(),1);
 assert.ok(await page.locator('.pool-card button[onclick*=deleteEntirePool]').isDisabled());
 for (const width of [390,1440]) {
  await page.setViewportSize({width,height:width<768?844:1000});
  await page.evaluate(()=>openCreatePoolModal());
  await page.locator('#create-pool-modal').waitFor({state:'visible'});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth),width);
  await page.screenshot({path:path.join(screenshots,`create-${width}.png`),fullPage:true});
  await page.keyboard.press('Escape');
  await page.locator('#create-pool-modal').waitFor({state:'hidden'});
 }
 assert.deepEqual(errors,[]);
 console.log(JSON.stringify({measurements,errors,checks:['live updates','completion while focused','preserved details and focus','unchanged card reuse','safe retry','confirmation cancel','inline HTTP errors','deleted-pool completion','stream fallback','global mutation lock']}));
 await browser.close();
})().catch(async error=>{console.error(error);process.exitCode=1;if(browser) await browser.close();});

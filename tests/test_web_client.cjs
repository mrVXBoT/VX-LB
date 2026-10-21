/* Tests of data presentation and request boundaries; no browser or live API. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '..');
const elements = new Map();
function element(id) {
  if (!elements.has(id)) {
    const classes = new Set();
    elements.set(id, {
      textContent: '', innerHTML: '', value: '', style: {}, dataset: {}, children: [], attributes: {},
      setAttribute(name, value) { this.attributes[name] = value; },
      removeAttribute(name) { delete this.attributes[name]; },
      focus() {},
      addEventListener() {},
      removeEventListener() {},
      className: '', contains: () => false,
      classList: {
        add: c => classes.add(c), remove: c => classes.delete(c),
        contains: c => classes.has(c),
        toggle: (c, force) => force ? classes.add(c) : classes.delete(c)
      },
      querySelector: () => ({textContent: '', focus() {}})
    });
  }
  return elements.get(id);
}
const context = vm.createContext({
  Intl, console, setTimeout, clearTimeout, setInterval, clearInterval,
  localStorage: {getItem: key => key === 'vx_lb_token' ? 'test-only' : 'dark', removeItem() {}, setItem() {}},
  window: {panelCopy: {}, matchMedia: () => ({matches: false})},
  document: {
    body: element('body'), documentElement: {dataset: {}}, activeElement: null,
    addEventListener() {}, getElementById: element,
    querySelector: () => element('query'), querySelectorAll: () => []
  },
  fetch: async () => ({status: 200, ok: true, json: async () => ({})})
});
vm.runInContext(fs.readFileSync(path.join(root, 'web/copy.fa.js'), 'utf8'), context);
vm.runInContext(fs.readFileSync(path.join(root, 'web/app.js'), 'utf8'), context);
const run = code => vm.runInContext(code, context);
(async () => {
  run(`updateHeroMetrics({pools: [], daemon_running: false})`);
  assert.equal(element('healthy-count').textContent, '0');
  assert.equal(element('hero-status-pill-text').textContent, context.window.panelCopy.noNodes);
  assert.equal(element('cf-summary-label').textContent, context.window.panelCopy.dnsMissing);
  run(`updateHeroMetrics({pools: [{nodes: [{status:'HEALTHY'}, {status:'CANARY'}, {status:'FILTERED'}, {status:'NEW_STATUS'}]}]})`);
  assert.equal(element('health-good').textContent, '1');
  assert.equal(element('health-warn').textContent, '1');
  assert.equal(element('health-bad').textContent, '2');
  assert.equal(element('hero-status-pill-text').textContent, context.window.panelCopy.issue);
  run(`renderPools([{name:'test', engine:'backpack', transport:'pck', nodes:[{name:'unknown', ip:'192.0.2.1', status:'NEW_STATUS', latency_ms:24.6}]}])`);
  assert.match(element('pools-container').innerHTML, /status-badge unknown/);
  assert.doesNotMatch(element('pools-container').innerHTML, /status-badge healthy/);
  assert.match(element('pools-container').innerHTML, /engine-backpack/);
  assert.match(element('pools-container').innerHTML, /pool-nodes-summary/);
  assert.match(element('pools-container').innerHTML, /node-latency-pill/);
  assert.match(element('pools-container').innerHTML, /25 ms/);
  run(`renderDomainRoutes({pools:[
    {name:'pool-one', subdomain:'first.example.com', cf_enabled:true},
    {name:'pool-two', subdomain:'second.example.com', cf_enabled:false},
    {name:'pool-three', subdomain:'Not set'}],
    global_cloudflare:{subdomain:'default.example.com', enabled:true}})`);
  for (const domain of ['first.example.com', 'second.example.com', 'default.example.com']) {
    assert.ok(element('domain-routes').innerHTML.includes(domain));
  }
  assert.match(element('domain-routes').innerHTML, /pool-three/);
  assert.match(element('domain-routes').innerHTML, /data-domain="second.example.com"/);
  assert.equal(element('domain-route-count').textContent, '4');
  assert.equal(run(`withoutEmoji('✅ ثبت شد 🇮🇷')`), 'ثبت شد');
  run(`renderServers({iran:[{name:'tehran',ip:'192.0.2.1',in_use:true}],kharej:[{name:'frankfurt',ip:'198.51.100.1',in_use:false}]})`);
  assert.match(element('servers-container').innerHTML, /class="ui-icon"/);
  assert.match(element('servers-container').innerHTML, /loc-iran/);
  assert.match(element('servers-container').innerHTML, /loc-kharej/);
  assert.match(element('servers-container').innerHTML, /server-spec-chip/);
  assert.match(element('servers-container').innerHTML, /در استخر فعال/);
  assert.match(element('servers-container').innerHTML, /آماده تخصیص/);
  assert.doesNotMatch(element('servers-container').innerHTML, /\p{Extended_Pictographic}|\p{Regional_Indicator}/u);
  // Failed refresh keeps a previously authorized snapshot and exposes stale state.
  const snapshot = {pools: []};
  context.snapshot = snapshot;
  run('cachedStatus = snapshot');
  context.fetch = async () => { throw new Error('offline'); };
  element('pools-container').innerHTML = 'existing rows';
  await run('fetchStatus()');
  assert.equal(element('pools-container').innerHTML, 'existing rows');
  assert.equal(element('connection-label').dataset.state, 'error');
  assert.equal(run('cachedStatus'), snapshot);
  // Job progress and completion render even while the delete button has focus.
  element('pools-container').contains = () => true;
  const jobSnapshot = status => ({pools:[{name:'one', nodes:status === 'succeeded' ? [] : [{ip:'192.0.2.1'}], node_removals:{'192.0.2.1':{ip:'192.0.2.1',status,message:status}}}]});
  context.fetch = async () => ({status:200,ok:true,json:async()=>jobSnapshot('running')});
  await run('fetchStatus()');
  assert.match(element('pools-container').innerHTML, /data-status="running"/);
  assert.match(element('pools-container').innerHTML, /node-del-btn[^>]*disabled/);
  context.fetch = async () => ({status:200,ok:true,json:async()=>jobSnapshot('succeeded')});
  await run('fetchStatus()');
  assert.match(element('pools-container').innerHTML, /data-status="succeeded"/);
  assert.doesNotMatch(element('pools-container').innerHTML, /node-del-btn/);
  element('pools-container').contains = () => false;
  // Offline-node removal is an explicit action after failed cleanup.
  run(`renderPools([{name:'one',nodes:[{ip:'192.0.2.1'}],node_removals:{a:{ip:'192.0.2.1',status:'failed',message:'SSH unavailable'}}}])`);
  assert.match(element('pools-container').innerHTML, /حذف از پنل بدون پاک‌سازی/);
  assert.match(element('pools-container').innerHTML, /removeNodeFromPool\(this.dataset.pool,this.dataset.ip,this,true\)/);
  run(`renderPools([{name:'one',nodes:[],node_removals:{a:{ip:'192.0.2.1',status:'succeeded',cleanup_pending:true,message:'پاک‌سازی تأیید نشده'}}}])`);
  assert.match(element('pools-container').innerHTML, /is-failed/);
  assert.doesNotMatch(element('pools-container').innerHTML, /operation-history/);
  const previousConfirm = context.confirmDialog;
  const previousToast = context.showToast;
  const previousRefresh = context.fetchStatus;
  const removalRequests = [];
  context.confirmDialog = async () => false;
  context.fetch = async (url, options) => {
    removalRequests.push({url, body:JSON.parse(options.body)});
    return {status:202,ok:true,json:async()=>({success:true})};
  };
  context.showToast = () => {};
  context.fetchStatus = async () => {};
  await run(`removeNodeFromPool('one','192.0.2.1',null,true)`);
  assert.equal(removalRequests.length,0,'cancelling must not submit a deletion');
  context.confirmDialog = async message => {
    assert.match(message,/متصل نمی‌شویم/);
    assert.match(message,/DNS/);
    return true;
  };
  await run(`removeNodeFromPool('one','192.0.2.1',null,true)`);
  assert.equal(removalRequests[0].body.forget,true);
  assert.equal(removalRequests[0].body.iran_ip,'192.0.2.1');
  context.confirmDialog = previousConfirm;
  context.showToast = previousToast;
  context.fetchStatus = previousRefresh;
  // Creation and pool jobs must lock mutations and remain visible after refresh.
  assert.equal(run(`poolIsBusy({creation_job:{status:'queued'}})`), true);
  assert.equal(run(`poolIsBusy({operation_task:{status:'running'}})`), true);
  assert.match(run(`renderPoolOperations({name:'p',operation_task:{kind:'ports_add',status:'running',message:'working'}})`), /data-status="running"/);
  assert.match(run(`renderPoolOperations({name:'p',operation_task:{kind:'delete',status:'failed',error:'cleanup failed'}})`), /cleanup failed/);
  // All-subdomain DNS badges require the address on every managed name.
  run(`globalThis.multiPool = {subdomain:'example.test',dns_scope:'all_subdomains',dns_report:{subdomain:'example.test',scope:'all_subdomains',dns_snapshot:{success:true,names:['a.example.test','b.example.test'],records:[{name:'a.example.test',content:'192.0.2.1'},{name:'b.example.test',content:'192.0.2.2'}]}}}`);
  assert.equal(run('poolDnsState(multiPool).ips.length'),0);
  run(`multiPool.dns_report.dns_snapshot.records[1].content='192.0.2.1'`);
  assert.equal(run(`poolDnsState(multiPool).ips[0]`),'192.0.2.1');
  run(`multiPool.dns_scope='single'`);
  assert.equal(run(`poolDnsState(multiPool).verified`),false);
  // Enabling broad management requires displaying and then confirming names.
  run(`currentPoolForAction='one'`);
  element('pool-cf-token').value='test-only';
  element('pool-cf-zone').value='test-zone';
  element('pool-cf-sub').value='example.test';
  element('pool-cf-scope').value='all_subdomains';
  const scopeRequests=[];
  context.fetch=async (url,options) => {
    scopeRequests.push({url,body:options?.body ? JSON.parse(options.body):null});
    const payload=url.endsWith('cloudflare-preview') ? {success:true,names:['ssh.example.test'],records:[{name:'ssh.example.test',content:'192.0.2.1'}]} : url.endsWith('/api/status') ? {pools:[]} : {success:true};
    return {status:200,ok:true,json:async()=>payload};
  };
  await run('submitPoolCloudflare({preventDefault(){}})');
  assert.deepEqual(scopeRequests.map(r=>r.url),['/api/pools/cloudflare-preview']);
  assert.match(element('pool-cf-preview').innerHTML,/ssh.example.test/);
  await run('submitPoolCloudflare({preventDefault(){}})');
  const activation=scopeRequests.find(r=>r.url==='/api/pools/cloudflare');
  assert.equal(activation.body.scope,'all_subdomains');
  assert.deepEqual(activation.body.confirmed_names,['ssh.example.test']);
  // Mutation error payloads remain available to existing form error handling.
  context.fetch = async () => ({status:400, ok:false, json: async () => ({error:'port conflict'})});
  assert.equal((await run(`apiFetch('/api/pools/create', {method:'POST', body:{}})`)).error, 'port conflict');
  await assert.rejects(run(`apiFetch('/api/status')`), /port conflict/);
  // Drawer state controls background isolation and restores normal desktop layout.
  const background = element('header');
  element('app-view').children = [background, element('app-tabbar')];
  for (const small of [true,false]) {
    run(`navigationMedia.matches = ${small}; setNavigationOpen(false)`);
    assert.equal(element('app-tabbar').inert,false,'persistent capsule must remain interactive');
    assert.equal(element('app-tabbar').attributes['aria-modal'],undefined);
    assert.equal(element('body').classList.contains('drawer-open'),false);
  }
  run(`renderPools([{name:'one',nodes:[],node_removals:{a:{ip:'193.148.253.149',status:'succeeded',message:'نود از استخر حذف شد'}},transport_change:{status:'succeeded',from:'pck',to:'tcp',completed:2,total:2,message:'تمام شد'}}])`);
  const completedHtml = element('pools-container').innerHTML;
  assert.match(completedHtml, /<details class="operation-history"[^>]*><summary>سوابق عملیات/);
  assert.doesNotMatch(completedHtml, /operation-history[^>]* open/);
  assert.doesNotMatch(completedHtml, /role="status"/,'completed jobs must not masquerade as active announcements');
  run(`rememberOperationHistory('one',true); renderPools([{name:'one',nodes:[],transport_change:{status:'succeeded'}}])`);
  assert.match(element('pools-container').innerHTML, /operation-history[^>]* open/);
  run(`renderPools([{name:'one',nodes:[{ip:'192.0.2.1'}],transport_change:{status:'rollback_failed',message:'restore failed',error:'SSH <error>'}}])`);
  assert.match(element('pools-container').innerHTML, /is-failed/);
  assert.match(element('pools-container').innerHTML, /retryTransportRollback/);
  assert.match(element('pools-container').innerHTML, /SSH &lt;error&gt;/);
  assert.match(element('pools-container').innerHTML, /openAddNodeModal[^>]*disabled/);
  run(`renderWatchdogRoutes({pools:[{...multiPool,dns_scope:'all_subdomains'}]})`);
  assert.match(element('watchdog-domain-routes').innerHTML,/a.example.test/);
  assert.match(element('watchdog-domain-routes').innerHTML,/b.example.test/);
  // Inline error remains beside the form after the toast timer expires.
  const errorElement = element('inline-form-error');
  element('create-pool-submit-btn').closest = () => ({querySelector:()=>errorElement});
  context.fetch = async () => ({status:409,ok:false,json:async()=>({error:'port conflict'})});
  await run(`apiFetch('/api/pools/create',{method:'POST',body:{}})`);
  assert.equal(errorElement.textContent,'port conflict');
  context.fetch = async () => {throw new Error('offline');};
  await assert.rejects(run(`apiFetch('/api/pools/create',{method:'POST',body:{}})`),/offline/);
  assert.match(errorElement.textContent,/تأیید نشده/);
  console.log('PASS: quiet completed history, visible failures, mutation locks, DNS records and durable form errors');
  run(`renderPools([{name:'gre-one',engine:'gre',transport:'gre',gre_mtu:1280,nodes:[{name:'iran',ip:'192.0.2.1',engine:'gre',transport:'gre',security:'ipsec',gre:{mtu:1280,local_private:'10.203.0.1',remote_private:'10.203.0.2'}}]}])`);
  assert.match(element('pools-container').innerHTML,/GRE · MTU 1280/);
  assert.match(element('pools-container').innerHTML,/IPsec \/ AES-GCM/);
  assert.doesNotMatch(element('pools-container').innerHTML,/بدون رمزنگاری/);
  assert.match(element('pools-container').innerHTML,/10.203.0.1/);
  assert.match(element('pools-container').innerHTML,/openGreSettingsModal/);
  assert.match(element('pools-container').innerHTML,/openTransportModal/);
  run(`renderPools([{name:'gre-one',transport:'gre',nodes:[],gre_update:{status:'rollback_failed',kind:'mtu',message:'restore failed'}}])`);
  assert.match(element('pools-container').innerHTML,/recoverGreSettings/);
  assert.doesNotMatch(element('pools-container').innerHTML,/retryTransportRollback/);
  assert.match(element('pools-container').innerHTML,/openAddNodeModal[^>]*disabled/);
  console.log('PASS: GRE private endpoints, MTU settings and dedicated recovery actions');
  run(`renderPools([{name:'https-one',engine:'xray',transport:'xhttp',camouflage:{server_name:'tunnel.example.com'},nodes:[{name:'iran',ip:'192.0.2.1',engine:'xray',transport:'xhttp',https:{server_name:'tunnel.example.com',outer_port:8443}}]}])`);
  assert.match(element('pools-container').innerHTML,/Xray · xhttp/);
  assert.match(element('pools-container').innerHTML,/tunnel.example.com:8443/);
  assert.match(element('pools-container').innerHTML,/openTransportModal/);
  const httpsInputs=['https-server-name','https-outer-port','https-certificate','https-key','https-binary'].map(element);
  element('https-create-fields').querySelectorAll=()=>httpsInputs;
  element('new-pool-proto').value='xhttp';run(`updateGreCreateFields()`);
  assert.equal(element('https-create-fields').classList.contains('hidden'),false);
  assert.equal(element('https-server-name').disabled,false);
  assert.equal(element('new-pool-gre-mtu').disabled,true);
  element('new-pool-proto').value='pck';run(`updateGreCreateFields()`);
  assert.equal(element('https-create-fields').classList.contains('hidden'),true);
  assert.ok(httpsInputs.every(input=>input.disabled));
  console.log('PASS: HTTPS profile rendering and hidden field constraints');

  // Verify cascading engine to transport population
  element('new-pool-engine').value = 'paqet';
  run('onPoolEngineChanged()');
  assert.match(element('new-pool-proto').innerHTML, /value="quantum"/);
  assert.match(element('new-pool-proto').innerHTML, /value="quantum\+"/);
  assert.match(element('new-pool-proto').innerHTML, /value="quantum-gaming"/);
  assert.match(element('new-pool-proto').innerHTML, /value="paqet"/);
  assert.doesNotMatch(element('new-pool-proto').innerHTML, /value="stealth"/);

  element('new-pool-engine').value = 'backpack';
  run('onPoolEngineChanged()');
  assert.match(element('new-pool-proto').innerHTML, /value="stealth"/);
  assert.match(element('new-pool-proto').innerHTML, /value="pck"/);
  assert.doesNotMatch(element('new-pool-proto').innerHTML, /value="quantum"/);

  element('new-pool-engine').value = 'waterwall';
  run('onPoolEngineChanged()');
  assert.match(element('new-pool-proto').innerHTML, /value="waterwall"/);
  element('new-pool-engine').value = 'kernel';
  run('onPoolEngineChanged()');
  assert.doesNotMatch(element('new-pool-proto').innerHTML, /value="tun" disabled/);
  assert.doesNotMatch(element('new-pool-proto').innerHTML, /value="dc6" disabled/);
  assert.equal(element('new-pool-proto').value, 'wireguard');
  console.log('PASS: Cascading tunnel engine to transport selection');

  for(const mode of ['fake-sni','split-tls','hop-ttl-injection','tcp-state-desync','l7-header-mutation']){
    element('new-pool-proto').value=mode;
    run('updateGreCreateFields()');
    assert.equal(element('new-pool-engine').value,'spoof');
    assert.equal(element('spoof-ip-list').disabled,true);
    assert.equal(element('spoof-dns-resolvers').disabled,true);
    assert.equal(element('spoof-fake-sni').disabled,!['fake-sni','hop-ttl-injection'].includes(mode));
    assert.equal(element('spoof-ttl-delta').disabled,mode!=='hop-ttl-injection');
  }
  run("populatePoolTransports('spoof')");
  assert.match(element('new-pool-proto').innerHTML,/value="l3-ip-spoof" disabled/);
  assert.doesNotMatch(element('new-pool-proto').innerHTML,/value="fake-sni" disabled/);
  console.log('PASS: packet profiles expose only implemented options and relevant inputs');


  // Verify universal transport change modal cascading
  run(`cachedStatus = { pools: [{ name: 'test-p1', transport: 'pck', engine: 'backpack', nodes: [{ ip: '1.2.3.4' }] }] }`);
  run("openTransportModal('test-p1')");
  assert.equal(element('transport-change-engine').value, 'backpack');
  assert.match(element('transport-target').innerHTML, /value="stealth"/);
  assert.match(element('transport-target').innerHTML, /value="tcp"/);
  assert.match(element('transport-summary').innerHTML, /test-p1/);

  // Switch target engine to paqet in transport modal
  element('transport-change-engine').value = 'paqet';
  run('onTransportChangeEngineChanged()');
  assert.match(element('transport-target').innerHTML, /value="quantum"/);
  assert.match(element('transport-target').innerHTML, /value="quantum\+"/);
  assert.doesNotMatch(element('transport-target').innerHTML, /value="stealth"/);

  // Switch target transport to quantum+ and verify FEC fields unhide
  element('transport-target').value = 'quantum+';
  run('onTransportChangeTransportChanged()');
  assert.equal(element('transport-change-fec-fields').classList.contains('hidden'), false);

  // Switch target engine to xray and verify TLS fields unhide
  element('transport-change-engine').value = 'xray';
  run('onTransportChangeEngineChanged()');
  element('transport-target').value = 'xhttp';
  run('onTransportChangeTransportChanged()');
  assert.equal(element('transport-change-tls-fields').classList.contains('hidden'), false);
  console.log('PASS: Universal transport modal cascading and adaptive field triggers');

  // Managed HTTP modes may switch within their family only.
  run(`cachedStatus = {pools:[{name:'http-pool',transport:'http',engine:'http',nodes:[]}]}`);
  run("openTransportModal('http-pool')");
  assert.match(element('transport-target').innerHTML, /value="http" disabled/);
  assert.doesNotMatch(element('transport-target').innerHTML, /value="https" disabled/);
  assert.match(element('transport-target').innerHTML, /value="ws" disabled/);
  assert.equal(element('transport-target').value, 'https');
  element('transport-change-engine').value = 'paqet';
  run('onTransportChangeEngineChanged()');
  assert.match(element('transport-target').innerHTML, /value="quantum" disabled/);
  assert.equal(element('transport-target').value, '');
  run(`cachedStatus = {pools:[{name:'tcp-pool',transport:'tcp',engine:'backpack',nodes:[]}]}`);
  run("openTransportModal('tcp-pool')");
  element('transport-change-engine').value=run('TRANSPORT_TO_ENGINE.http');
  run('onTransportChangeEngineChanged()');
  assert.match(element('transport-target').innerHTML, /value="http" disabled/);
  assert.match(element('transport-target').innerHTML, /value="https" disabled/);
  console.log('PASS: HTTP mode migration excludes cross-family targets');



// Untrusted labels must round-trip as data, never become handler source.
const hostile = `');globalThis.__injected = true;//"<img src=x onerror=alert(1)>`;
context.hostile = hostile;
run(`renderPools([{name:hostile,subdomain:hostile,client_ports:[8443],nodes:[{name:hostile,ip:'192.0.2.1'}]}])`);
const rendered = element('pools-container').innerHTML;
const logButton = rendered.match(/<button class="node-log-btn" ([^>]+)>/)[1];
const attrs = Object.fromEntries([...logButton.matchAll(/([\w-]+)="([^"]*)"/g)].map(m => [m[1], m[2]]));
const decode = s => s.replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
let received;
const proofContext = vm.createContext({openLogsModal: (...args) => {received = args;}, button: {dataset: {arg0:decode(attrs['data-arg0']),arg1:decode(attrs['data-arg1']),pool:decode(attrs['data-pool'])}}});
vm.runInContext(`(function(){${decode(attrs.onclick)}}).call(button)`, proofContext);
assert.deepEqual(received, ['192.0.2.1', hostile, hostile]);
assert.equal(proofContext.__injected, undefined);
for (const match of rendered.matchAll(/onclick="([^"]*)"/g)) assert.ok(!decode(match[1]).includes('__injected'));
console.log('PASS: hostile names remain data in action handlers');

// Execute the delivered topology script and exercise repeated listener setup.
const topology = fs.readFileSync(path.join(root, 'web/topology.html'), 'utf8');
const script = topology.match(/<script>([\s\S]*?)<\/script>/);
assert.ok(script, 'topology script must have a closing tag');
const topologyContext = vm.createContext({console, AbortController,
 window:{addEventListener(){}}, document:{getElementById:element, addEventListener(){}, documentElement:{dataset:{}}},
 localStorage:{getItem:()=>null}, setInterval(){}, setTimeout(){},
 fetch:async()=>{throw new Error('test offline');}
});
vm.runInContext(script[1].replace(/^load\(false\);$/m,''), topologyContext);
vm.runInContext(`showDetail({type:'kharej',ip:'192.0.2.1',pool:'sample'}); hideDetail()`, topologyContext);
const svg = new EventTarget(); svg.style = {};
let transforms = 0;
topologyContext.svg = svg;
topologyContext.group = {setAttribute(){transforms++;}};
vm.runInContext('enablePanZoom(svg,group); enablePanZoom(svg,group)',topologyContext);
const wheel = new Event('wheel', {cancelable:true}); wheel.deltaY = -1;
svg.dispatchEvent(wheel);
assert.equal(transforms, 1, 'refresh must not multiply zoom listeners');
console.log('PASS: topology details and single zoom handler after refresh');

  run(`cachedServers={iran:[{name:'IR 1',ip:'192.0.2.1'},{name:'IR 2',ip:'192.0.2.2'}],kharej:[{name:'OUT',ip:'198.51.100.1'}]};
    globalThis.matrixSelection=[];
    document.querySelectorAll=(selector)=>selector==='input[data-matrix-pair]:checked'?globalThis.matrixSelection:[];
    formError=(_button,message)=>{globalThis.lastMatrixError=message;};
    fetchStatus=async()=>{};showToast=()=>{};
    apiFetch=async(endpoint,options)=>{globalThis.matrixSubmission={endpoint,body:options.body};return {accepted:true};};
    openMatrixModal();`);
  assert.equal(element('matrix-submit').disabled, true);
  assert.match(element('matrix-pairs').innerHTML,/data-matrix-pair="0"/);
  assert.match(element('matrix-pairs').innerHTML,/data-matrix-pair="1"/);
  await run(`submitMatrix({preventDefault(){}})`);
  assert.match(run('lastMatrixError'), /حداقل/);
  run(`matrixSelection=[{dataset:{matrixPair:'0'}}];updateMatrixPreview();`);
  element('matrix-port').value='51820';element('matrix-mtu').value='1400';
  await run(`submitMatrix({preventDefault(){}})`);
  assert.equal(run('matrixSubmission.endpoint'), '/api/links/matrix');
  assert.equal(run('JSON.stringify(matrixSubmission.body.pairs)'), '[["192.0.2.1","198.51.100.1"]]');
  assert.ok(element('matrix-modal').classList.contains('hidden'));
  run(`renderPrivateLinks({private_links:{one:{link_name:'<unsafe>',engine_id:'wireguard',status:'active',iran_server:{ip:'192.0.2.1'},kharej_server:{ip:'198.51.100.1'}}},link_tasks:{}})`);
  assert.match(element('private-links-list').innerHTML,/&lt;unsafe&gt;/);
  assert.match(element('private-links-list').innerHTML,/سلامت فعلی تأیید نشده/);
  run(`renderPrivateLinks({private_links:{one:{link_name:'fresh',engine_id:'wireguard',status:'active',telemetry:{status:'HEALTHY',checked_at:Date.now()/1000}}}})`);
  assert.match(element('private-links-list').innerHTML,/مسیر سالم/);
  run(`renderPrivateLinks({private_links:{one:{link_name:'stale',engine_id:'wireguard',status:'active',telemetry:{status:'HEALTHY',checked_at:Date.now()/1000-120}}}})`);
  assert.doesNotMatch(element('private-links-list').innerHTML,/مسیر سالم/);
  run(`globalThis.savedLinkNow=Date.now;globalThis.linkNow=Date.now();Date.now=()=>linkNow;
    globalThis.linkSnapshot={private_links:{one:{link_name:'same',engine_id:'wireguard',status:'active',telemetry:{status:'HEALTHY',checked_at:linkNow/1000}}}};
    renderPrivateLinks(linkSnapshot);linkNow+=120000;renderPrivateLinks(linkSnapshot);Date.now=savedLinkNow;`);
  assert.doesNotMatch(element('private-links-list').innerHTML,/مسیر سالم/);
  console.log('PASS: matrix requires explicit pairs, submits only selection, closes on admission and labels last verified status');

  run(`cachedStatus={pools:[{name:'dns',engine:'slipstream',slipstream:{domain:'tunnel.example.com',resolvers:['1.1.1.1:53'],dns_port:53,rate_limit:1000,slipstream_runtime_version:3}}]};
    formError=(_button,message)=>{globalThis.lastSlipstreamError=message;};
    showToast=()=>{}; fetchStatus=async()=>{};
    apiFetch=async(endpoint,options)=>{globalThis.settingsSubmission={endpoint,body:options.body};return {accepted:true};};
    openSlipstreamSettingsModal('dns');`);
  assert.equal(element('slipstream-settings-rate').value, 1000);
  element('slipstream-settings-rate').value = '120';
  await run(`submitSlipstreamSettings({preventDefault(){}})`);
  assert.equal(run(`settingsSubmission.endpoint`), '/api/pools/slipstream-settings');
  assert.equal(run(`JSON.stringify(settingsSubmission.body.settings)`), '{"rate_limit":120}');
  assert.ok(element('slipstream-settings-modal').classList.contains('hidden'));
  run(`openSlipstreamSettingsModal('dns');apiFetch=async()=>({accepted:false,error:'تنظیمات رد شد'});`);
  element('slipstream-settings-domain').value='changed.example.com';
  await run(`submitSlipstreamSettings({preventDefault(){}})`);
  assert.equal(element('slipstream-settings-domain').value, 'changed.example.com');
  assert.ok(!element('slipstream-settings-modal').classList.contains('hidden'));
  assert.equal(run('lastSlipstreamError'), 'تنظیمات رد شد');
  run(`cachedStatus.pools[0].slipstream.slipstream_runtime_version=1;openSlipstreamSettingsModal('dns');`);
  assert.equal(element('slipstream-settings-rate').disabled, true);
  console.log('PASS: Slipstream settings submit only edits, close on admission, retain rejected input and disable legacy QPS');

  console.log('PASS: telemetry, stale/API errors, persistent capsule navigation');

  // 7.7: mutation-locked buttons carry a visible reason and aria attributes.
  run(`renderPools([{name:'busy-one',nodes:[{ip:'192.0.2.1',status:'HEALTHY'}],operation_task:{status:'running',kind:'ports_add',message:'working'}}])`);
  const lockedHtml = element('pools-container').innerHTML;
  assert.match(lockedHtml, /pool-lock-notice/);
  assert.match(lockedHtml, /aria-disabled="true"/);
  assert.match(lockedHtml, /title="[^"]*در جریان است[^"]*"/);
  // 7.7: DNS-move button explains missing Cloudflare when pool is not locked.
  run(`renderPools([{name:'free-one',cf_enabled:false,nodes:[{ip:'192.0.2.1',status:'HEALTHY'}]}])`);
  assert.match(element('pools-container').innerHTML, /title="ابتدا Cloudflare را برای این استخر فعال کنید"/);
  console.log('PASS: locked buttons expose a visible reason');

  // 7.10: pool search + engine filter narrow the rendered pools.
  run(`cachedStatus={pools:[
    {name:'alpha',engine:'gre',transport:'gre',kharej_ip:'203.0.113.10',nodes:[{ip:'192.0.2.1',name:'ir-1'}]},
    {name:'beta',engine:'vxlan',transport:'vxlan',kharej_ip:'203.0.113.20',nodes:[{ip:'192.0.2.2',name:'ir-2'}]}]};
    lastRenderedPools='';`);
  run(`setPoolSearch('203.0.113.20')`);
  const filteredHtml = element('pools-container').innerHTML;
  assert.match(filteredHtml, /beta/); assert.doesNotMatch(filteredHtml, /alpha/);
  run(`setPoolSearch(''); setPoolEngineFilter('gre')`);
  const engineHtml = element('pools-container').innerHTML;
  assert.match(engineHtml, /alpha/); assert.doesNotMatch(engineHtml, /beta/);
  run(`setPoolEngineFilter('')`);
  console.log('PASS: pool search and engine filter');

  element('https-create-fields').querySelectorAll = () => [];
  element('new-pool-proto').value = 'waterwall';
  element('https-binary').value = '/usr/local/bin/xray';
  run('updateGreCreateFields()');
  assert.equal(element('https-binary').value, '/usr/local/bin/waterwall');
  assert.equal(element('query').textContent, 'مسیر WaterWall روی هر دو سرور');
  element('new-pool-proto').value = 'xhttp';
  run('updateGreCreateFields()');
  assert.equal(element('https-binary').value, '/usr/local/bin/xray');
  element('https-binary').value = '/opt/custom/engine';
  element('new-pool-proto').value = 'waterwall';
  run('updateGreCreateFields()');
  assert.equal(element('https-binary').value, '/opt/custom/engine');
  console.log('PASS: WaterWall binary defaults follow the engine and preserve custom paths');


  // 7.10: server search narrows inventory.
  run(`cachedServers={iran:[{name:'tehran',ip:'192.0.2.1',username:'root'},{name:'shiraz',ip:'192.0.2.2',username:'root'}],kharej:[{name:'fra',ip:'198.51.100.5',username:'debian'}]};
    setServerSearch('shiraz')`);
  const srvHtml = element('servers-container').innerHTML;
  assert.match(srvHtml, /shiraz/); assert.doesNotMatch(srvHtml, /tehran/);
  run(`setServerSearch('')`);
  console.log('PASS: server inventory search');

  // 7.12: topology empty-state renders no pictographic emoji.
  const topoHtml = fs.readFileSync(path.join(root,'web/topology.html'),'utf8');
  assert.doesNotMatch(topoHtml, /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u, 'topology must not embed emoji');
  console.log('PASS: topology has no emoji');

  // 7.12: app.js user-facing strings contain no pictographic emoji.
  const appSrc = fs.readFileSync(path.join(root,'web/app.js'),'utf8');
  const emojiRe = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u;
  // Emoji may legitimately appear inside log-classification regexes (e.g. l.includes("✅")) —
  // those never reach the user. Flag any other line that carries an emoji.
  const offenderLines = appSrc.split('\n').filter(line => emojiRe.test(line) && !/l\.includes\(/.test(line));
  assert.deepEqual(offenderLines, [], `lines with emoji: ${offenderLines.slice(0,3).join(' | ')}`);
  console.log('PASS: app.js user-facing strings contain no emoji');
})().catch(error => { console.error(error); process.exitCode = 1; });
vm.runInContext(`renderWatchdogRoutes({pools:[{name:'A',subdomain:'a.test',cf_enabled:true,dns_report:{subdomain:'a.test',checked_at:'now',healthy_ips:['192.0.2.2'],dns_snapshot:{success:true,records:[{content:'192.0.2.1'}]}}},{name:'B',subdomain:'b.test',dns_report:{subdomain:'old.test',dns_snapshot:{success:true,records:[{content:'192.0.2.99'}]}}}]})`,context);
assert.match(element('watchdog-domain-routes').innerHTML,/a.test/);
assert.match(element('watchdog-domain-routes').innerHTML,/192.0.2.1/);
assert.doesNotMatch(element('watchdog-domain-routes').innerHTML,/192.0.2.2/);
assert.doesNotMatch(element('watchdog-domain-routes').innerHTML,/192.0.2.99/);
assert.match(element('watchdog-domain-routes').innerHTML,/تأیید نشده/);

assert.equal(vm.runInContext("poolDnsState({subdomain:'a.test',dns_override:{version:'new'},dns_report:{subdomain:'a.test',override_version:'old',dns_snapshot:{success:true,records:[{content:'192.0.2.1'}]}}}).verified",context),false);
assert.match(element('watchdog-domain-routes').innerHTML,/dns-route-list-row/);

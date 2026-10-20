/* ==========================================================================
   VX LB Control Panel Client Logic
   Full-Feature Parity with Core Script
   ========================================================================== */

let authToken = localStorage.getItem("ld_bp_token") || "";
let pollTimer = null;
let currentTab = localStorage.getItem("ld_bp_tab") || "pools";
let nodeFilter = "ALL";
let serverFilter = "ALL";
let poolSearch = "";
let poolEngineFilter = "";
let serverSearch = "";
let cachedStatus = null;
let cachedServers = null;
let currentPoolForAction = "";
let statusInFlight = false;
let statusRefreshPending = false;
let lastPoolsSnapshot = null;
let lastRenderedPools = "";
let toastTimer = null;
let lastDomainSnapshot = "";
const tabScroll = {};
const faNumber = { format: n => (n === null || n === undefined ? '' : String(n)) };
const copy = window.panelCopy;

const storedTheme = localStorage.getItem('ld_bp_theme');
if (storedTheme === 'light' || storedTheme === 'dark') {
  document.documentElement.dataset.theme = storedTheme;
} else {
  document.documentElement.dataset.theme = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}
let loginHairlineHandle = null;
let overviewHairlineHandle = null;
let pageHairlineHandle = null;
let currentOverviewFigure = "";
let currentPageFigure = "";

const TAB_FIGURES = {
  pools: "router",
  servers: "cabinet",
  watchdog: "dish",
  settings: "vault"
};

function setPageFigure(tabName) {
  const figName = TAB_FIGURES[tabName] || "router";
  const stage = document.getElementById("page-hairline-stage");
  if (!stage || !window.Hairline || typeof window.Hairline[figName] !== "function") return;
  if (pageHairlineHandle && currentPageFigure === figName) return;
  if (pageHairlineHandle) {
    try { pageHairlineHandle.destroy(); } catch (_) {}
    pageHairlineHandle = null;
  }
  stage.innerHTML = "";
  currentPageFigure = figName;
  pageHairlineHandle = window.Hairline[figName](stage, { play: true, intensity: 0.65 });
}

function setLoginFigure(figName, btn) {
  if (btn && btn.parentElement) {
    btn.parentElement.querySelectorAll(".story-fig-btn").forEach(b => b.classList.toggle("active", b === btn));
  }
  const stage = document.getElementById("login-hairline-stage");
  if (!stage || !window.Hairline || typeof window.Hairline[figName] !== "function") return;
  if (loginHairlineHandle) {
    try { loginHairlineHandle.destroy(); } catch (_) {}
    loginHairlineHandle = null;
  }
  stage.innerHTML = "";
  loginHairlineHandle = window.Hairline[figName](stage, { play: true, intensity: 0.65 });
}

function setOverviewFigure(figName, intensity = 0.6) {
  const stage = document.getElementById("overview-hairline-stage");
  if (!stage || !window.Hairline || typeof window.Hairline[figName] !== "function") return;
  if (overviewHairlineHandle && currentOverviewFigure === figName) {
    try { overviewHairlineHandle.update({ play: true, intensity }); } catch (_) {}
    return;
  }
  if (overviewHairlineHandle) {
    try { overviewHairlineHandle.destroy(); } catch (_) {}
    overviewHairlineHandle = null;
  }
  stage.innerHTML = "";
  currentOverviewFigure = figName;
  overviewHairlineHandle = window.Hairline[figName](stage, { play: true, intensity });
}

const cardHairlineHandles = new Map();
function mountCardHairlines() {
  if (!window.Hairline) return;
  document.querySelectorAll(".card-hairline-stage:not([data-mounted])").forEach(el => {
    const fig = el.dataset.hairline || "router";
    const fn = window.Hairline[fig];
    if (typeof fn !== "function") return;
    el.dataset.mounted = "1";
    const handle = fn(el, { play: true, intensity: parseFloat(el.dataset.intensity || "0.5") });
    cardHairlineHandles.set(el, handle);
  });
}

function mountEmptyHairlines() {
  if (!window.Hairline) return;
  document.querySelectorAll(".empty-state-hairline:not([data-mounted])").forEach(el => {
    const fig = el.dataset.hairline || "router";
    const fn = window.Hairline[fig] || window.Hairline.router;
    if (typeof fn === "function") {
      el.dataset.mounted = "1";
      fn(el, { play: true, intensity: 0.55 });
    }
  });
}

function updateThemeLogos(theme) {
  if (typeof document === 'undefined' || !document.querySelectorAll) return;
  const isLight = theme === 'light';
  const authLogos = document.querySelectorAll('.auth-logo-img');
  if (authLogos && authLogos.forEach) {
    authLogos.forEach(el => {
      el.src = isLight ? 'logo.svg' : 'logo-light.svg';
    });
  }
  const brandLogos = document.querySelectorAll('.brand-img');
  if (brandLogos && brandLogos.forEach) {
    brandLogos.forEach(el => {
      el.src = isLight ? 'mark-dark.svg' : 'mark.svg';
    });
  }
}

function toggleTheme() {
  const theme = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  document.documentElement.dataset.theme = theme;
  localStorage.setItem('ld_bp_theme', theme);
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.content = theme === 'light' ? '#f1f4f0' : '#101819';
  updateThemeLogos(theme);
}
function loadingMarkup() {
  return `<div class="skeleton" role="status" aria-label="${copy.loading}"><span></span><span></span><span></span></div>`;
}
function emptyMarkup(title, hint, label, action) {
  const fig = String(action || "").includes("Server") ? "cabinet" : "router";
  requestAnimationFrame(mountEmptyHairlines);
  return `<div class="empty-state"><div class="empty-state-hairline" data-hairline="${fig}" aria-hidden="true"></div><h4>${title}</h4><p>${hint}</p><button class="btn-primary sm" onclick="${action}">${label}</button></div>`;
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll('[data-copy]').forEach(element => {
    const text = copy.shell[element.dataset.copy];
    if (text) element.textContent = text;
  });
  setupDialogs();
  setupFormFeedback();
  setupNavigation();
  setLoginFigure("relay");
  setOverviewFigure("relay");
  setPageFigure(currentTab || "pools");
  mountCardHairlines();
  document.querySelectorAll('.nav-tab-btn').forEach(button => button.setAttribute('aria-current', button.classList.contains('active') ? 'page' : 'false'));
  const poolEngineSelect = document.getElementById("new-pool-engine");
  if (poolEngineSelect) {
    poolEngineSelect.addEventListener("change", onPoolEngineChanged);
    populatePoolTransports(poolEngineSelect.value || "backpack");
  }
  const poolProtoSelect = document.getElementById("new-pool-proto");
  if (poolProtoSelect) {
    poolProtoSelect.addEventListener("change", onPoolTransportChanged);
  }
  if (authToken) {
    showAppView();
    startPolling();
  } else {
    showLoginView();
  }
});

function showLoginView() {
  document.getElementById("login-view").classList.remove("hidden");
  document.getElementById("app-view").classList.add("hidden");
  const tabbar = document.getElementById("app-tabbar");
  if (tabbar) tabbar.classList.add("hidden");
  if (pollTimer) clearInterval(pollTimer);
  if (!loginHairlineHandle) setLoginFigure("relay");
}

function showAppView() {
  document.getElementById("login-view").classList.add("hidden");
  document.getElementById("app-view").classList.remove("hidden");
  const tabbar = document.getElementById("app-tabbar");
  if (tabbar) tabbar.classList.remove("hidden");
  if (!overviewHairlineHandle) setOverviewFigure("relay");
  setPageFigure(currentTab || "pools");
  mountCardHairlines();
  if (!cachedStatus) document.getElementById('pools-container').innerHTML = loadingMarkup();
  if (!cachedServers) document.getElementById('servers-container').innerHTML = loadingMarkup();
  fetchStatus();
  fetchServers();
  fetchDaemonLogs();
  if (currentTab && currentTab !== "pools") {
    switchTab(currentTab);
  }
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(() => {
    if (authToken) fetchStatus();
  }, 4000);
}

const formActions = {'/api/servers/add':'add-server-submit-btn','/api/pools/create':'create-pool-submit-btn',
  '/api/pools/add_node':'add-node-submit-btn','/api/ports':'add-port-submit-btn',
  '/api/pools/cloudflare':'pool-cf-submit-btn','/api/pools/cloudflare-preview':'pool-cf-submit-btn',
  '/api/cloudflare':'save-cf-global-btn','/api/password':'change-pass-btn','/api/pools/transport':'transport-submit','/api/pools/gre-settings':'gre-settings-submit',
  '/api/links/matrix':'matrix-submit','/api/pools/slipstream-settings':'slipstream-settings-submit','/api/dashboard-domain':'save-dash-domain-btn'};
const poolActionErrors = new Map();
function formError(buttonId, message) {
  const form = document.getElementById(buttonId)?.closest?.('form');
  if (!form) return;
  let error = form.querySelector('.form-error');
  if (!error) { error = document.createElement('p'); error.className = 'form-error'; error.setAttribute('role','alert'); form.append(error); }
  error.textContent = withoutEmoji(message); error.classList.toggle('hidden', !message);
}
function setupFormFeedback() {
  document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', () => { const error = form.querySelector('.form-error'); if (error) {error.textContent='';error.classList.add('hidden');} }, {capture:true});
    form.addEventListener('input', () => { const error = form.querySelector('.form-error'); if (error) {error.textContent='';error.classList.add('hidden');} });
  });
}
function clearPoolActionError(pool) { poolActionErrors.delete(pool); lastRenderedPools=''; if (cachedStatus) renderPools(cachedStatus.pools || []); }
async function apiFetch(endpoint, options = {}) {
  const body = options.body && typeof options.body === 'object' ? options.body : {};
  const button = options.method === 'POST' ? formActions[endpoint] : null;
  if (button) formError(button,'');
  if (options.method === 'POST' && body.pool) poolActionErrors.delete(body.pool);
  const report = message => {
    if (button) formError(button,message);
    if (body.pool && !button) {poolActionErrors.set(body.pool,message); lastRenderedPools=''; if (cachedStatus) renderPools(cachedStatus.pools || []);}
  };
  try {
    const result = await requestJson(endpoint, options);
    if (options.method === 'POST' && (result.error || result.success === false)) report(result.error || result.message || 'عملیات انجام نشد؛ دوباره تلاش کنید');
    return result;
  } catch (error) {
    if (authToken) report('ارتباط قطع شد؛ نتیجهٔ عملیات تأیید نشده است. وضعیت را بررسی کنید و سپس دوباره تلاش کنید.');
    throw error;
  }
}

async function requestJson(endpoint, options = {}) {
  options.headers = options.headers || {};
  options.headers["Authorization"] = `Bearer ${authToken}`;
  if (options.body && typeof options.body === "object") {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(options.body);
  }

  const res = await fetch(endpoint, options);
  if (res.status === 401) {
    localStorage.removeItem("ld_bp_token");
    authToken = "";
    showLoginView();
    throw new Error("Unauthorized");
  }
  if (!res.ok && (!options.method || options.method === "GET")) {
    let message = copy.loadFailed;
    try { const body = await res.json(); message = body.error || body.message || message; } catch (_) {}
    throw new Error(message);
  }
  return res.json();
}

/* ==========================================================================
   1. Auth Flow
   ========================================================================== */
async function handleLogin(e) {
  e.preventDefault();
  const pass = document.getElementById("password").value.trim();
  const errorEl = document.getElementById("login-error");
  const btn = document.getElementById("login-btn");
  errorEl.textContent = "";

  btn.disabled = true;
  btn.querySelector("span").textContent = "در حال بررسی...";

  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: pass })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      authToken = data.token;
      localStorage.setItem("ld_bp_token", authToken);
      showAppView();
      startPolling();
      showToast("ورود با موفقیت انجام شد");
    } else {
      errorEl.textContent = data.error || "رمز عبور نادرست است";
    }
  } catch (err) {
    errorEl.textContent = "خطا در اتصال به سرور";
  } finally {
    btn.disabled = false;
    btn.querySelector("span").textContent = "ورود به داشبورد";
  }
}

function handleLogout() {
  // Invalidate the server-side token too (it otherwise lives 7 days).
  try {
    fetch("/api/logout", {
      method: "POST",
      headers: { "Authorization": "Bearer " + authToken }
    }).catch(() => {});
  } catch (e) {}
  localStorage.removeItem("ld_bp_token");
  authToken = "";
  showLoginView();
  showToast("از حساب خارج شدید");
}

function togglePasswordVisibility(inputId, btn) {
  const input = document.getElementById(inputId);
  if (!input) return;
  if (input.type === "password") {
    input.type = "text";
    btn.style.color = "var(--accent-blue)";
  } else {
    input.type = "password";
    btn.style.color = "var(--text-muted)";
  }
}

/* ==========================================================================
   2. Navigation & Tabs
   ========================================================================== */
function switchTab(tab) {
  if (!authToken) {
    showLoginView();
    return;
  }
  if (!copy.pages[tab]) return;
  tabScroll[currentTab] = window.scrollY;
  currentTab = tab;
  try { localStorage.setItem("ld_bp_tab", tab); } catch (e) {}
  document.getElementById("network-summary").classList.toggle("hidden", tab !== "pools");
  document.getElementById('page-kicker').textContent = copy.kickers[tab];
  document.getElementById('page-heading').textContent = copy.pages[tab][0];
  document.getElementById('page-caption').textContent = copy.pages[tab][1];
  setPageFigure(tab);

  // Bottom tab buttons
  document.querySelectorAll(".nav-tab-btn").forEach(b => b.classList.remove("active"));
  const tabBtn = document.getElementById(`nav-tab-${tab}`);
  if (tabBtn) tabBtn.classList.add("active");
  document.querySelectorAll('.nav-tab-btn').forEach(button => button.setAttribute('aria-current', button === tabBtn ? 'page' : 'false'));

  // Show/Hide panels
  document.getElementById("tab-pools-view").classList.toggle("hidden", tab !== "pools");
  document.getElementById("tab-servers-view").classList.toggle("hidden", tab !== "servers");
  document.getElementById("tab-watchdog-view").classList.toggle("hidden", tab !== "watchdog");
  document.getElementById("tab-settings-view").classList.toggle("hidden", tab !== "settings");
  const cfView = document.getElementById("tab-cloudflare-view");
  if (cfView) cfView.classList.toggle("hidden", tab !== "cloudflare");

  if (tab === "servers") fetchServers();
  if (tab === "watchdog") fetchDaemonLogs();
  if (tab === "cloudflare") cfLoadProfiles();
  window.scrollTo({ top: tabScroll[tab] || 0, behavior: "instant" });
}

function setNodeFilter(f, btn) {
  nodeFilter = f;
  btn.parentElement.querySelectorAll(".segment-chip").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
  btn.parentElement.querySelectorAll('.segment-chip').forEach(button => button.setAttribute('aria-pressed', String(button === btn)));
  if (cachedStatus) renderPools(cachedStatus.pools || []);
}

function setServerFilter(f, btn) {
  serverFilter = f;
  btn.parentElement.querySelectorAll(".segment-chip").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
  btn.parentElement.querySelectorAll('.segment-chip').forEach(button => button.setAttribute('aria-pressed', String(button === btn)));
  if (cachedServers) renderServers(cachedServers);
}

function setPoolSearch(q) { poolSearch = String(q || "").trim().toLowerCase(); if (cachedStatus) { lastRenderedPools = ""; renderPools(cachedStatus.pools || []); } }
function setPoolEngineFilter(v) { poolEngineFilter = String(v || ""); if (cachedStatus) { lastRenderedPools = ""; renderPools(cachedStatus.pools || []); } }
function setServerSearch(q) { serverSearch = String(q || "").trim().toLowerCase(); if (cachedServers) renderServers(cachedServers); }

function poolMatchesFilters(p) {
  if (poolEngineFilter && (p.engine || p.transport || "") !== poolEngineFilter) return false;
  if (!poolSearch) return true;
  const hay = [p.name, p.kharej_ip, p.subdomain, p.engine, p.transport, ...(p.nodes || []).flatMap(n => [n.ip, n.name])]
    .filter(Boolean).join(" ").toLowerCase();
  return hay.includes(poolSearch);
}
function serverMatchesSearch(s) {
  if (!serverSearch) return true;
  return [s.name, s.ip, s.username, s.arch, s.role].filter(Boolean).join(" ").toLowerCase().includes(serverSearch);
}

/* ==========================================================================
   3. Status & Data Fetching
   ========================================================================== */
async function fetchStatus(force = false) {
  if (!authToken) return;
  if (cachedStatus) renderPrivateLinks(cachedStatus);
  if (statusInFlight) { statusRefreshPending ||= force; return; }
  statusInFlight = true;
  try {
    const data = await apiFetch("/api/status");
    if (!authToken) return;
    cachedStatus = data;
    updateHeroMetrics(data);
    renderPrivateLinks(data);
    const signature = JSON.stringify(data.pools || []);
    const transportInProgress = (data.pools || []).some(pool => ['queued','preflight','changing','validating','rolling_back','rollback_failed'].includes(pool.transport_change?.status));
    const removalChanged = JSON.stringify((data.pools || []).map(p => p.node_removals || {})) !== JSON.stringify((lastPoolsSnapshot || []).map(p => p.node_removals || {}));
    const removing = (data.pools || []).some(p => Object.values(p.node_removals || {}).some(j => ['queued','running'].includes(j.status)));
    const additionChanged = JSON.stringify((data.pools || []).map(p => p.node_additions || {})) !== JSON.stringify((lastPoolsSnapshot || []).map(p => p.node_additions || {}));
    const adding = (data.pools || []).some(p => Object.values(p.node_additions || {}).some(j => ['queued','running'].includes(j.status)));
    // Hold re-render while the user is interacting inside the pools list (typing
    // in search, holding a checkbox) and nothing structurally urgent changed.
    // We keep lastRenderedPools stale so the next non-focused poll cycle paints.
    const poolsContainer = document.getElementById('pools-container');
    const focusInsidePools = poolsContainer && poolsContainer.contains(document.activeElement);
    const urgent = additionChanged || adding || removalChanged || removing || transportInProgress;
    const hasFocus = !force && !urgent && focusInsidePools;
    if (signature !== lastRenderedPools && !hasFocus) {
      renderPools(data.pools || []);
      lastRenderedPools = signature;
      lastPoolsSnapshot = data.pools || [];
    } else if (hasFocus && poolsContainer && !poolsContainer.dataset.deferBound) {
      // Repaint once focus leaves the container (focusout bubbles).
      poolsContainer.dataset.deferBound = "1";
      poolsContainer.addEventListener('focusout', () => {
        setTimeout(() => {
          if (poolsContainer.contains(document.activeElement) || !cachedStatus) return;
          const sig = JSON.stringify(cachedStatus.pools || []);
          if (sig !== lastRenderedPools) {
            renderPools(cachedStatus.pools || []);
            lastRenderedPools = sig;
            lastPoolsSnapshot = cachedStatus.pools || [];
          }
        });
      });
    }
    updateWatchdogTabUI(data);
    document.getElementById('status-error').classList.add('hidden');
    const connection = document.getElementById('connection-label');
    connection.textContent = data.preview ? 'پیش‌نمایش محلی · دادهٔ آزمایشی' : copy.connected;
    connection.dataset.state = 'connected';
  } catch (e) {
    if (authToken) {
      document.getElementById('status-error').classList.remove('hidden');
      const connection = document.getElementById('connection-label');
      connection.textContent = copy.disconnected;
      connection.dataset.state = 'error';
      if (!cachedStatus) document.getElementById('pools-container').innerHTML = '';
    }
  } finally { statusInFlight = false; if (statusRefreshPending) { statusRefreshPending = false; fetchStatus(true); } }
}

function updateHeroMetrics(data) {
  const pools = data.pools || [];
  let totalIranNodes = 0;
  const uniqueKharej = [...new Set(pools.map(p => p.kharej_ip).filter(Boolean))];

  pools.forEach(p => {
    totalIranNodes += (p.nodes || []).length;
  });

  document.getElementById("hero-node-count-val").textContent = `${faNumber.format(totalIranNodes)} نود`;

  const kharejVal = document.getElementById("hero-kharej-ip-val");
  const kharejSub = document.getElementById("hero-kharej-sub-val");
  if (kharejVal) {
    if (uniqueKharej.length === 0) {
      kharejVal.textContent = "-";
      if (kharejSub) kharejSub.textContent = "استخری ثبت نشده";
    } else if (uniqueKharej.length === 1) {
      kharejVal.textContent = uniqueKharej[0];
      if (kharejSub) kharejSub.textContent = "مقصد استخرها";
    } else {
      kharejVal.textContent = `${faNumber.format(uniqueKharej.length)} سرور خارج`;
      if (kharejSub) {
        kharejSub.innerHTML = `<bdi dir="ltr">${escapeHtml(uniqueKharej.join(" · "))}</bdi>`;
      }
    }
  }

  document.getElementById("hero-pools-count-val").textContent = `${faNumber.format(pools.length)} استخر`;
  document.getElementById("pools-total-count-badge").textContent = faNumber.format(pools.length);

  const nodes = pools.flatMap(pool => pool.nodes || []);
  const healthy = nodes.filter(node => node.status === 'HEALTHY').length;
  const pending = nodes.filter(node => ['IDLE', 'CANARY'].includes(node.status)).length;
  const issues = nodes.length - healthy - pending;
  document.getElementById('healthy-count').textContent = faNumber.format(healthy);
  document.getElementById('health-total-label').textContent = `از مجموع ${faNumber.format(nodes.length)} نود`;
  const total = nodes.length || 0;
  for (const [kind, count] of [['good', healthy], ['warn', pending], ['bad', issues]]) {
    document.getElementById(`health-${kind}`).textContent = faNumber.format(count);
    document.getElementById(`health-track-${kind}`).style.width = total ? `${count / total * 100}%` : '0%';
  }
  const DONUT_C = 2 * Math.PI * 58;
  const gap = total ? Math.min(6, DONUT_C / total / 3) : 0;
  let donutOffset = 0;
  const donutStart = { good: healthy, warn: pending, bad: issues };
  for (const [kind, count] of Object.entries(donutStart)) {
    const seg = document.getElementById(`donut-${kind}`);
    if (!seg) continue;
    const frac = total ? count / total : 0;
    const len = Math.max(0, frac * DONUT_C - (frac > 0 && frac < 1 ? gap : 0));
    seg.style.strokeDasharray = `${len} ${DONUT_C - len}`;
    seg.style.strokeDashoffset = `${-donutOffset}`;
    donutOffset += frac * DONUT_C;
  }
  const pctEl = document.getElementById('healthy-pct');
  if (pctEl) pctEl.textContent = total ? `${faNumber.format(Math.round(healthy / total * 100))}٪` : '—';
  const statusPill = document.getElementById('hero-status-pill');
  const state = !nodes.length ? copy.noNodes : issues ? copy.issue : pending ? copy.waiting : copy.stable;
  statusPill.className = `hero-status-pill ${!nodes.length || pending ? 'warn' : 'good'}`;
  if (issues) statusPill.className = 'hero-status-pill error';
  document.getElementById('hero-status-pill-text').textContent = state;
  setOverviewFigure(!nodes.length ? 'cabinet' : issues ? 'patch' : pending ? 'dish' : 'relay', issues ? 0.85 : 0.6);
  const dnsConfigured = pools.some(pool => pool.cf_enabled) || Boolean(data.global_cloudflare?.enabled);
  document.getElementById('cf-summary-label').textContent = dnsConfigured ? copy.dnsReady : copy.dnsMissing;
  document.getElementById('hero-failover-sub-val').textContent = dnsConfigured ? copy.dnsReady : copy.dnsMissing;
  document.getElementById('hero-failover-sub-val').classList.toggle('good-text', dnsConfigured);
  document.getElementById('hero-node-sub-val').textContent = `${faNumber.format(healthy)} نود سالم`;

  renderDomainRoutes(data);

  // Last check
  document.getElementById("hero-last-check-time").textContent = "—";
  if (data.last_check) {
    const parts = data.last_check.split(" ");
    document.getElementById("hero-last-check-time").textContent = parts[1] || data.last_check;
  }

  // Daemon status in header
  const dLabel = document.getElementById("top-daemon-label");
  const dot = document.querySelector(".pulse-status-dot");
  if (data.daemon_running) {
    dLabel.textContent = "دیمن فعال";
    dot.classList.remove("stopped");
  } else {
    dLabel.textContent = "دیمن متوقف";
    dot.classList.add("stopped");
  }
}

/* ==========================================================================
   4. Render Pools & Nodes
   ========================================================================== */
const operationHistoryOpen = new Set();
const operationLabels = {task:'عملیات استخر',creation:'ساخت استخر',gre:'تنظیمات GRE',addition:'افزودن نود', removal:'حذف نود', transport:'تغییر تونل'};
function poolIsBusy(pool) {
  return ['queued','running'].includes(pool.operation_task?.status) || ['queued','running'].includes(pool.creation_job?.status) || ['running','rollback_failed'].includes(pool.gre_update?.status) || ['queued','preflight','changing','validating','rolling_back','rollback_failed'].includes(pool.transport_change?.status) ||
    ['node_additions','node_removals'].some(key => Object.values(pool[key] || {}).some(j => ['queued','running'].includes(j.status)));
}
function operationMarkup(pool, job, kind) {
  const active = ['queued','running','preflight','changing','validating','rolling_back'].includes(job.status);
  const failed = ['failed','rollback_failed'].includes(job.status);
  const targetId = kind === 'transport' ? '' : (job.ip || '');
  const description = kind === 'task' ? `<span>${job.kind === 'delete' ? 'حذف سرویس‌ها و منابع استخر' : job.kind === 'slipstream_settings' ? 'تغییر دامنه، resolver یا QPS تونل DNS' : job.kind === 'http_transport' ? 'تغییر HTTP/HTTPS و بررسی انتقال داده' : 'تغییر پورت‌های استخر'}</span>` : kind === 'creation' ? '<span>راه‌اندازی سرورها و تونل‌های استخر</span>' : kind === 'gre' ? '<span>تنظیمات لینک خصوصی و فوروارد پورت</span>' : kind === 'transport' ? `<span class="operation-route" dir="rtl">از <bdi dir="ltr">${escapeHtml(job.from)}</bdi> به <bdi dir="ltr">${escapeHtml(job.to)}</bdi><small style="color:var(--text-muted);font-size:10px;"> · ${faNumber.format(job.completed || 0)} از ${faNumber.format(job.total || 0)} نود</small></span>` : `<span class="op-ip-pill"><bdi dir="ltr">${escapeHtml(job.ip)}</bdi></span>`;
  const clearBtn = !active && job.status !== 'rollback_failed' ? `<button type="button" class="op-dismiss-btn" data-pool="${escapeHtml(pool.name)}" data-kind="${escapeHtml(kind)}" data-id="${escapeHtml(targetId)}" onclick="clearPoolOperation(this.dataset.pool, this.dataset.kind, this.dataset.id, this)" title="پاک کردن این پیام" aria-label="پاک کردن پیام">${uiIcon("close")}</button>` : '';

  return `<div class="operation-item ${active ? 'is-active' : failed ? 'is-failed' : 'is-complete'}" data-status="${escapeHtml(job.status)}" ${active ? 'role="status" aria-live="polite"' : ''}>
    <div class="operation-heading">
      <div class="op-heading-title">
        <strong>${['slipstream_runtime','slipstream_settings'].includes(job.kind) ? 'به‌روزرسانی تنظیمات Slipstream' : job.kind === 'http_transport' ? 'تغییر HTTP/HTTPS' : job.kind === 'relay_ports' ? 'به‌روزرسانی پورت‌های رله' : job.kind === 'waterwall_ports' ? 'به‌روزرسانی پورت‌های WaterWall' : job.kind === 'paqet_ports' ? 'به‌روزرسانی پورت‌های Paqet' : job.kind === 'https_ports' ? 'به‌روزرسانی پورت‌های HTTPS' : operationLabels[kind] || 'عملیات'}</strong>
        <span class="status-badge ${failed ? 'filtered' : active ? 'canary' : 'healthy'}">${failed ? 'نیازمند بررسی' : active ? 'در حال انجام' : job.status === 'rolled_back' ? 'بازگردانی شد' : 'پایان یافت'}</span>
      </div>
      ${clearBtn}
    </div>
    <div class="op-desc-line">
      ${description}
      ${job.message ? `<p class="op-msg">${escapeHtml(withoutEmoji(job.message || ''))}</p>` : ''}
    </div>
    ${job.error ? `<details class="operation-error"><summary>جزئیات خطا</summary><pre dir="auto">${escapeHtml(withoutEmoji(job.error))}</pre></details>` : ''}
    ${job.status === 'rollback_failed' && kind === 'gre' ? `<button type="button" class="btn-secondary sm" data-pool="${escapeHtml(pool.name)}" onclick="recoverGreSettings(this.dataset.pool,this)">بازگردانی تنظیمات ${job.kind === 'slipstream_runtime' ? 'Slipstream' : job.kind === 'http_transport' ? 'تغییر HTTP/HTTPS' : job.kind === 'relay_ports' ? 'پورت‌ها' : 'GRE'}</button>` : ''}${job.status === 'rollback_failed' && kind !== 'gre' ? `<div class="operation-actions"><button type="button" class="btn-secondary sm" data-pool="${escapeHtml(pool.name)}" onclick="retryTransportRollback(this.dataset.pool,this)">تلاش دوباره برای بازگردانی</button><button type="button" class="btn-danger sm" data-pool="${escapeHtml(pool.name)}" onclick="abandonTransportChange(this.dataset.pool,this)">رها کردن عملیات شکست‌خورده</button></div>` : ''}
  </div>`;
}
function renderPoolOperations(pool) {
  const jobs = [...(pool.operation_task ? [[pool.operation_task,'task']] : []), ...(pool.creation_job ? [[pool.creation_job,'creation']] : []), ...Object.values(pool.node_removals || {}).map(job => [job,'removal']),
    ...Object.values(pool.node_additions || {}).map(job => [job,'addition']),
    ...(pool.transport_change ? [[pool.transport_change,'transport']] : []),
    ...(pool.gre_update ? [[pool.gre_update,'gre']] : [])];
  const finished = jobs.filter(([job]) => ['succeeded','rolled_back','abandoned'].includes(job.status));
  const attention = jobs.filter(([job]) => ['failed','rollback_failed'].includes(job.status));
  // Pending additions have their own server row. Other active work is grouped here.
  const active = jobs.filter(([job,kind]) => kind !== 'addition' && ['queued','running','preflight','changing','validating','rolling_back'].includes(job.status));
  return active.map(([job,kind]) => operationMarkup(pool,job,kind)).join('') + attention.map(([job,kind]) => operationMarkup(pool,job,kind)).join('') +
    (finished.length ? `<details class="operation-history" data-pool="${escapeHtml(pool.name)}" ${operationHistoryOpen.has(pool.name) ? 'open' : ''} ontoggle="rememberOperationHistory(this.dataset.pool,this.open)"><summary>سوابق عملیات <span>(${faNumber.format(finished.length)})</span><button type="button" class="btn-secondary sm op-clear-all-btn" data-pool="${escapeHtml(pool.name)}" onclick="event.preventDefault();event.stopPropagation();clearPoolOperation(this.dataset.pool,'all','',this);">پاکسازی همه</button></summary><div class="operation-history-body">${finished.map(([job,kind]) => operationMarkup(pool,job,kind)).join('')}</div></details>` : '');
}
async function clearPoolOperation(poolName, kind, targetId, button) {
  if (button) button.disabled = true;
  try {
    const res = await apiFetch("/api/pools/clear-operation", {
      method: "POST",
      body: { pool: poolName, kind: kind, id: targetId }
    });
    if (res.success) {
      showToast(res.message || "پیام پاک شد");
      lastRenderedPools = "";
      await fetchStatus(true);
    } else {
      showToast(res.error || "خطا در پاک کردن پیام");
    }
  } catch (e) {
    showToast("خطا در ارتباط با سرور");
  } finally {
    if (button) button.disabled = false;
  }
}
function rememberOperationHistory(pool, open) {
  if (open) operationHistoryOpen.add(pool); else operationHistoryOpen.delete(pool);
}

function getEngineBadge(engine, transport) {
  const eng = (engine || "").toLowerCase();
  const tr = (transport || "").toLowerCase();
  let cls = "engine-other";
  let label = engine || transport || "Unknown";

  if (eng === "backpack" || ["stealth", "pck", "mux"].includes(tr)) {
    cls = "engine-backpack";
    label = "BackPack";
  } else if (eng === "paqet" || tr.startsWith("quantum") || tr === "paqet") {
    cls = "engine-paqet";
    label = "Paqet";
  } else if (eng === "waterwall" || tr === "waterwall") {
    cls = "engine-waterwall";
    label = "WaterWall";
  } else if (eng === "xray" || ["xhttp", "grpc", "ws", "h2", "gre_xhttp"].includes(tr)) {
    cls = "engine-xray";
    label = "Xray";
  } else if (["wireguard", "gre", "vxlan", "tun", "dc6", "geneve", "geneve_ipsec", "gre6", "ip6ip6"].includes(eng) ||
             ["wireguard", "gre", "vxlan", "tun", "dc6", "geneve", "geneve_ipsec", "gre6", "ip6ip6"].includes(tr)) {
    cls = "engine-kernel";
    label = (eng === "wireguard" || tr === "wireguard") ? "WireGuard" : "Kernel";
  } else if (eng === "slipstream" || tr === "slipstream") {
    cls = "engine-other";
    label = "Slipstream";
  }

  return `<span class="engine-badge ${cls}"><span class="engine-badge-dot"></span><span>${escapeHtml(label)}</span></span>`;
}

function renderPools(pools) {
  const container = document.getElementById("pools-container");
  if (!container) return;

  // Populate engine filter options from observed engines/transports.
  const engineSel = document.getElementById("pool-engine-filter");
  if (engineSel) {
    const engines = [...new Set(pools.map(p => p.engine || p.transport || "").filter(Boolean))].sort();
    const current = engineSel.value;
    const html = '<option value="">همهٔ موتورها</option>' + engines.map(e => `<option value="${escapeHtml(e)}">${escapeHtml(e)}</option>`).join("");
    if (engineSel.dataset.lastHtml !== html) { engineSel.innerHTML = html; engineSel.dataset.lastHtml = html; }
    if (engineSel.options && [...engineSel.options].some(o => o.value === current)) engineSel.value = current;
  }

  const visiblePools = pools.filter(poolMatchesFilters);
  if (!pools.length) {
    container.innerHTML = emptyMarkup(copy.noPools, copy.noPoolsHint, copy.createPool, "openCreatePoolModal()");
    return;
  }
  if (!visiblePools.length) {
    container.innerHTML = `<p class="empty-hint" style="padding:24px;text-align:center;">استخری مطابق فیلتر یا جست‌وجو نیست.</p>`;
    return;
  }
  pools = visiblePools;

  container.innerHTML = (pools.some(poolIsBusy) ? '<p id="pool-lock-notice" class="pool-lock-notice" role="status">عملیات استخر در حال انجام است؛ تغییر تنظیمات تا پایان آن موقتاً غیرفعال است. می‌توانید بخش‌های دیگر پنل را ببینید.</p>' : '') + pools.map(p => {
    const dns = poolDnsState(p);
    const poolDomain = p.subdomain && p.subdomain !== 'Not set' && p.subdomain !== 'تعیین نشده' ? p.subdomain : '';
    const transportJob = p.transport_change;
    const changingTransport = poolIsBusy(p);
    const mutationsLocked = pools.some(poolIsBusy) || p.creation_placeholder;
    const lockReason = p.creation_placeholder
      ? 'استخر در حال ساخت است؛ تا پایان راه‌اندازی تغییر ممکن نیست'
      : 'یک عملیات استخر در جریان است؛ تا پایان آن تغییر غیرفعال است';
    const lockAttrs = extra => mutationsLocked
      ? `disabled title="${escapeHtml(lockReason)}" aria-disabled="true" aria-describedby="pool-lock-notice"`
      : (extra || '');
    // Ports
    const portsHtml = (p.client_ports || []).map(port => `
      <span class="port-pill-badge">
        <span>${escapeHtml(String(port))}</span>
        <button class="port-del-cross" data-arg0="${escapeHtml(p.name)}" data-arg1="${escapeHtml(String(port))}" onclick="event.stopPropagation(); deletePort(this.dataset.arg0, this.dataset.arg1)" ${mutationsLocked ? `disabled title="${escapeHtml(lockReason)}" aria-disabled="true"` : 'title="حذف پورت"'}>${uiIcon("close")}</button>
      </span>
    `).join("");

    // Nodes with filter
    const filteredNodes = (p.nodes || []).filter(n => {
      if (nodeFilter === "HEALTHY") return n.status === "HEALTHY";
      if (nodeFilter === "ISSUE") return n.status !== "HEALTHY";
      return true;
    });

    const nodesHtml = filteredNodes.length ? filteredNodes.map(n => {
      let stClass = "unknown";
      let stLabel = "نامشخص";
      if (n.status === "PROVISIONING") { stClass = "canary"; stLabel = "در حال راه‌اندازی"; }
      if (n.status === "HEALTHY") { stClass = "healthy"; stLabel = "سالم"; }
      if (n.status === "DEGRADED") { stClass = "canary"; stLabel = "اختلال جزئی / مشکوک"; }
      if (n.status === "DOWN") { stClass = "unknown"; stLabel = "تانل قطع / پایش ناموفق"; }
      if (n.status === "CANARY") { stClass = "canary"; stLabel = "آزمایشی"; }
      else if (n.status === "FILTERED") { stClass = "filtered"; stLabel = "اختلال تأییدشده"; }
      else if (n.status === "IDLE") { stClass = "idle"; stLabel = "بدون ترافیک تازه"; }

      const latVal = typeof n.latency_ms === "number" && n.latency_ms > 0 ? n.latency_ms : (typeof n.ping_ms === "number" && n.ping_ms > 0 ? n.ping_ms : null);
      const latBadge = latVal !== null ? `<span class="node-latency-pill" title="پینگ / تأخیر پاسخ"><svg class="ui-icon" style="width:10px;height:10px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg><bdi>${Math.round(latVal)} ms</bdi></span>` : "";

      return `
        <div class="node-item-row">
          <div class="node-info-col">
            <div class="node-header-line">
              <span class="node-name">${escapeHtml(withoutEmoji(n.name))}</span>
              <span class="status-badge ${stClass}"><span class="pulse-dot"></span>${stLabel}</span>
              ${latBadge}
            </div>
            <div class="node-ip-row">
              <span class="node-ip-text">${escapeHtml(n.ip)}</span>
              <button class="copy-micro-btn" data-arg0="${escapeHtml(n.ip)}" onclick="copyText(this.dataset.arg0)" title="کپی آی‌پی نود">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
              </button>
              <small style="color: var(--text-muted); font-size: 10px;">${n.engine === "tun" || p.transport === "tun" ? `TUN / UDP / Noise · MTU ${escapeHtml(String(n.tun?.mtu || p.mtu || "1380"))} · TCPMSS Clamping` : n.engine === "dc6" || p.transport === "dc6" ? `DC6 (${escapeHtml(n.dc6?.carrier_type || p.carrier_type || "ip6gre")}) · MTU ${escapeHtml(String(n.dc6?.mtu || p.mtu || "1400"))} · MSS ${escapeHtml(String(n.dc6?.mss_clamp || n.dc6?.configs?.[0]?.mss_clamp || Number(n.dc6?.mtu || p.dc6_mtu || 1280) - 60))}` : (n.transport || "").startsWith("quantum") ? `${escapeHtml(n.transport)} · KCP Fast3 · ${escapeHtml(String(n.tunnel_port || p.tunnel_port || "443"))}` : ["http","https"].includes(n.engine) ? `${escapeHtml(String(n.http_connect?.mode || p.transport).toUpperCase())} CONNECT · mTLS · ${escapeHtml(String(n.http_connect?.public_port || ""))} · گواهی اختصاصی` : n.engine === "waterwall" ? `WaterWall · VLESS / TLS 1.3 / Mux · ${escapeHtml(n.waterwall?.profile?.server_name || p.camouflage?.server_name || "")}:${escapeHtml(String(n.waterwall?.outer_port || ""))}` : n.engine === "paqet" ? `Paqet · Raw KCP · ${escapeHtml(String(n.paqet?.tunnel_port || n.tunnel_port || p.tunnel_port || "443"))}` : n.engine === "xray" ? `Xray · ${(n.transport === "gre_xhttp" ? "GRE / XHTTP / TLS" : escapeHtml(n.transport))} · ${escapeHtml(n.https?.server_name)}:${escapeHtml(n.https?.outer_port)}` : n.engine === "vxlan" || p.transport === "vxlan" ? `VXLAN (${escapeHtml(n.vxlan?.method_title || n.vxlan?.method || p.vxlan_method || "P2P")}) · VNI ${escapeHtml(String(n.vxlan?.vni || p.vni || "1000"))} · UDP ${escapeHtml(String(n.vxlan?.dst_port || p.dst_port || "4789"))} · MTU ${escapeHtml(String(n.vxlan?.mtu || p.vxlan_mtu || "1400"))} · بدون رمزنگاری (Overlay خام) · آزمایشگاه ایزوله` : (n.engine === "wireguard" || p.transport === "wireguard") ? `WireGuard · پورت UDP ${escapeHtml(String(n.wireguard?.tunnel_port || p.wireguard_port || "51820"))} · MTU ${escapeHtml(String(n.wireguard?.mtu || p.wireguard_mtu || "1280"))} · رمزنگاری Curve25519/ChaCha20 · آزمایشی (آزمون کرنلی لینک تأیید شد)` : (n.engine === "gre6" || p.transport === "gre6") ? `GRE6 (RFC 7676) · MTU ${escapeHtml(String(n.gre6?.mtu || p.gre6_mtu || "1400"))} · بدون رمزنگاری (Cleartext خام IPv6) · آزمایشگاه ایزوله` : (n.engine === "ip6ip6" || p.transport === "ip6ip6") ? `IP6IP6 (RFC 2473) · MTU ${escapeHtml(String(n.ip6ip6?.mtu || p.ip6ip6_mtu || "1420"))} · بدون رمزنگاری (Cleartext خام IPv6) · آزمایشگاه ایزوله` : ['geneve','geneve_ipsec'].includes(n.engine) || n.transport === 'geneve_ipsec' ? `Geneve · VNI ${escapeHtml(String(n.geneve?.vni || "-"))} · MTU ${escapeHtml(String(n.geneve?.mtu || "1400"))} · IPsec / AES-GCM · آزمایشی (آزمون کرنلی لینک تأیید شد)` : n.engine === "gre" ? `GRE · MTU ${escapeHtml(n.gre?.mtu)} · ${n.security === "ipsec" ? "IPsec / AES-GCM" : "ناامن؛ نیازمند مهاجرت"}` : `(پورت تونل: ${escapeHtml(String(n.tunnel_port || "-"))} · ${escapeHtml(n.transport || p.transport || "tcp")})`}</small>
            </div>
            ${n.gre_https ? `<div class="gre-private-route"><span>GRE داخل HTTPS:</span><bdi dir="ltr">${escapeHtml(n.gre_https.local_private)}</bdi><span>به</span><bdi dir="ltr">${escapeHtml(n.gre_https.remote_private)}</bdi><span>MTU ${escapeHtml(n.gre_https.mtu)}</span></div>` : ''}
            ${(n.engine === 'tun' || p.transport === 'tun') ? `<div class="gre-private-route"><span>لینک TUN:</span><bdi dir="ltr">${escapeHtml(n.tun?.iran_inner || "10.210.1.1")}</bdi><span>به</span><bdi dir="ltr">${escapeHtml(n.tun?.kharej_inner || "10.210.1.2")}</bdi><span>(${escapeHtml(n.tun?.interface || "tun")}) · لایه 3 کرنل</span></div>` : ''}
            ${(n.engine === 'dc6' || p.transport === 'dc6') ? `<div class="gre-private-route"><span>حامل DC6:</span><bdi dir="ltr">${escapeHtml(n.dc6?.private_addressing?.iran_ipv4 || n.ip)}</bdi><span>به</span><bdi dir="ltr">${escapeHtml(n.dc6?.private_addressing?.kharej_ipv4 || p.kharej_ip)}</bdi><span>(${escapeHtml(n.dc6?.interface || "dc6")}) · Dual-Stack</span></div>` : ''}
            ${n.engine === 'gre' ? `<div class="gre-private-route"><span>لینک خصوصی:</span><bdi dir="ltr">${escapeHtml(n.gre?.local_private)}</bdi><span>به</span><bdi dir="ltr">${escapeHtml(n.gre?.remote_private)}</bdi></div>` : ''}
            ${(['geneve','geneve_ipsec'].includes(n.engine) || n.transport === 'geneve_ipsec') ? `<div class="gre-private-route"><span>لینک Geneve:</span><bdi dir="ltr">${escapeHtml(n.geneve?.local_private)}</bdi><span>به</span><bdi dir="ltr">${escapeHtml(n.geneve?.remote_private)}</bdi><span>(VNI ${escapeHtml(String(n.geneve?.vni || ""))})</span></div>` : ''}
            ${(n.engine === 'vxlan' || p.transport === 'vxlan') ? `<div class="gre-private-route"><span>لینک VXLAN:</span><bdi dir="ltr">${escapeHtml(n.vxlan?.local_private || n.ip)}</bdi><span>به</span><bdi dir="ltr">${escapeHtml(n.vxlan?.remote_private || p.kharej_ip)}</bdi><span>(پروفایل: ${escapeHtml(n.vxlan?.method_title || n.vxlan?.method || p.vxlan_method || "P2P")} · VNI ${escapeHtml(String(n.vxlan?.vni || p.vni || "1000"))}) · <strong style="color:var(--amber, #f59e0b);">بدون رمزنگاری</strong></span></div>` : ''}
            ${(n.engine === 'wireguard' || p.transport === 'wireguard') ? `<div class="gre-private-route"><span>لینک WireGuard:</span><bdi dir="ltr">${escapeHtml(n.wireguard?.local_private || "-")}</bdi><span>به</span><bdi dir="ltr">${escapeHtml(n.wireguard?.remote_private || "-")}</bdi><span>(${escapeHtml(n.wireguard?.interface || n.node_name || "-")}) · <strong style="color:var(--amber, #f59e0b);">${escapeHtml(n.wireguard?.status_note || "آزمایشی — آزمون واقعی اجرا نشده")}</strong></span></div>` : ''}
            ${(n.engine === 'gre6' || p.transport === 'gre6') ? `<div class="gre-private-route"><span>لینک GRE6:</span><bdi dir="ltr">${escapeHtml(n.gre6?.local_private || n.ip)}</bdi><span>به</span><bdi dir="ltr">${escapeHtml(n.gre6?.remote_private || p.kharej_ip)}</bdi><span>(اینترفیس ${escapeHtml(n.gre6?.interface || n.node_name || "-")}) · <strong style="color:var(--amber, #f59e0b);">بدون رمزنگاری (Cleartext)</strong></span></div>` : ''}
            ${(n.engine === 'ip6ip6' || p.transport === 'ip6ip6') ? `<div class="gre-private-route"><span>لینک IP6IP6:</span><bdi dir="ltr">${escapeHtml(n.ip6ip6?.local_private || n.ip)}</bdi><span>به</span><bdi dir="ltr">${escapeHtml(n.ip6ip6?.remote_private || p.kharej_ip)}</bdi><span>(اینترفیس ${escapeHtml(n.ip6ip6?.interface || n.node_name || "-")} · اختصاصی IPv6) · <strong style="color:var(--amber, #f59e0b);">بدون رمزنگاری (Cleartext)</strong></span></div>` : ''}
            <div class="node-dns-line"><span class="status-badge ${dns.verified ? (dns.ips.includes(n.ip) ? 'healthy' : 'idle') : 'unknown'}">${dns.verified ? (dns.ips.includes(n.ip) ? (p.dns_scope === 'all_subdomains' ? 'آی‌پی در همهٔ ساب‌دامین‌ها ثبت است' : 'آی‌پی در DNS ثبت است') : (p.dns_scope === 'all_subdomains' ? 'آی‌پی در همهٔ ساب‌دامین‌ها ثبت نیست' : 'آی‌پی در DNS نیست')) : 'وضعیت DNS تأیید نشده'}</span><span>${dns.source}</span></div>
            <div class="node-reason-text ${n.status === 'DEGRADED' || n.status === 'CANARY' ? 'has-issue' : (n.status === 'FILTERED' || n.status === 'DOWN') ? 'has-error' : ''}" title="${escapeHtml(n.reason)}">${n.status === 'DEGRADED' || n.status === 'CANARY' ? '<svg class="ui-icon" style="width:13px;height:13px;flex-shrink:0;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' : (n.status === 'FILTERED' || n.status === 'DOWN') ? '<svg class="ui-icon" style="width:13px;height:13px;flex-shrink:0;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>' : ''}<span>${escapeHtml(copy.translateReason(withoutEmoji(n.reason || "در حال بررسی")))}</span></div>
            ${Object.keys(n.port_details || {}).length ? `<details class="node-port-details"><summary><div class="node-port-summary-left"><svg class="ui-icon" style="width:13px;height:13px;color:var(--text-muted);" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1"/><circle cx="6" cy="18" r="1"/></svg><span>وضعیت پورت‌ها و آخرین تبادل (${faNumber.format(Object.keys(n.port_details).length)})</span></div><svg class="ui-icon port-chevron-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m6 9 6 6 6-6"/></svg></summary><div class="node-port-grid">${Object.entries(n.port_details).map(([port, info]) => {
              const pClass = info.status === 'HEALTHY' ? 'healthy' : (info.status === 'DEGRADED' || info.status === 'CANARY') ? 'canary' : (info.status === 'FILTERED' || info.status === 'DOWN') ? 'filtered' : 'idle';
              const pLabel = ({HEALTHY:'سالم',DEGRADED:'مشکوک',FILTERED:'اختلال',IDLE:'بدون ترافیک'})[info.status] || info.status;
              const tStr = info.last_success_epoch ? new Date(info.last_success_epoch * 1000).toLocaleString('en-US') : 'ثبت نشده';
              return `<div class="node-port-card"><div class="node-port-card-header"><span class="node-port-number">${escapeHtml(port)}</span><span class="status-badge ${pClass}"><span class="pulse-dot"></span>${escapeHtml(pLabel)}</span></div>${info.reason ? `<div class="node-port-card-reason">${escapeHtml(copy.translateReason(withoutEmoji(info.reason)))}</div>` : ''}<div class="node-port-card-time">آخرین تبادل موفق: <bdi>${escapeHtml(tStr)}</bdi></div></div>`;
            }).join('')}</div></details>` : ''}
          </div>
          <div class="node-actions-col">
            <button type="button" class="node-log-btn dns-switch-btn" data-pool="${escapeHtml(p.name)}" data-ip="${escapeHtml(n.ip)}" onclick="setPoolDnsRoute(this.dataset.pool, 'manual', this.dataset.ip, this)" ${p.cf_enabled && !mutationsLocked ? '' : `disabled aria-disabled="true" title="${escapeHtml(mutationsLocked ? lockReason : 'ابتدا Cloudflare را برای این استخر فعال کنید')}"`}>${dns.verified && dns.ips.length === 1 && dns.ips[0] === n.ip && p.dns_mode === 'manual' ? 'DNS دستی روی این نود' : 'انتقال DNS به این نود'}</button>
            ${(n.engine === 'wireguard' || p.transport === 'wireguard') ? `<button type="button" class="node-log-btn" data-pool="${escapeHtml(p.name)}" data-ip="${escapeHtml(n.ip)}" onclick="runWireguardNodeProbe(this.dataset.pool, this.dataset.ip, this)"><span>آزمون Probe</span></button>` : ''}
            <button class="node-log-btn" data-arg0="${escapeHtml(n.ip)}" data-arg1="${escapeHtml(n.name)}" data-pool="${escapeHtml(p.name)}" onclick="openLogsModal(this.dataset.arg0, this.dataset.arg1, this.dataset.pool)">
              <span>لاگ</span>
            </button>
            <button class="node-del-btn" data-arg0="${escapeHtml(p.name)}" data-arg1="${escapeHtml(n.ip)}" onclick="removeNodeFromPool(this.dataset.arg0, this.dataset.arg1, this)" ${mutationsLocked ? `disabled aria-disabled="true" title="${escapeHtml(lockReason)}"` : 'title="حذف سرور از این استخر"'}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
              </svg>
            </button>
          </div>
        </div>
      `;
    }).join("") : `
      <div style="padding: 16px; text-align: center; color: var(--text-muted); font-size: 11.5px;">
        ${(p.nodes || []).length ? 'نودی مطابق این فیلتر نیست؛ فیلتر «همه نودها» را انتخاب کنید.' : Object.values(p.node_additions || {}).some(j => ['queued','running'].includes(j.status)) ? 'نود پس از پایان راه‌اندازی به استخر اضافه می‌شود.' : 'این استخر هنوز نودی ندارد؛ یک سرور ایران اضافه کنید.'}
      </div>
    `;

    const totalNodesCount = (p.nodes || []).length;
    const healthyNodesCount = (p.nodes || []).filter(n => n.status === "HEALTHY").length;
    const nodesSummaryHtml = totalNodesCount
      ? `<span class="pool-nodes-summary" title="${faNumber.format(healthyNodesCount)} از ${faNumber.format(totalNodesCount)} نود فعال است">${uiIcon("pin")}<span>${faNumber.format(healthyNodesCount)} / ${faNumber.format(totalNodesCount)} نود</span></span>`
      : `<span class="pool-nodes-summary">${uiIcon("pin")}<span>بدون نود</span></span>`;

    return `
      <div class="pool-card">
        <div class="pool-card-top">
          <div class="pool-title-line">
            <div class="pool-title-left">
              <h4 class="pool-name">${escapeHtml(withoutEmoji(p.name))}</h4>
              ${getEngineBadge(p.engine, p.transport)}
              <span class="status-badge">${p.dns_mode === 'manual' ? 'DNS دستی' : 'DNS خودکار'}</span>
              ${nodesSummaryHtml}
              ${p.dns_mode === 'manual' ? `<button type="button" class="node-log-btn" data-pool="${escapeHtml(p.name)}" onclick="setPoolDnsRoute(this.dataset.pool,'auto','',this)" ${mutationsLocked ? `disabled aria-disabled="true" title="${escapeHtml(lockReason)}"` : ''}>بازگشت به خودکار</button>` : ''}
              <span class="proto-tag">${escapeHtml(p.transport || "tcp")}</span>
            </div>
            <div class="node-ip-row">
              <span style="font-size: 11px; color: var(--text-sub);">مقصد:</span>
              <span class="node-ip-text">${escapeHtml(p.kharej_ip || "-")}</span>
              <button class="copy-micro-btn" data-arg0="${escapeHtml(p.kharej_ip)}" onclick="copyText(this.dataset.arg0)" title="کپی آی‌پی خارج">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
              </button>
            </div>
          </div>
          <div class="pool-subdomain-row">
            <span style="color: var(--text-sub);">دامنه DNS:</span>
            <span class="pool-subdomain-text">${escapeHtml(poolDomain || "تعیین نشده")}${p.dns_scope === 'all_subdomains' ? ' · همهٔ ساب‌دامین‌های A' : ''}</span>
            ${poolDomain ? `
              <button class="copy-micro-btn" data-arg0="${escapeHtml(p.subdomain)}" onclick="copyText(this.dataset.arg0)" title="کپی ساب‌دومین">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
              </button>
            ` : ""}
          </div>
          ${p.rotation ? `<div class="pool-subdomain-row" style="flex-wrap:wrap;gap:8px;"><span class="status-badge ${p.rotation.enabled ? 'healthy' : 'idle'}">چرخش DNS: ${p.rotation.enabled ? 'فعال' : 'خاموش'}</span>${p.rotation.active_ip ? `<span class="node-ip-text">IP فعال: ${escapeHtml(p.rotation.active_ip)}</span>` : ''}${p.rotation.next_rotation_at ? `<span style="color:var(--text-sub);font-size:11px;">بعدی: <bdi>${escapeHtml(p.rotation.next_rotation_at)}</bdi></span>` : ''}${p.rotation.last_result ? `<span style="color:var(--text-sub);font-size:11px;">آخرین نتیجه: ${escapeHtml(p.rotation.last_result)}</span>` : ''}</div>` : ''}
        </div>

        <div class="ports-strip">
          <span class="ports-label-text">پورت‌ها:</span>
          ${portsHtml}
          <button class="add-port-btn" data-arg0="${escapeHtml(p.name)}" onclick="openAddPortModal(this.dataset.arg0)" ${mutationsLocked ? `disabled aria-disabled="true" title="${escapeHtml(lockReason)}"` : ''}>${uiIcon("plus")}<span>پورت جدید</span></button>
        </div>

        <div class="nodes-list-body">
          ${nodesHtml}
          ${Object.values(p.node_additions || {}).filter(job => ['queued','running'].includes(job.status)).map(job => `<div class="node-item-row node-addition-row" role="status" aria-live="polite" data-status="${escapeHtml(job.status)}"><div class="node-info-col"><div class="node-header-line"><span class="node-name">${escapeHtml(withoutEmoji(job.name))}</span><span class="status-badge ${job.status === 'failed' ? 'filtered' : job.status === 'succeeded' ? 'healthy' : 'canary'}">${({queued:'در صف',running:'در حال افزودن',succeeded:'اضافه شد',failed:'ناموفق'})[job.status] || 'در حال بررسی'}</span></div><bdi class="node-ip-text" dir="ltr">${escapeHtml(job.ip)}</bdi><p class="node-reason-text">${escapeHtml(job.message)}</p>${job.error ? `<p class="node-addition-error" dir="auto">${escapeHtml(job.error)}</p>` : ''}</div>${job.status === 'failed' ? `<button type="button" class="node-log-btn" data-pool="${escapeHtml(p.name)}" onclick="openAddNodeModal(this.dataset.pool)">بررسی و تلاش مجدد</button>` : ''}</div>`).join('')}
        </div>

        ${poolActionErrors.has(p.name) ? `<div class="pool-action-error" role="alert"><span>${escapeHtml(poolActionErrors.get(p.name))}</span><button type="button" class="node-log-btn" data-pool="${escapeHtml(p.name)}" onclick="clearPoolActionError(this.dataset.pool)">بستن پیام</button></div>` : ''}
        ${renderPoolOperations(p)}
        <div class="pool-footer-actions">
          <div class="pool-actions-main pool-management-actions">
            <button class="btn-secondary sm" data-arg0="${escapeHtml(p.name)}" onclick="openAddNodeModal(this.dataset.arg0)" ${mutationsLocked ? `disabled aria-disabled="true" title="${escapeHtml(lockReason)}"` : ''}>${uiIcon("plus")}<span>افزودن نود ایران</span></button>
            <button type="button" class="btn-secondary sm" data-pool="${escapeHtml(p.name)}" onclick="openTransportModal(this.dataset.pool)" ${mutationsLocked || !p.nodes?.length ? `disabled aria-disabled="true" title="${escapeHtml(mutationsLocked ? lockReason : 'استخر هنوز نود فعالی ندارد')}"` : ''}>تغییر نوع تونل</button>
            ${(p.engine === "wireguard" || p.transport === "wireguard") ? `<button type="button" class="btn-secondary sm" data-pool="${escapeHtml(p.name)}" onclick="openWireguardSettingsModal(this.dataset.pool)" ${mutationsLocked ? `disabled aria-disabled="true" title="${escapeHtml(lockReason)}"` : ''}>تنظیمات و آزمون WireGuard</button>` : (p.engine === "vxlan" || p.transport === "vxlan") ? `<button type="button" class="btn-secondary sm" data-pool="${escapeHtml(p.name)}" onclick="openVxlanSettingsModal(this.dataset.pool)" ${mutationsLocked ? `disabled aria-disabled="true" title="${escapeHtml(lockReason)}"` : ''}>تنظیمات و وضعیت VXLAN</button>` : (p.engine === "gre6" || p.transport === "gre6") ? `<button type="button" class="btn-secondary sm" data-pool="${escapeHtml(p.name)}" onclick="openGre6SettingsModal(this.dataset.pool)" ${mutationsLocked ? `disabled aria-disabled="true" title="${escapeHtml(lockReason)}"` : ''}>تنظیمات GRE6</button>` : (p.engine === "ip6ip6" || p.transport === "ip6ip6") ? `<button type="button" class="btn-secondary sm" data-pool="${escapeHtml(p.name)}" onclick="openIp6ip6SettingsModal(this.dataset.pool)" ${mutationsLocked ? `disabled aria-disabled="true" title="${escapeHtml(lockReason)}"` : ''}>تنظیمات IP6IP6</button>` : (['geneve','geneve_ipsec'].includes(p.engine) || p.transport === "geneve_ipsec") ? `<button type="button" class="btn-secondary sm" data-pool="${escapeHtml(p.name)}" onclick="openGeneveSettingsModal(this.dataset.pool)" ${mutationsLocked ? `disabled aria-disabled="true" title="${escapeHtml(lockReason)}"` : ''}>تنظیمات Geneve</button>` : p.transport === "gre" ? `<button type="button" class="btn-secondary sm" data-pool="${escapeHtml(p.name)}" onclick="openGreSettingsModal(this.dataset.pool)" ${mutationsLocked ? `disabled aria-disabled="true" title="${escapeHtml(lockReason)}"` : ''}>تنظیمات GRE</button>` : p.engine === "slipstream" ? `<button type="button" class="btn-secondary sm" data-pool="${escapeHtml(p.name)}" onclick="openSlipstreamSettingsModal(this.dataset.pool)" ${mutationsLocked ? `disabled aria-disabled="true" title="${escapeHtml(lockReason)}"` : ''}>تنظیمات Slipstream</button>` : ""}
            <button type="button" class="btn-secondary sm" data-pool="${escapeHtml(p.name)}" onclick="configurePoolRotation(this.dataset.pool)" ${mutationsLocked || !p.cf_enabled || (p.nodes || []).length < 2 ? `disabled aria-disabled="true" title="برای چرخش Cloudflare حداقل دو نود و تنظیم DNS لازم است"` : ''}>زمان‌بندی چرخش IP</button>
            <button type="button" class="btn-secondary sm" data-pool="${escapeHtml(p.name)}" onclick="rotatePoolNow(this.dataset.pool, this)" ${mutationsLocked || !p.cf_enabled || (p.nodes || []).length < 2 ? `disabled aria-disabled="true" title="برای چرخش Cloudflare حداقل دو نود و تنظیم DNS لازم است"` : ''}>چرخش الان</button>
            <button class="btn-secondary sm" data-arg0="${escapeHtml(p.name)}" data-domain="${escapeHtml(p.subdomain || "")}" onclick="openPoolCfModal(this.dataset.arg0, this.dataset.domain)" ${mutationsLocked ? `disabled aria-disabled="true" title="${escapeHtml(lockReason)}"` : ''}>تنظیم DNS</button>
          </div>
          <div class="pool-actions-danger">
            <button class="btn-danger sm" data-arg0="${escapeHtml(p.name)}" onclick="deleteEntirePool(this.dataset.arg0)" ${mutationsLocked ? `disabled aria-disabled="true" title="${escapeHtml(lockReason)}"` : ''}>حذف استخر</button>
          </div>
        </div>
      </div>
    `;
  }).join("");
}

/* ==========================================================================
   5. Server Inventory Management
   ========================================================================== */
async function rotatePoolNow(pool, button) {
  if (button) button.disabled = true;
  try {
    const res = await apiFetch('/api/rotation/rotate', {method:'POST', body:{pool}});
    showToast(res.success ? `DNS به ${res.to_ip} منتقل شد` : (res.error || 'چرخش ناموفق بود'));
    await fetchStatus(true);
  } catch (_) { showToast('خطا در ارتباط با سرور'); }
  finally { if (button) button.disabled = false; }
}

async function configurePoolRotation(pool) {
  const current = cachedStatus?.pools?.find(p => p.name === pool)?.rotation || {};
  const enabled = window.prompt('چرخش فعال باشد؟ (yes/no)', current.enabled ? 'yes' : 'no');
  if (enabled === null) return;
  const mode = window.prompt('mode: interval یا daily', current.mode || 'interval');
  if (mode === null) return;
  const value = mode === 'daily' ? window.prompt('ساعت روزانه HH:MM', current.daily_time || '03:00') : window.prompt('بازه به دقیقه', String(current.interval_minutes || 60));
  if (value === null) return;
  const body = {pool, inherit_global:false, enabled: enabled.toLowerCase() === 'yes', mode};
  if (mode === 'daily') body.daily_time = value; else body.interval_minutes = Number(value);
  try {
    const res = await apiFetch('/api/rotation/settings', {method:'POST', body});
    showToast(res.success ? 'زمان‌بندی چرخش ذخیره شد' : (res.error || 'ذخیره ناموفق بود'));
    await fetchStatus(true);
  } catch (_) { showToast('خطا در ارتباط با سرور'); }
}


async function fetchServers() {
  try {
    const data = await apiFetch("/api/servers");
    document.getElementById('servers-error')?.classList.add('hidden');
    cachedServers = data;
    renderServers(data);
  } catch (e) {
    if (authToken) document.getElementById('servers-error')?.classList.remove('hidden');
    if (authToken && !cachedServers) document.getElementById('servers-container').innerHTML = emptyMarkup(copy.loadFailed, '', copy.retry, 'fetchServers()');
  }
}

function renderServers(data) {
  const container = document.getElementById("servers-container");
  if (!container) return;

  const iran = data.iran || [];
  const kharej = data.kharej || [];
  document.getElementById("servers-total-count-badge").textContent = faNumber.format(iran.length + kharej.length);

  let allList = [];
  if (serverFilter === "ALL" || serverFilter === "IRAN") {
    allList = allList.concat(iran.map(s => ({ ...s, role: "iran" })));
  }
  if (serverFilter === "ALL" || serverFilter === "KHAREJ") {
    allList = allList.concat(kharej.map(s => ({ ...s, role: "kharej" })));
  }
  allList = allList.filter(serverMatchesSearch);

  if (!allList.length) {
    container.innerHTML = emptyMarkup(copy.noServers, copy.noServersHint, copy.addServer, "openAddServerModal()");
    return;
  }

  container.innerHTML = allList.map(s => `
    <div class="server-card">
      <div class="server-main-info">
        <div class="server-title-line">
          <span class="server-loc-pill ${s.role === "iran" ? "loc-iran" : "loc-kharej"}">${uiIcon(s.role === "iran" ? "pin" : "globe")}<span>${s.role === "iran" ? "ایران" : "خارج"}</span></span>
          <strong style="font-size: 13.5px;">${escapeHtml(withoutEmoji(s.name))}</strong>
          ${s.in_use ? `<span class="status-badge healthy" style="font-size: 9px;"><span class="pulse-dot"></span>در استخر فعال</span>` : `<span class="status-badge idle" style="font-size: 9px;">آماده تخصیص</span>`}
        </div>
        <div class="server-ip-line">
          <bdi dir="ltr">${escapeHtml(s.ip)}</bdi>
          <button class="copy-micro-btn" data-arg0="${escapeHtml(s.ip)}" onclick="copyText(this.dataset.arg0)" title="کپی آی‌پی">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
          </button>
        </div>
        <div class="server-specs-line">
          <span class="server-spec-chip"><svg class="ui-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 17l6-6-6-6"/><path d="M12 19h8"/></svg>SSH: ${escapeHtml(String(s.port || 22))} (${escapeHtml(s.username || "root")})</span>
          <span class="server-spec-chip"><svg class="ui-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>معماری: ${escapeHtml(s.arch || "x86_64")}</span>
        </div>
      </div>
      <button class="server-del-btn" data-arg0="${escapeHtml(String(s.role))}" data-arg1="${escapeHtml(s.ip)}" onclick="deleteServer(this.dataset.arg0, this.dataset.arg1)" title="حذف سرور">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="3 6 5 6 21 6"></polyline>
          <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
        </svg>
      </button>
    </div>
  `).join("");
}

/* ==========================================================================
   6. Watchdog & Cloudflare Tab UI
   ========================================================================== */
let globalCfHydrated = false;
function updateWatchdogTabUI(data) {
  const badge = document.getElementById("watchdog-daemon-status-badge");
  const toggleBtn = document.getElementById("watchdog-toggle-daemon-btn");
  
  if (badge) {
    if (data.daemon_running) {
      badge.className = "status-badge healthy";
      badge.textContent = `فعال (PID: ${data.daemon_pid || "?"})`;
      if (toggleBtn) toggleBtn.querySelector("span").textContent = "توقف دیمن خودکار";
    } else {
      badge.className = "status-badge canary";
      badge.textContent = "متوقف";
      if (toggleBtn) toggleBtn.querySelector("span").textContent = "شروع به کار دیمن (هر 30 ثانیه)";
    }
  }

  renderWatchdogRoutes(data);

  // Pre-fill global Cloudflare settings
  if (data.global_cloudflare && !globalCfHydrated) {
    globalCfHydrated = true;
    const cf = data.global_cloudflare;
    const tInput = document.getElementById("cf-global-token");
    const zInput = document.getElementById("cf-global-zone");
    const sInput = document.getElementById("cf-global-sub");
    if (tInput && !tInput.value) tInput.value = cf.api_token || "";
    if (zInput && !zInput.value) zInput.value = cf.zone_id || "";
    if (sInput && !sInput.value) sInput.value = cf.subdomain || "";
  }

  // Pre-fill dashboard domain settings
  if (data.dashboard_domain) {
    const dCfg = data.dashboard_domain;
    const dInput = document.getElementById("dash-domain-input");
    const sMode = document.getElementById("dash-ssl-mode");
    const badge = document.getElementById("domain-ssl-badge");
    const link = document.getElementById("dash-cf-link");
    if (dInput && !dInput.value) dInput.value = dCfg.domain || "";
    if (sMode && dCfg.ssl_mode) sMode.value = dCfg.ssl_mode;
    if (badge) badge.style.display = dCfg.configured ? "inline-flex" : "none";
    if (link && dCfg.domain) link.textContent = `https://${dCfg.domain}:8443`;
  }
}

async function fetchDaemonLogs() {
  const viewer = document.getElementById("watchdog-logs-viewer");
  if (!viewer) return;
  try {
    const data = await apiFetch("/api/daemon_logs");
    if (!data.logs || !data.logs.length) {
      viewer.textContent = "هنوز هیچ رویدادی در فایل لاگ ثبت نشده است.";
      return;
    }
    viewer.innerHTML = data.logs.slice(-30).map(l => {
      let cls = "";
      if (l.includes("HEALTHY") || l.includes("✅")) cls = "log-healthy";
      else if (l.includes("FILTERED") || l.includes("❌")) cls = "log-err";
      else if (l.includes("CANARY") || l.includes("⚠️")) cls = "log-warn";
      return `<div class="${cls}">${escapeHtml(withoutEmoji(l))}</div>`;
    }).join("");
    viewer.scrollTop = viewer.scrollHeight;
  } catch (e) { if (authToken) viewer.textContent = copy.loadFailed; }
}

/* ==========================================================================
   7. Actions: Sync & Daemon Toggle
   ========================================================================== */
async function triggerManualSync() {
  const btn = document.getElementById("top-sync-btn");
  if (btn) btn.classList.add("spinning");
  showToast("در حال پایش زنده سلامت و ارزیابی نودها...");

  try {
    const res = await apiFetch("/api/check", { method: "POST" });
    if (res.success) {
      showToast("پایش سلامت با موفقیت انجام شد");
      fetchStatus();
      if (currentTab === "watchdog") fetchDaemonLogs();
    }
  } catch (e) {
    showToast("خطا در اجرای همگام‌سازی");
  } finally {
    if (btn) btn.classList.remove("spinning");
  }
}

async function toggleDaemonState() {
  showToast("در حال تغییر وضعیت دیمن واچ‌داگ...");
  try {
    const statusData = await apiFetch("/api/status");
    const nextAction = statusData.daemon_running ? "stop" : "start";
    const res = await apiFetch("/api/daemon", {
      method: "POST",
      body: { action: nextAction }
    });
    if (res.success) {
      showToast(nextAction === "start" ? "دیمن خودکار فعال شد" : "دیمن خودکار متوقف شد");
      fetchStatus();
    }
  } catch (e) {
    showToast("خطا در تغییر وضعیت دیمن");
  }
}

/* ==========================================================================
   8. Modals & Complex Flows
   ========================================================================== */
function closeModal(modalId) {
  const m = document.getElementById(modalId);
  if (m) m.classList.add("hidden");
}

function closeModalOnBackdrop(e) {
  if (e.target.classList.contains("modal-backdrop")) {
    closeModal(e.target.id);
  }
}

/* Async replacement for native window.confirm — uses the styled sheet modal. */
function confirmDialog(message, opts = {}) {
  return new Promise(resolve => {
    const modal = document.getElementById('confirm-modal');
    if (!modal) { resolve(window.confirm(message)); return; }
    const titleEl = document.getElementById('confirm-modal-title');
    const msgEl = document.getElementById('confirm-modal-message');
    const okBtn = document.getElementById('confirm-modal-ok');
    const cancelBtn = document.getElementById('confirm-modal-cancel');
    titleEl.textContent = opts.title || 'تأیید عملیات';
    msgEl.textContent = message;
    okBtn.querySelector('span').textContent = opts.confirmText || 'تأیید';
    cancelBtn.querySelector('span').textContent = opts.cancelText || 'انصراف';
    okBtn.className = opts.danger === false ? 'btn-primary' : 'btn-danger';
    okBtn.style.flex = '1';
    cancelBtn.style.flex = '1';
    const done = val => {
      okBtn.onclick = cancelBtn.onclick = null;
      closeModal('confirm-modal');
      resolve(val);
    };
    okBtn.onclick = () => done(true);
    cancelBtn.onclick = () => done(false);
    modal.classList.remove('hidden');
    okBtn.focus({ preventScroll: true });
  });
}

/* Add Server */
function openAddServerModal() {
  document.getElementById("server-name-input").value = "";
  document.getElementById("server-ip-input").value = "";
  document.getElementById("server-pass-input").value = "";
  document.getElementById("add-server-modal").classList.remove("hidden");
}

async function submitAddServer(e) {
  e.preventDefault();
  const role = document.querySelector("input[name='server-role']:checked").value;
  const name = document.getElementById("server-name-input").value.trim();
  const ip = document.getElementById("server-ip-input").value.trim();
  const port = parseInt(document.getElementById("server-port-input").value) || 22;
  const user = document.getElementById("server-user-input").value.trim() || "root";
  const pass = document.getElementById("server-pass-input").value;

  const btn = document.getElementById("add-server-submit-btn");
  btn.disabled = true;
  btn.querySelector("span").textContent = "در حال تست اتصال SSH...";

  try {
    const res = await apiFetch("/api/servers/add", {
      method: "POST",
      body: { type: role, name, ip, port, username: user, password: pass }
    });
    if (res.success) {
      showToast(`سرور ${ip} با موفقیت افزوده شد`);
      closeModal("add-server-modal");
      fetchServers();
      fetchStatus();
    } else {
      formError("add-server-submit-btn", res.error || "خطا در افزودن سرور");
    }
  } catch (err) {
    formError("add-server-submit-btn", "خطا در ارسال درخواست سرور");
  } finally {
    btn.disabled = false;
    btn.querySelector("span").textContent = "تست اتصال و ذخیره در مخزن";
  }
}

/* Delete Server */
async function deleteServer(type, ip) {
  if (!await confirmDialog(`آیا از حذف سرور ${ip} از مخزن سرورها اطمینان دارید؟`, { title: 'حذف سرور', confirmText: 'حذف' })) return;
  showToast(`در حال حذف سرور ${ip}...`);

  try {
    const res = await apiFetch("/api/servers/delete", {
      method: "POST",
      body: { type, ip }
    });
    if (res.success) {
      showToast(`سرور ${ip} حذف شد`);
      fetchServers();
      fetchStatus();
    } else {
      showToast(`${res.error || "خطا در حذف سرور"}`);
    }
  } catch (e) {
    showToast("خطا در درخواست حذف سرور");
  }
}

/* Create Pool */
async function openCreatePoolModal() {
  const khSelect = document.getElementById("new-pool-kharej");
  const irBox = document.getElementById("new-pool-iran-checkboxes");
  
  const engineSel = document.getElementById("new-pool-engine");
  if (engineSel && !engineSel.value) engineSel.value = "backpack";
  if (engineSel) populatePoolTransports(engineSel.value);
  updateGreCreateFields();
  khSelect.innerHTML = "<option value=''>در حال دریافت...</option>";
  irBox.innerHTML = "در حال بارگذاری سرورهای ایران...";
  document.getElementById("create-pool-modal").classList.remove("hidden");

  try {
    const srvData = await apiFetch("/api/servers");
    const kharejs = srvData.kharej || [];
    const irans = srvData.iran || [];

    if (!kharejs.length) {
      khSelect.innerHTML = "<option value=''>ابتدا سرور خارج در مخزن ثبت کنید</option>";
    } else {
      khSelect.innerHTML = kharejs.map(s => `<option value="${s.ip}">${escapeHtml(s.name)} (${s.ip})</option>`).join("");
    }

    if (!irans.length) {
      irBox.innerHTML = "هیچ سرور ایرانی در مخزن ثبت نشده است.";
    } else {
      irBox.innerHTML = irans.map(s => `
        <label class="checkbox-row">
          <input type="checkbox" name="pool-iran-nodes" value="${s.ip}" checked>
          <span>${escapeHtml(s.name)} (${s.ip})</span>
        </label>
      `).join("");
    }
  } catch (e) {
    khSelect.innerHTML = `<option value="">${copy.loadFailed}</option>`;
    irBox.innerHTML = `<p class="field-hint" role="alert">${escapeHtml(copy.loadFailed)} <button type="button" class="node-log-btn" onclick="openCreatePoolModal()">تلاش دوباره</button></p>`;
  }
}

async function submitCreatePool(e) {
  e.preventDefault();
  const name = document.getElementById("new-pool-name").value.trim();
  const kharejIp = document.getElementById("new-pool-kharej").value;
  const transport = document.getElementById("new-pool-proto").value;
  const portsRaw = document.getElementById("new-pool-ports").value.trim();

  const selectedIrans = Array.from(document.querySelectorAll("input[name='pool-iran-nodes']:checked")).map(cb => cb.value);
  if (!selectedIrans.length) {
    formError("create-pool-submit-btn", "حداقل یک سرور ایران باید انتخاب شود");
    return;
  }

  const ports = portsRaw.split(",").map(p => p.trim()).filter(Boolean);

  const btn = document.getElementById("create-pool-submit-btn");
  btn.disabled = true;
  btn.querySelector("span").textContent = "در حال استقرار تونل‌ها و فایروال...";

  try {
    const res = await apiFetch("/api/pools/create", {
      method: "POST",
      body: {
        name,
        kharej_ip: kharejIp,
        iran_ips: selectedIrans,
        transport,
        client_ports: ports,
        ...(transport === "gre" ? {gre_mtu:document.getElementById("new-pool-gre-mtu").value} :
           transport === "gre6" ? {gre6_mtu: document.getElementById("new-pool-gre6-mtu")?.value || '1280'} :
           transport === "ip6ip6" ? {ip6ip6_mtu: document.getElementById("new-pool-ip6ip6-mtu")?.value || '1280'} :
           transport === "tun" ? {tun_mtu: document.getElementById("new-pool-tun-mtu")?.value || '1280'} :
           transport === "dc6" ? {
             dc6_mtu: document.getElementById("new-pool-dc6-mtu")?.value || '1280',
             carrier: document.getElementById("new-pool-dc6-carrier")?.value || 'ip6gre'
           } :
           ['quantum', 'quantum+', 'quantum-gaming'].includes(transport) ? {
             fec_datashard: parseInt(document.getElementById("new-pool-quantum-data")?.value || '10', 10),
             fec_parityshard: parseInt(document.getElementById("new-pool-quantum-parity")?.value || '3', 10),
             camouflage: {kcp_mode: 'fast3'}
           } :
           transport === "geneve_ipsec" ? {geneve_mtu:document.getElementById("new-pool-geneve-mtu")?.value || '1280', vni:document.getElementById("new-pool-geneve-vni")?.value || null} :
           transport === "vxlan" ? {
             vxlan_method: document.getElementById("new-pool-vxlan-method")?.value || "p2p",
             vni: document.getElementById("new-pool-vxlan-vni")?.value || "1000",
             dst_port: document.getElementById("new-pool-vxlan-port")?.value || "4789",
             vxlan_mtu: document.getElementById("new-pool-vxlan-mtu")?.value || "1280",
             bridge_name: document.getElementById("new-pool-vxlan-bridge")?.value || ""
           } :
           transport === "wireguard" ? {
             wireguard_port: document.getElementById("new-pool-wireguard-port")?.value || '51820',
             wireguard_mtu: document.getElementById("new-pool-wireguard-mtu")?.value || '1280',
             enable_psk: document.getElementById("new-pool-wireguard-psk")?.checked || false,
           } :
           transport === "paqet" ? {camouflage:{tunnel_port:document.getElementById('paqet-tunnel-port')?.value || '9999',binary:document.getElementById('paqet-binary')?.value || '/usr/local/bin/paqet'}} :
           transport === "slipstream" ? {
             domain: document.getElementById("slipstream-domain")?.value || "",
             resolvers: (document.getElementById("slipstream-resolvers")?.value || "").split(",").map(r => r.trim()).filter(Boolean),
             dns_port: document.getElementById("slipstream-dns-port")?.value || "53",
             rate_limit: document.getElementById("slipstream-rate-limit")?.value || "1000"
           } :
           MANAGED_PACKET_TRANSPORTS.includes(transport) ? {
             engine: 'spoof',
             ...(['fake-sni','hop-ttl-injection'].includes(transport) ? {fake_sni:document.getElementById('spoof-fake-sni')?.value || 'www.shaparak.ir'} : {}),
             ...(transport==='hop-ttl-injection' ? {auto_ttl_delta:parseInt(document.getElementById('spoof-ttl-delta')?.value || '3',10)} : {})
           } :
           ['fake-sni','split-tls','hop-ttl-injection','tcp-state-desync','l3-ip-spoof','l7-header-mutation','udp-raw-spoof','dns-spoof','spoof','spoof-tcp-syn','spoof-udp-raw','spoof-icmp','qs-dns-hybrid','hyperion-x'].includes(transport) ? {
             engine: 'spoof',
             fake_sni: document.getElementById('spoof-fake-sni')?.value || 'www.shaparak.ir',
             auto_ttl_delta: parseInt(document.getElementById('spoof-ttl-delta')?.value || '3', 10),
             spoof_ips: document.getElementById('spoof-ip-list')?.value || '',
             peer_spoof_ip: document.getElementById('spoof-peer-ip')?.value || '',
             dns_resolvers: document.getElementById('spoof-dns-resolvers')?.value || '',
             fake_send_ip: document.getElementById('spoof-fake-send-ip')?.value || '',
             knock_key: document.getElementById('spoof-knock-key')?.value || '',
             camouflage: {
               server_name: document.getElementById('spoof-fake-sni')?.value || 'www.shaparak.ir'
             }
           } :
           ['xhttp','xhttps','nova','gre_xhttp','waterwall','reality'].includes(transport) ? {
             camouflage: {
               server_name: document.getElementById('https-server-name').value,
               port: document.getElementById('https-outer-port').value,
               binary: document.getElementById('https-binary').value,
               certificate: document.getElementById('https-certificate').value,
               key: document.getElementById('https-key').value,
               xmux_concurrency: document.getElementById('https-xmux-concurrency')?.value || 8,
               tls_fragment_min: document.getElementById('https-fragment-min')?.value || 10,
               tls_fragment_max: document.getElementById('https-fragment-max')?.value || 30
             }
           } : {})
      }
    });
    if (res.success) {
      showToast(res.accepted ? "ساخت استخر شروع شد؛ وضعیت را در کارت استخر دنبال کنید" : "استخر لودبالانسر با موفقیت راه‌اندازی شد");
      closeModal("create-pool-modal");
      fetchStatus();
    } else {
      formError("create-pool-submit-btn", res.error || "خطا در ساخت استخر");
    }
  } catch (err) {
    formError("create-pool-submit-btn", "خطا در راه‌اندازی استخر");
  } finally {
    btn.disabled = false;
    btn.querySelector("span").textContent = "استقرار و راه‌اندازی استخر";
  }
}

/* Delete Entire Pool */
async function deleteEntirePool(poolName) {
  if (!await confirmDialog(`آیا از حذف کامل استخر '${poolName}' و متوقف کردن تمام تونل‌های آن اطمینان دارید؟`, { title: 'حذف استخر', confirmText: 'حذف کامل' })) return;
  showToast(`در حال خاموش کردن و حذف استخر ${poolName}...`);

  try {
    const res = await apiFetch("/api/pools/delete", {
      method: "POST",
      body: { pool: poolName }
    });
    if (res.success) {
      showToast(res.accepted ? "حذف شروع شد؛ وضعیت را در کارت استخر دنبال کنید" : (res.message || "استخر با موفقیت حذف شد"));
      fetchStatus();
    } else {
      showToast(`${res.error || "خطا در حذف استخر"}`);
    }
  } catch (e) {
    showToast("خطا در ارسال درخواست حذف استخر");
  }
}

/* Add Node to Pool */
let addNodeLoadVersion = 0;
async function openAddNodeModal(poolName) {
  const version = ++addNodeLoadVersion;
  const submit = document.getElementById("add-node-submit-btn");
  submit.disabled = true;
  currentPoolForAction = poolName;
  document.getElementById("add-node-modal-pool").textContent = `استخر: ${poolName}`;
  const select = document.getElementById("select-iran-node-to-add");
  select.innerHTML = "<option value=''>در حال بارگذاری...</option>";
  document.getElementById("add-node-modal").classList.remove("hidden");

  try {
    const srvData = await apiFetch("/api/servers");
    if (version !== addNodeLoadVersion || currentPoolForAction !== poolName || document.getElementById("add-node-modal").classList.contains("hidden")) return;
    const irans = srvData.iran || [];
    const pool = (cachedStatus?.pools || []).find(p => p.name === poolName);
    const existingIps = (pool ? pool.nodes : []).map(n => n.ip);
    const available = irans.filter(s => !existingIps.includes(s.ip));

    submit.disabled = !available.length;
    if (!available.length) {
      select.innerHTML = "<option value=''>تمام سرورهای ایران موجود در این استخر عضو هستند</option>";
    } else {
      select.innerHTML = available.map(s => `<option value="${s.ip}">${escapeHtml(s.name)} (${s.ip})</option>`).join("");
    }
  } catch (e) {
    select.innerHTML = `<option value="">${copy.loadFailed}</option>`;
    select.insertAdjacentHTML('afterend', `<p class="field-hint" role="alert">${escapeHtml(copy.loadFailed)} <button type="button" class="node-log-btn" data-pool="${escapeHtml(poolName)}" onclick="openAddNodeModal(this.dataset.pool)">تلاش دوباره</button></p>`);
  }
}

async function submitAddNodeToPool(e) {
  e.preventDefault();
  const iranIp = document.getElementById("select-iran-node-to-add").value;
  if (!iranIp) return;

  const poolName = currentPoolForAction;
  const btn = document.getElementById("add-node-submit-btn");
  btn.disabled = true;
  btn.querySelector("span").textContent = "در حال راه‌اندازی تونل نود...";

  try {
    const res = await apiFetch("/api/pools/add_node", {
      method: "POST",
      body: { pool: poolName, iran_ip: iranIp }
    });
    if (res.success) {
      showToast("افزودن نود شروع شد؛ وضعیت را در کارت استخر دنبال کنید");
      closeModal("add-node-modal");
      lastRenderedPools = "";
      await fetchStatus();
    } else {
      formError("add-node-submit-btn", res.error || "خطا در اتصال نود");
    }
  } catch (err) {
    formError("add-node-submit-btn", "خطا در ارسال درخواست نود");
  } finally {
    btn.disabled = false;
    btn.querySelector("span").textContent = "افزودن و اتصال تونل نود";
  }
}

/* Remove Node from Pool */
async function abandonTransportChange(poolName, button) {
  if (!await confirmDialog(`عملیات شکست‌خوردهٔ ${poolName} رها شود؟ این کار فقط قفل را آزاد می‌کند و سلامت یا هماهنگی تانل‌ها را تأیید نمی‌کند.`, { title: 'رهاسازی عملیات', confirmText: 'رهاسازی' })) return;
  button.disabled = true;
  try {
    const result = await apiFetch("/api/pools/transport-force-clear", {method:"POST",body:{pool:poolName,confirm:`abandon-${poolName}`}});
    if (!result.success) throw new Error(result.error || result.message || "رفع قفل ناموفق بود");
    showToast(result.message); await fetchStatus();
  } catch (error) { showToast(error.message); }
  finally { button.disabled = false; }
}

async function removeNodeFromPool(poolName, iranIp, button) {
  if (!await confirmDialog(`آیا از جدا کردن سرور ${iranIp} از استخر ${poolName} اطمینان دارید؟`, { title: 'جدا کردن نود', confirmText: 'جدا کردن' })) return;
  if (button) { button.disabled = true; button.setAttribute("aria-busy", "true"); }
  showToast(`در حال ثبت حذف نود ${iranIp}...`);

  try {
    const res = await apiFetch("/api/pools/remove_node", {
      method: "POST",
      body: { pool: poolName, iran_ip: iranIp }
    });
    if (res.success) {
      showToast("حذف شروع شد؛ مراحل و نتیجه در کارت استخر نمایش داده می‌شود");
      await fetchStatus(true);
    } else {
      showToast(res.error || "خطا در جدا کردن نود");
    }
  } catch (e) {
    showToast("ثبت درخواست حذف ممکن نشد؛ وضعیت اتصال را بررسی کنید");
  } finally { if (button) { button.disabled = false; button.removeAttribute("aria-busy"); } }
}

/* Ports */
function openAddPortModal(poolName) {
  currentPoolForAction = poolName;
  document.getElementById("port-modal-pool-name").textContent = `استخر: ${poolName}`;
  document.getElementById("new-port-input").value = "";
  document.getElementById("port-modal").classList.remove("hidden");
}

function selectPresetPort(p) {
  const input = document.getElementById("new-port-input");
  if (input) {
    input.value = p;
    input.focus();
  }
}

async function submitAddPort(e) {
  e.preventDefault();
  const port = document.getElementById("new-port-input").value.trim();
  if (!port) return;

  const btn = document.getElementById("add-port-submit-btn");
  btn.disabled = true;
  btn.querySelector("span").textContent = "در حال بازگشایی فایروال نودها...";

  try {
    const res = await apiFetch("/api/ports", {
      method: "POST",
      body: { pool: currentPoolForAction, action: "add", ports: [port] }
    });
    if (res.success) {
      showToast(res.accepted ? "تغییر پورت شروع شد؛ وضعیت را در کارت استخر دنبال کنید" : `پورت ${port} با موفقیت به استخر افزوده شد`);
      closeModal("port-modal");
      fetchStatus();
    } else {
      formError("add-port-submit-btn", res.message || res.error || "خطا در افزودن پورت");
    }
  } catch (err) {
    formError("add-port-submit-btn", "خطا در بازگشایی پورت");
  } finally {
    btn.disabled = false;
    btn.querySelector("span").textContent = "اعمال و بازگشایی پورت در تمام نودها";
  }
}

async function deletePort(poolName, port) {
  if (!await confirmDialog(`آیا از بستن و حذف پورت ${port} از استخر ${poolName} اطمینان دارید؟`, { title: 'بستن پورت', confirmText: 'بستن پورت' })) return;
  showToast(`در حال بستن پورت ${port}...`);

  try {
    const res = await apiFetch("/api/ports", {
      method: "POST",
      body: { pool: poolName, action: "remove", port: port }
    });
    if (res.success) {
      showToast(res.accepted ? "حذف پورت شروع شد؛ وضعیت را در کارت استخر دنبال کنید" : `پورت ${port} بسته شد`);
      fetchStatus();
    } else {
      showToast(`${res.message || "خطا در حذف پورت"}`);
    }
  } catch (e) {
    showToast("خطا در درخواست حذف پورت");
  }
}

/* Pool Cloudflare Modal */
let poolCfLoadVersion = 0;
let poolCfPreview = null;
function resetPoolCfPreview() {
  poolCfPreview = null;
  document.getElementById('pool-cf-preview').classList.add('hidden');
  document.getElementById('pool-cf-submit-btn').querySelector('span').textContent = document.getElementById('pool-cf-scope').value === 'all_subdomains' ? 'نمایش رکوردهای تحت مدیریت' : 'ذخیره و فعال‌سازی فیل‌اور DNS';
}
async function openPoolCfModal(poolName, existingSub) {
  const loadVersion = ++poolCfLoadVersion;
  currentPoolForAction = poolName;
  const modal = document.getElementById('pool-cf-modal');
  const token = document.getElementById('pool-cf-token');
  const zone = document.getElementById('pool-cf-zone');
  const sub = document.getElementById('pool-cf-sub');
  const state = document.getElementById('pool-cf-load-state');
  const button = document.getElementById('pool-cf-submit-btn');
  document.getElementById('pool-cf-modal-subtitle').textContent = `استخر: ${poolName}`;
  resetPoolCfPreview();
  token.value = ''; token.type = 'password'; zone.value = ''; sub.value = existingSub || '';
  [token,zone,sub].forEach(input => input.disabled = true); button.disabled = true;
  document.getElementById('pool-cf-retry').classList.add('hidden');
  state.dataset.failed = 'false';
  state.textContent = 'در حال دریافت تنظیمات ذخیره‌شده…'; modal.classList.remove('hidden');
  try {
    const config = await apiFetch(`/api/pools/cloudflare?pool=${encodeURIComponent(poolName)}`);
    if (loadVersion !== poolCfLoadVersion || currentPoolForAction !== poolName || modal.classList.contains('hidden')) return;
    document.getElementById('pool-cf-scope').value = config.scope || 'single';
    resetPoolCfPreview();
    token.value = config.api_token || ''; zone.value = config.zone_id || ''; sub.value = config.subdomain || existingSub || '';
    state.textContent = token.value && zone.value ? 'تنظیمات ذخیره‌شده دریافت شد؛ توکن در حالت پنهان است.' : 'تنظیمات ذخیره‌شده‌ای وجود ندارد؛ توکن و Zone ID را وارد کنید.';
    [token,zone,sub].forEach(input => input.disabled = false); button.disabled = false;
  } catch (error) {
    if (loadVersion !== poolCfLoadVersion || currentPoolForAction !== poolName || modal.classList.contains('hidden')) return;
    state.textContent = 'دریافت تنظیمات ناموفق بود؛ دوباره تلاش کنید.';
    state.dataset.failed = 'true';
    document.getElementById('pool-cf-retry').classList.remove('hidden');
  }
}
let dnsRoutePending = new Set();
async function setPoolDnsRoute(pool, mode, ip, button) {
  if (dnsRoutePending.has(pool)) { showToast("تغییر قبلی DNS هنوز در حال انجام است"); return; }
  dnsRoutePending.add(pool);
  button.disabled = true;
  const previous = button.textContent; button.textContent = 'در حال تغییر DNS…';
  try {
    const response = await apiFetch('/api/pools/dns-route', {method:'POST',body:{pool,mode,ip}});
    showToast(response.message || response.error || 'تغییر DNS ناموفق بود');
    button.blur();
    if (response.success) { lastRenderedPools = ''; await fetchStatus(); }
  } catch (error) { showToast('ارتباط با سرور ناموفق بود؛ وضعیت DNS را بررسی کنید'); }
  finally {dnsRoutePending.delete(pool); button.disabled = false; button.textContent = previous;}
}
function poolDnsState(pool) {
  const report = pool.dns_report || {};
  const snapshot = report.dns_snapshot;
  const verified = report.subdomain === pool.subdomain && (report.scope || 'single') === (pool.dns_scope || 'single') && snapshot?.success && (report.override_version || null) === (pool.dns_override?.version || null);
  return {verified, ips: verified ? [...new Set(snapshot.records.map(record => record.content))].filter(ip => !snapshot.names || snapshot.names.every(name => snapshot.records.some(r => r.name.toLowerCase() === name && r.content === ip))) : [], source: report.source === 'manual' ? 'آخرین هماهنگی: دستی' : report.source === 'auto' ? 'آخرین هماهنگی: خودکار' : 'منبع تغییر نامشخص'};
}

async function submitPoolCloudflare(e) {
  e.preventDefault();
  const tok = document.getElementById("pool-cf-token").value.trim();
  const zid = document.getElementById("pool-cf-zone").value.trim();
  const scope = document.getElementById('pool-cf-scope').value || 'single';
  const sub = document.getElementById("pool-cf-sub").value.trim();
  const fingerprint = JSON.stringify([currentPoolForAction,tok,zid,sub,scope]);

  const btn = document.getElementById("pool-cf-submit-btn");
  btn.disabled = true;
  btn.querySelector("span").textContent = "در حال ذخیره و تنظیم...";

  try {
    if (scope === 'all_subdomains' && poolCfPreview?.fingerprint !== fingerprint) {
      const preview = await apiFetch('/api/pools/cloudflare-preview',{method:'POST',body:{api_token:tok,zone_id:zid,subdomain:sub}});
      if (!preview.success) { showToast(preview.error || 'خواندن رکوردها ناموفق بود'); return; }
      poolCfPreview = {fingerprint,names:preview.names};
      const box = document.getElementById('pool-cf-preview');
      box.innerHTML = '<strong>رکوردهایی که تحت مدیریت قرار می‌گیرند</strong>' + preview.records.map(r => `<div><bdi>${escapeHtml(r.name)} → ${escapeHtml(r.content)}</bdi><span>${r.proxied ? ' · تبدیل به DNS-only' : ''}</span></div>`).join('');
      box.classList.remove('hidden');
      return;
    }
    const res = await apiFetch("/api/pools/cloudflare", {
      method: "POST",
      body: { pool: currentPoolForAction, api_token: tok, zone_id: zid, subdomain: sub, enabled: true, scope, confirmed_names:poolCfPreview?.names || [] }
    });
    if (res.success) {
      showToast("فیل‌اور DNS برای استخر فعال شد");
      closeModal("pool-cf-modal");
      fetchStatus();
    } else {
      if (scope === "all_subdomains") poolCfPreview = null;
      showToast(`${res.error || "خطا در ذخیره Cloudflare"}`);
    }
  } catch (err) {
    showToast("خطا در ذخیره Cloudflare");
  } finally {
    btn.disabled = false;
    btn.querySelector("span").textContent = scope === "all_subdomains" ? (poolCfPreview?.fingerprint === fingerprint ? "تأیید فهرست و فعال‌سازی برای همه" : "نمایش رکوردهای تحت مدیریت") : "ذخیره و فعال‌سازی فیل‌اور DNS";
  }
}

/* Global Cloudflare */
async function submitGlobalCloudflare(e) {
  e.preventDefault();
  const tok = document.getElementById("cf-global-token").value.trim();
  const zid = document.getElementById("cf-global-zone").value.trim();
  const sub = document.getElementById("cf-global-sub").value.trim();

  showToast("در حال ذخیره تنظیمات پیش‌فرض کلودفلر...");
  try {
    const res = await apiFetch("/api/cloudflare", {
      method: "POST",
      body: { api_token: tok, zone_id: zid, subdomain: sub, enabled: true }
    });
    if (res.success) {
      showToast("تنظیمات عمومی کلودفلر ذخیره شد");
      fetchStatus();
    } else {
      showToast(`${res.error || "خطا در ذخیره"}`);
    }
  } catch (err) {
    showToast("خطا در ارسال تنظیمات کلودفلر");
  }
}

function showDomainFeedback(msg, isSuccess = false) {
  const el = document.getElementById("dash-domain-alert");
  if (!el) return;
  if (!msg) {
    el.classList.add("hidden");
    el.textContent = "";
    return;
  }
  el.textContent = withoutEmoji(msg);
  el.className = isSuccess ? "status-badge healthy" : "inline-error";
  el.style.display = "block";
  el.classList.remove("hidden");
}

/* Dashboard Domain & SSL */
async function submitDashboardDomain(e) {
  if (e) {
    if (typeof e.preventDefault === 'function') e.preventDefault();
    if (typeof e.stopPropagation === 'function') e.stopPropagation();
  }
  showDomainFeedback("");
  const domain = document.getElementById("dash-domain-input").value.trim().toLowerCase();
  const sslMode = document.getElementById("dash-ssl-mode").value;
  const btn = document.getElementById("save-dash-domain-btn");

  if (!domain) {
    showDomainFeedback("لطفاً نام دامنه را وارد کنید");
    return;
  }

  btn.disabled = true;
  showDomainFeedback("در حال تنظیم خودکار وب‌سرور و اتصال دامنه...", true);
  try {
    const res = await apiFetch("/api/dashboard-domain", {
      method: "POST",
      body: { domain: domain, ssl_mode: sslMode, action: "save" }
    });
    if (res.success) {
      showDomainFeedback(res.message || "دامنه با موفقیت تنظیم شد", true);
      const badge = document.getElementById("domain-ssl-badge");
      const link = document.getElementById("dash-cf-link");
      if (badge) badge.style.display = "inline-flex";
      if (link) link.textContent = `https://${domain}:8443`;
      await fetchStatus(true);
    } else {
      showDomainFeedback(res.error || "خطا در تنظیم دامنه");
    }
  } catch (err) {
    showDomainFeedback("خطا در برقراری ارتباط با سرور");
  } finally {
    btn.disabled = false;
  }
}

async function issueLetsEncryptNow(e) {
  if (e) {
    if (typeof e.preventDefault === 'function') e.preventDefault();
    if (typeof e.stopPropagation === 'function') e.stopPropagation();
  }
  showDomainFeedback("");
  const domain = document.getElementById("dash-domain-input").value.trim().toLowerCase();
  const btn = document.getElementById("issue-le-btn");

  if (!domain) {
    showDomainFeedback("لطفاً ابتدا نام دامنه را وارد کنید");
    return;
  }

  btn.disabled = true;
  showDomainFeedback("در حال درخواست و صدور خودکار گواهینامه Let's Encrypt (این کار ممکن است تا 30 ثانیه طول بکشد)...", true);
  try {
    const res = await apiFetch("/api/dashboard-domain", {
      method: "POST",
      body: { domain: domain, action: "issue_ssl" }
    });
    if (res.success) {
      showDomainFeedback(res.message || "گواهینامه SSL با موفقیت فعال شد!", true);
      const badge = document.getElementById("domain-ssl-badge");
      if (badge) badge.style.display = "inline-flex";
      await fetchStatus(true);
    } else {
      showDomainFeedback(res.error || "خطا در دریافت سرتیفیکیت");
    }
  } catch (err) {
    showDomainFeedback("خطا در ارتباط با سرور");
  } finally {
    btn.disabled = false;
  }
}

/* Password Change */
async function submitChangePassword(e) {
  e.preventDefault();
  const newPass = document.getElementById("new-pass-input").value.trim();
  if (newPass.length < 4) {
    formError("change-pass-btn", "رمز عبور باید حداقل 4 کاراکتر باشد");
    return;
  }

  const btn = document.getElementById("change-pass-btn");
  btn.disabled = true;
  btn.querySelector("span").textContent = "در حال ذخیره...";

  try {
    const res = await apiFetch("/api/password", {
      method: "POST",
      body: { new_password: newPass }
    });
    if (res.success) {
      showToast("رمز عبور داشبورد به‌روزرسانی شد");
      document.getElementById("new-pass-input").value = "";
    } else {
      showToast(`${res.error || "خطا در تغییر رمز"}`);
    }
  } catch (err) {
    showToast("خطا در ارتباط با سرور");
  } finally {
    btn.disabled = false;
    btn.querySelector("span").textContent = "ذخیره رمز عبور جدید";
  }
}

/* Node Live Connection Logs Modal */
let logsLoadVersion = 0;
async function openLogsModal(ip, name, pool) {
  const version = ++logsLoadVersion;
  const modal = document.getElementById("logs-modal");
  document.getElementById("logs-modal-title").textContent = `لاگ اتصالات زنده (${name})`;
  document.getElementById("logs-modal-sub").textContent = `آی‌پی سرور: ${ip}`;

  const content = document.getElementById("node-logs-content");
  content.innerHTML = "در حال اتصال امن به سرور ایران و دریافت لاگ‌ها...";
  modal.classList.remove("hidden");

  try {
    const data = await apiFetch(`/api/logs?ip=${encodeURIComponent(ip)}${pool ? "&pool="+encodeURIComponent(pool) : ""}`);
    if (version !== logsLoadVersion || modal.classList.contains("hidden")) return;
    if (data.logs && data.logs.length) {
      content.innerHTML = data.logs.map(l => {
        let cls = "";
        if (l.includes("CLEAN_FLOW") || l.includes("USER_SESSION_ACTIVE")) cls = "log-healthy";
        else if (l.includes("STALL") || l.includes("DROP")) cls = "log-err";
        return `<div class="${cls}">${escapeHtml(withoutEmoji(l))}</div>`;
      }).join("");
      content.scrollTop = content.scrollHeight;
    } else {
      content.innerHTML = `<div style="color:var(--text-muted)">هنوز نشست ترافیکی روی این سرور ثبت نشده است.</div>`;
    }
  } catch (e) {
    if (version !== logsLoadVersion || modal.classList.contains("hidden")) return;
    content.innerHTML = `<div class="log-err">خطا در دریافت لاگ از سرور: ${escapeHtml(e.message)} <button type="button" class="node-log-btn" data-ip="${escapeHtml(ip)}" data-name="${escapeHtml(name)}" data-pool="${escapeHtml(pool || '')}" onclick="openLogsModal(this.dataset.ip, this.dataset.name, this.dataset.pool)">تلاش دوباره</button></div>`;
  }
}

/* ==========================================================================
   9. Utilities: Minimal Copy & Toast
   ========================================================================== */
async function copyText(txt) {
  if (!txt || txt === "-" || txt === "تعیین نشده" || txt === "Not set") return;
  try {
    if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
    await navigator.clipboard.writeText(txt);
  } catch (_) {
    const previous = document.activeElement;
    const field = document.createElement('textarea');
    field.value = txt;
    field.style.position = 'fixed';
    field.style.opacity = '0';
    document.body.appendChild(field);
    field.select();
    const copied = document.execCommand('copy');
    field.remove();
    previous?.focus({ preventScroll: true });
    if (!copied) { showToast('کپی خودکار ممکن نیست؛ مقدار را به صورت دستی انتخاب کنید.'); return; }
  }
  showToast("در کلیپ‌بورد کپی شد");
}

function copyTextFromElem(elemId) {
  const el = document.getElementById(elemId);
  if (el) copyText(el.textContent.trim());
}

function copyKharejIps() {
  const pools = cachedStatus?.pools || [];
  const uniqueKharej = [...new Set(pools.map(p => p.kharej_ip).filter(Boolean))];
  if (uniqueKharej.length) {
    copyText(uniqueKharej.join(", "));
  } else {
    copyTextFromElem('hero-kharej-ip-val');
  }
}

function showToast(msg) {
  const toast = document.getElementById("toast");
  toast.textContent = withoutEmoji(msg);
  toast.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.classList.add("hidden");
  }, 3500);
}

function escapeHtml(str) {
  if (!str) return "";
  // NOTE: single quotes are escaped too -- values are interpolated into
  // single-quoted onclick handlers elsewhere in this file.
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
}

/* Dialog lifecycle applies to every existing form and log sheet. */
function setupDialogs() {
  let returnFocus = null;
  let activeModal = null;
  const app = document.getElementById('app-view');
  const login = document.getElementById('login-view');
  const tabbar = document.getElementById('app-tabbar');
  const observer = new MutationObserver(() => {
    const modal = document.querySelector('.modal-backdrop:not(.hidden)');
    if (modal === activeModal) return;
    if (modal) {
      returnFocus = document.activeElement;
      activeModal = modal;
      document.body.classList.add('modal-open');
      if (tabbar) { tabbar.classList.add('hidden'); tabbar.inert = true; }
      app.inert = true;
      login.inert = true;
      const target = modal.querySelector('input:not([type="hidden"]), select, button');
      (target || modal.querySelector('[role="dialog"]')).focus({ preventScroll: true });
    } else {
      activeModal = null;
      document.body.classList.remove('modal-open');
      if (tabbar && app && !app.classList.contains('hidden')) { tabbar.classList.remove('hidden'); tabbar.inert = false; }
      app.inert = false;
      login.inert = false;
      if (returnFocus?.isConnected) returnFocus.focus({ preventScroll: true });
    }
  });
  document.querySelectorAll('.modal-backdrop').forEach(modal => {
    const heading = modal.querySelector('.sheet-title');
    if (!heading.id) heading.id = `${modal.id}-title`;
    modal.querySelector('[role="dialog"]').setAttribute('aria-labelledby', heading.id);
    observer.observe(modal, { attributes: true, attributeFilter: ['class'] });
  });
  document.addEventListener('keydown', event => {
    if (!activeModal) return;
    if (event.key === 'Escape') { event.preventDefault(); closeModal(activeModal.id); }
    if (event.key !== 'Tab') return;
    const targets = [...activeModal.querySelectorAll('button, input, select, textarea, [tabindex="0"]')].filter(el => !el.disabled && el.tabIndex !== -1 && el.getClientRects().length);
    const first = targets[0], last = targets.at(-1);
    if (event.shiftKey && (document.activeElement === first || !targets.includes(document.activeElement))) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && (document.activeElement === last || !targets.includes(document.activeElement))) { event.preventDefault(); first?.focus(); }
  });
}

/* Persistent capsule navigation; sheets manage background focus independently. */
const navigationMedia = (typeof window !== "undefined" && window.matchMedia) ? window.matchMedia('(max-width: 1100px)') : { matches: false };
function setNavigationOpen(open = false) {
  const nav = document.getElementById('app-tabbar');
  if (nav) {
    nav.inert = false;
    nav.removeAttribute('role');
    nav.removeAttribute('aria-modal');
  }
  document.body.classList.remove('drawer-open');
  document.body.classList.remove('sidebar-collapsed');
}
function toggleNavigation() { setNavigationOpen(); }
function setupNavigation() { setNavigationOpen(); }

/* Icons are markup, never emoji or decorative text glyphs. */
function uiIcon(name) {
  const paths = {plus: '<path d="M12 5v14M5 12h14"/>', pin: '<path d="M20 10c0 6-8 12-8 12S4 16 4 10a8 8 0 1 1 16 0Z"/><circle cx="12" cy="10" r="2.5"/>', globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c5 5 5 13 0 18-5-5-5-13 0-18Z"/>', close: '<path d="m6 6 12 12M6 18 18 6"/>', copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M15 5V3H3v12h2"/>', edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/>'};
  return `<svg class="ui-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.globe}</svg>`;
}
function withoutEmoji(text) {
  return String(text ?? '').replace(/[\p{Extended_Pictographic}\p{Regional_Indicator}\uFE0F\u200D\u20E3]/gu, '').trim();
}
function renderDomainRoutes(data) {
  const validDomain = domain => domain && domain !== 'Not set' && domain !== 'تعیین نشده' ? domain : '';
  const routes = (data.pools || []).map(pool => ({
    name: pool.name, domain: validDomain(pool.subdomain), enabled: Boolean(pool.cf_enabled)
  }));
  const global = data.global_cloudflare || {};
  const defaultDomain = validDomain(global.subdomain);
  if (defaultDomain && !routes.some(route => route.domain === defaultDomain)) {
    routes.push({name: copy.routes.global, domain: defaultDomain, enabled: Boolean(global.enabled)});
  }
  const signature = JSON.stringify(routes);
  if (signature === lastDomainSnapshot) return;
  const container = document.getElementById('domain-routes');
  // Keep keyboard focus while polling; apply any pending snapshot on the next cycle.
  if (container.contains(document.activeElement)) return;
  lastDomainSnapshot = signature;
  document.getElementById('domain-route-count').textContent = faNumber.format(routes.length);
  container.innerHTML = routes.length ? routes.map(route => `
    <div class="domain-route">
      <div class="domain-route-info"><span class="domain-route-pool">${escapeHtml(withoutEmoji(route.name))}</span>
      <bdi class="domain-route-host" dir="ltr">${escapeHtml(route.domain || copy.routes.missing)}</bdi>
      <span class="domain-route-state ${route.enabled && route.domain ? 'good-text' : ''}">${route.domain ? (route.enabled ? copy.routes.enabled : copy.routes.disabled) : copy.routes.missing}</span></div>
      ${route.domain ? `<button type="button" class="copy-chip-btn" data-domain="${escapeHtml(route.domain)}" onclick="copyText(this.dataset.domain)" aria-label="${copy.routes.copy}: ${escapeHtml(route.domain)}" title="${copy.routes.copy}">${uiIcon('copy')}</button>` : ''}
    </div>
  `).join('') : `<p class="empty-hint">${copy.routes.none}</p>`;
}

function renderWatchdogRoutes(data) {
  const box = document.getElementById('watchdog-domain-routes');
  const rows = (data.pools || []).flatMap(pool => {
    const dns = poolDnsState(pool);
    const snapshot = pool.dns_report?.dns_snapshot;
    const names = dns.verified && snapshot?.success ? [...new Set([...(snapshot.names || []), ...(snapshot.records || []).map(r => r.name)].filter(Boolean))] : [];
    return (names.length ? names : [pool.subdomain && pool.subdomain !== 'Not set' ? pool.subdomain : 'دامنه تنظیم نشده']).map(name => {
      const ips = names.length ? [...new Set((snapshot.records || []).filter(r => r.name === name).map(r => r.content))] : dns.ips;
      return `<li class="dns-route-list-row"><div class="dns-route-domain"><strong><bdi dir="ltr">${escapeHtml(name)}</bdi></strong><small>${escapeHtml(withoutEmoji(pool.name))}</small></div><div class="route-ip-chips">${dns.verified ? (ips.length ? ips.map(ip => `<bdi class="ip-chip-pill" dir="ltr">${escapeHtml(ip)}</bdi>`).join('') : '<span class="empty-hint">رکورد A ندارد</span>') : '<span class="empty-hint">رکورد واقعی تأیید نشده</span>'}</div><div class="dns-route-meta"><span class="status-badge">${pool.cf_enabled ? (pool.dns_mode === 'manual' ? 'حالت دستی' : 'حالت خودکار') : 'مدیریت DNS غیرفعال'}</span><small>${dns.source}</small><bdi>${escapeHtml(pool.dns_report?.checked_at || 'هنوز بررسی نشده')}</bdi></div></li>`;
    });
  });
  box.innerHTML = `<ul class="dns-route-list">${rows.join('') || '<li class="empty-hint">استخری ثبت نشده است.</li>'}</ul>`;
}

// Native selects remain form data sources; all interaction uses the custom listbox.
function setupSelectMenus() {
  document.querySelectorAll('select').forEach(select => {
    const wrapper = document.createElement('div');
    wrapper.className = 'custom-select';
    select.before(wrapper); wrapper.append(select);
    select.classList.add('select-source'); select.tabIndex = -1; select.setAttribute('aria-hidden','true');
    const trigger = document.createElement('button');
    trigger.id = `${select.id}-trigger`; trigger.type = 'button'; trigger.className = 'field-input select-trigger';
    trigger.setAttribute('role', 'combobox'); trigger.setAttribute('aria-haspopup', 'listbox');
    trigger.setAttribute('aria-expanded', 'false');
    const label = document.querySelector(`label[for="${select.id}"]`) || wrapper.parentElement.querySelector('.field-label');
    if (label?.htmlFor === select.id) label.htmlFor = trigger.id;
    trigger.setAttribute('aria-label', label?.textContent || (select.id === 'new-pool-kharej' ? 'انتخاب سرور مقصد خارج' : 'پروتکل انتقال تونل'));
    const list = document.createElement('div'); list.id = `${select.id}-options`;
    list.className = 'select-options hidden'; list.setAttribute('role', 'listbox');
    trigger.setAttribute('aria-controls', list.id); wrapper.append(trigger, list);
    let active = 0;
    const close = () => { list.classList.add('hidden'); trigger.setAttribute('aria-expanded', 'false'); trigger.removeAttribute('aria-activedescendant'); };
    const render = () => {
      trigger.disabled = select.disabled;
      trigger.innerHTML = `<span>${escapeHtml(withoutEmoji(select.selectedOptions[0]?.textContent || 'انتخاب کنید'))}</span><svg class="ui-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>`;
      list.replaceChildren();
      Array.from(select.options).forEach((option, i) => {
        const button = document.createElement('button'); button.type = 'button'; button.tabIndex = -1;
        button.id = `${list.id}-${i}`; button.className = 'select-option'; button.textContent = withoutEmoji(option.textContent);
        button.setAttribute('role','option'); button.setAttribute('aria-selected',String(option.selected)); button.disabled = option.disabled || (select.required && !option.value);
        button.addEventListener('click', () => { select.value = option.value; select.dispatchEvent(new Event('change',{bubbles:true})); close(); trigger.focus(); });
        list.append(button);
      });
    };
    const highlight = index => {
      const options = Array.from(list.children); if (!options.length) return;
      const direction = index < active ? -1 : 1;
      active = (index + options.length) % options.length;
      for (let tried = 0; options[active]?.disabled && tried < options.length; tried++) active = (active + direction + options.length) % options.length;
      if (options[active]?.disabled) return;
      options.forEach((option,i) => option.classList.toggle('active',i === active));
      trigger.setAttribute('aria-activedescendant',options[active].id); options[active].scrollIntoView({block:'nearest'});
    };
    const open = () => { if (select.disabled) return; document.querySelectorAll('.custom-select [aria-expanded="true"]').forEach(other => {if (other !== trigger) other.click();}); render(); list.classList.remove('hidden'); trigger.setAttribute('aria-expanded','true'); highlight(Math.max(0,select.selectedIndex)); };
    trigger.addEventListener('click', () => list.classList.contains('hidden') ? open() : close());
    trigger.addEventListener('keydown', event => {
      const opened = !list.classList.contains('hidden');
      if (['ArrowDown','ArrowUp','Home','End','Escape','Enter',' '].includes(event.key)) {
        event.preventDefault();
        if (event.key === 'Escape') { close(); event.stopPropagation(); }
        else if (!opened) open();
        else if (event.key === 'Enter' || event.key === ' ') list.children[active]?.click();
        else highlight(event.key === 'Home' ? 0 : event.key === 'End' ? list.children.length-1 : active + (event.key === 'ArrowUp' ? -1 : 1));
      } else if (event.key === 'Tab') close();
    });
    select.addEventListener('change',render);
    select.addEventListener('invalid',event => {event.preventDefault(); trigger.focus(); open();});
    document.addEventListener('click',event => {if (!event.composedPath().includes(wrapper)) close();});
    new MutationObserver(render).observe(select,{childList:true,subtree:true,attributes:true});
    render();
  });
}
document.addEventListener('DOMContentLoaded',setupSelectMenus);

let poolForTransport = '';
async function retryTransportRollback(pool, button) {
  button.disabled = true;
  try {
    const result = await apiFetch('/api/pools/transport-rollback',{method:'POST',body:{pool}});
    showToast(result.message || result.error || 'بازگردانی ناموفق بود');
    button.blur();lastRenderedPools='';await fetchStatus();
  } catch (error) {showToast('ارتباط برای بازگردانی ناموفق بود');}
  finally {button.disabled = false;}
}

const MANAGED_PACKET_TRANSPORTS = ['fake-sni','split-tls','hop-ttl-injection','tcp-state-desync','l7-header-mutation'];
const ENGINE_TRANSPORTS = {
  backpack: {
    label: "اسکریپت BackPack (موتور 6 ترنسپورت بومی L4)",
    transports: [
      { value: "tcp", label: "01. Standard TCP (کمترین مصرف CPU و تأخیر پایه)", hint: "اتصال مستقیم خام با سرعت حداکثری و حداقل بار پردازنده" },
      { value: "stealth", label: "02. TCP + Stealth (پروتکل استتار Noise بدون اثرانگشت) [پیشنهادی]", hint: "رمزنگاری نویز ضد DPI و غیرقابل شناسایی در لایه 4" },
      { value: "pck", label: "03. TCP + PCK (بسته‌های خام مقاوم در برابر تزریق TCP RST)", hint: "مقاوم در برابر دستکاری و ریست‌های فایروال و شبکه" },
      { value: "kcp", label: "04. UDP + KCP + FEC (اصلاح خطای بسته‌های گم‌شده BackPack)", hint: "پروتکل پرسرعت مبتنی بر UDP مناسب بازی و خطوط با پکت‌لاس" },
      { value: "wss", label: "05. WebSocket Secure TLS 1.3 (شبیه‌سازی مرورگر و عبور CDN)", hint: "شبیه‌سازی اثرانگشت مرورگر (uTLS) و عبور امن از CDNها" },
      { value: "quic", label: "06. UDP + QUIC (نشست استاندارد با رمزنگاری TLS 1.3)", hint: "هندشیک سریع 0-RTT با رمزنگاری مدرن" }
    ]
  },
  paqet: {
    label: "اسکریپت Paqet (موتور پکت خام و حالت‌های کوانتوم L3)",
    transports: [
      { value: "quantum", label: "06. Quantum (KCP Fast-ARQ تهاجمی - رفع گلوگاه پکت‌لاس)", hint: "الگوریتم پرسرعت تهاجمی جهت حذف کامل افت سرعت ناشی از پکت‌لاس" },
      { value: "quantum+", label: "07. Quantum+ (KCP + Reed-Solomon FEC)", hint: "تحمل قطعی بسته‌ها با کدگذاری ماتریسی رید-سولومون بدون نیاز به بازفرست" },
      { value: "quantum-gaming", label: "12. Quantum Gaming (KCP با تایمر 10ms برای بازی و مکالمه)", hint: "تایمر 10ms و ارسال ACK فوری؛ تأخیر به شبکه وابسته است" },
      { value: "paqet", label: "Paqet Raw Carrier (حامل باینری مستقیم پکت روی سوکت خام)", hint: "استفاده مستقیم از باینری رسمی Paqet در لایه 3" }
    ]
  },
  waterwall: {
    label: "اسکریپت WaterWall (موتور گراف نود L7 VLESS + TLS + Mux)",
    transports: [
      { value: "waterwall", label: "WaterWall (VLESS + TLS 1.3 + Mux - زنجیره گراف L7)", hint: "VLESS/TLS/Mux؛ نیازمند گواهی صادرشده از CA عمومی مورد اعتماد موتور" }
    ]
  },
  xray: {
    label: "استتار پیشرفته Xray (حالت‌های XHTTP، XHTTPS و Nova)",
    transports: [
      { value: "xhttp", label: "09. SplitHTTP (تفکیک دوطرفه دانلود/آپلود با پدینگ تصادفی)", hint: "جداسازی کامل استریم آپلود و دانلود برای شکستن سیستم‌های DPI نامتقارن" },
      { value: "xhttps", label: "10. XHTTP + TLS 1.3 + XMUX (استتار پیشرفته)", hint: "کانکشن‌های چندگانه موازی xmux و استتار روی دامنه‌های معتبر" },
      { value: "nova", label: "13. Nova (XHTTP/TLS با قطعه‌بندی ابتدای اتصال)", hint: "تکه‌تکه‌کردن پکت‌های هندشیک TLS جهت دور زدن قطعی‌های هوشمند فایروال" },
      { value: "gre_xhttp", label: "GRE با رمزنگاری و استتار HTTPS", hint: "کپسوله‌سازی بسته‌های لایه 3 GRE داخل استریم استتارشدهٔ HTTPS" }
    ]
  },
  kernel: {
    label: "حامل‌های شبکه و هسته لینوکس (TUN, DC6, WireGuard, GRE, VXLAN)",
    transports: [
      { value: "tun", label: "08. TUN روی UDP/Noise (آزمایشی)", hint: "کارت شبکهٔ واقعی لینوکس با حامل رمزنگاری‌شدهٔ BackPack L3؛ آزمون TCP/UDP پیش از فعال‌شدن" },
      { value: "dc6", label: "11. DC6 (آزمایشی؛ بدون رمزنگاری)", hint: "حامل GRE6 یا IP6IP6 با IPv6 عمومی؛ SIT با IPv4 عمومی. آزمون دوطرفهٔ TCP/UDP پیش از فعال‌شدن" },
      { value: "wireguard", label: "WireGuard (رمزنگاری Curve25519 هسته لینوکس)", hint: "سریع‌ترین و مدرن‌ترین پروتکل VPN کرنل با کلیدهای نامتقارن" },
      { value: "gre", label: "GRE با IPsec — بدون استتار HTTPS", hint: "تونل لایه 3 رسمی با رمزگذاری سخت‌افزاری IPsec AES-GCM" },
      { value: "gre6", label: "GRE6 (آزمایشی — بدون رمزنگاری و استتار)", hint: "کپسوله‌سازی GRE روی آدرس‌های Native IPv6 بدون رمزنگاری" },
      { value: "ip6ip6", label: "IP6IP6 (آزمایشی — بدون رمزنگاری و استتار)", hint: "تونل مستقیم نقطه به نقطه بین سرورهای دارای IPv6 عمومی" },
      { value: "vxlan", label: "VXLAN (آزمایشی؛ بدون رمزنگاری و استتار — سه متد P2P/Bridge/FDB)", hint: "گسترش شبکه محلی L2 با سه روش Point-to-Point، Bridge و FDB" },
      { value: "geneve_ipsec", label: "Geneve + IPsec (آزمایشی — آزمون کرنلی لینک تأیید شد)", hint: "پروتکل مجازی‌سازی نسل جدید شبکه با افزونه‌های متادیتا و رمزنگاری" }
    ]
  },
  spoof: {
    label: "پروفایل‌های پردازش بسته (آزمایشی)",
    transports: [
      { value: "fake-sni", label: "Fake SNI + MD5/BadSum (آزمایشی)", hint: "تزریق ClientHello با SNI انتخابی و بررسی بستهٔ واقعی در کنار آزمون TCP/UDP" },
      { value: "split-tls", label: "TLS Record + TCP Disorder (آزمایشی)", hint: "تقسیم رکورد ClientHello و ارسال معکوس قطعات TCP روی مسیر mTLS" },
      { value: "hop-ttl-injection", label: "TTL محدود با برآورد هاپ (آزمایشی)", hint: "تزریق ClientHello با TTL برآوردشده و محدود؛ مقدار جایگزین و BadSum حفظ می‌شوند" },
      { value: "tcp-state-desync", label: "RST + OOB (آزمایشی)", hint: "تزریق RST نامعتبر و دادهٔ خارج از باند؛ پذیرش فقط پس از مشاهدهٔ تغییر و عبور داده" },
      { value: "l3-ip-spoof", disabled: true, label: "05. L3 Source-IP Spoofing (جعل آدرس آی‌پی مبدا لایه ۳)", hint: "بازنویسی هدر IP در سوکت خام برای قطع همبستگی ۵-تایی جریان‌های رفت و برگشت" },
      { value: "l7-header-mutation", label: "HTTP Host Header Mutation (آزمایشی)", hint: "تغییر واقعی حروف نام هدر Host روی CONNECT؛ دادهٔ TCP/UDP در mTLS عبور می‌کند" },
      { value: "udp-raw-spoof", disabled: true, label: "07. Raw UDP / QUIC Spoofing (استتار و ضدسانسور ترافیک UDP)", hint: "تزریق پکت‌های اولیه جعلی QUIC/WireGuard جهت دور زدن مسدودسازی پروتکل‌های UDP" },
      { value: "dns-spoof", disabled: true, label: "08. DNS Anti-Poisoning (مسدودسازی پاسخ‌های جعلی و بوگون‌های زیرساخت)", hint: "فیلتر بسته‌های تزریقی پورت ۵۳ و مسیردهی امن پرس‌وجوهای DNS" },
      { value: "spoof-tcp-syn", disabled: true, label: "09. ParsaKSH TCP-SYN Spoof (جعل سورس IP با TCP SYN و راند-رابین)", hint: "سوکت خام لایه ۴ با تولید بسته‌های TCP SYN، چک‌سام دستی و چرخش بین آی‌پی‌های مجاز" },
      { value: "spoof-udp-raw", disabled: true, label: "10. ParsaKSH UDP Spoof (جعل بسته‌های خام UDP با راند-رابین)", hint: "ارسال بسته‌های UDP با جعل آی‌پی مبدأ روی لیست آی‌پی‌های سفید بدون نشست مستقیم" },
      { value: "spoof-icmp", disabled: true, label: "11. ParsaKSH ICMP (تونل داده در اکوی ICMP با غیرفعال‌سازی ریپلای)", hint: "کپسوله‌سازی ترافیک در بسته‌های ICMP Ping و مسدودسازی پاسخ پیش‌فرض لینوکس" },
      { value: "qs-dns-hybrid", disabled: true, label: "12. QS-Tunnel Hybrid (آپلود DNS بیس۳۲ + دانلود Raw IP-Spoof)", hint: "دور زدن محدودیت uRPF: ارسال آپلود با کوئری‌های DNS استاندارد و دریافت مستقیم از خارج با جعل سورس IP" },
      { value: "hyperion-x", disabled: true, label: "13. HYPERION-X Tri-Vector (runtime تکمیل نشده)", hint: "موتور مدیریت‌شده و آزمون انتقال داده هنوز تکمیل نشده است" }
    ]
  },
  other: {
    label: "سایر پروتکل‌های وب و اضطراری (WebSocket, HTTP/2, Slipstream)",
    transports: [
      { value: "ws", label: "02. WebSocket Plaintext RFC 6455 (پشت ریورس‌پروکسی)", hint: "استریم وب‌سوکت ساده جهت کار پشت CDN یا Nginx/Caddy" },
      { value: "http", label: "HTTP/1.1 CONNECT + mTLS (آزمایشی)", hint: "حامل CONNECT با انتقال TCP/UDP و گواهی اختصاصی دوطرفه؛ بدون ادعای HTTP/2 یا تقلید مرورگر" },
      { value: "https", label: "HTTPS CONNECT + mTLS (آزمایشی)", hint: "CONNECT روی TLS1.3 با گواهی اختصاصی و اعتبارسنجی هویت دوطرفه؛ دامنه یا گواهی عمومی لازم نیست" },
      { value: "slipstream", label: "Slipstream (آزمایشی — تونل اضطراری DNS)", hint: "مسیر پشتیبان و اضطراری برای عبور از فیلترینگ کامل از طریق پرس‌وجوهای DNS" }
    ]
  }
};

const TRANSPORT_TO_ENGINE = {};
Object.entries(ENGINE_TRANSPORTS).forEach(([eng, data]) => {
  data.transports.forEach(t => {
    TRANSPORT_TO_ENGINE[t.value] = eng;
  });
});

function populatePoolTransports(engineKey, preferredTransport) {
  const protoSel = document.getElementById("new-pool-proto");
  if (!protoSel) return;
  const cfg = ENGINE_TRANSPORTS[engineKey] || ENGINE_TRANSPORTS.backpack;
  const opts = cfg.transports;
  const chosen = opts.some(t => !t.disabled && t.value === preferredTransport) ? preferredTransport : (engineKey === "kernel" ? "wireguard" : (opts.find(t => !t.disabled)?.value || ""));
  protoSel.innerHTML = opts.map(t => `<option value="${escapeHtml(t.value)}" ${t.disabled ? "disabled" : ""} ${t.value === chosen ? "selected" : ""}>${escapeHtml(t.label)}</option>`).join("");
  protoSel.value = chosen;
  updateTransportDesc(engineKey, chosen);
}

function updateTransportDesc(engineKey, transportValue) {
  const descEl = document.getElementById("new-pool-transport-desc");
  if (!descEl) return;
  const cfg = ENGINE_TRANSPORTS[engineKey] || ENGINE_TRANSPORTS[TRANSPORT_TO_ENGINE[transportValue]] || ENGINE_TRANSPORTS.backpack;
  const found = cfg.transports.find(t => t.value === transportValue);
  descEl.textContent = found ? found.hint : "";
}

function onPoolEngineChanged() {
  const engineSel = document.getElementById("new-pool-engine");
  const engineKey = engineSel ? engineSel.value : "backpack";
  populatePoolTransports(engineKey);
  updateGreCreateFields();
}

function onPoolTransportChanged() {
  const protoSel = document.getElementById("new-pool-proto");
  const engineSel = document.getElementById("new-pool-engine");
  const transport = protoSel ? protoSel.value : "";
  const engineKey = engineSel ? engineSel.value : (TRANSPORT_TO_ENGINE[transport] || "backpack");
  updateTransportDesc(engineKey, transport);
  updateGreCreateFields();
}

function openTransportModal(name) {
  const pool = cachedStatus?.pools.find(p => p.name === name);
  if (!pool) return;
  poolForTransport = name;
  const currentEngine = TRANSPORT_TO_ENGINE[pool.transport] || (pool.engine in ENGINE_TRANSPORTS ? pool.engine : "backpack");
  const currentTransport = pool.transport || "tcp";

  const summaryEl = document.getElementById('transport-summary');
  if (summaryEl) {
    summaryEl.innerHTML = `<bdi dir="auto">${escapeHtml(name)}</bdi><span>موتور فعلی: <bdi dir="ltr">${escapeHtml(currentEngine)}</bdi></span><span>نوع فعلی: <bdi dir="ltr">${escapeHtml(currentTransport)}</bdi></span><span>${faNumber.format(pool.nodes?.length || 0)} نود</span>`;
  }

  const engineSel = document.getElementById('transport-change-engine');
  if (engineSel) {
    engineSel.value = currentEngine in ENGINE_TRANSPORTS ? currentEngine : "backpack";
  }

  populateTransportModalOptions(engineSel ? engineSel.value : "backpack", currentTransport);

  const tlsInput = document.getElementById('transport-tls-server-name');
  if (tlsInput) {
    tlsInput.value = pool.camouflage?.server_name || pool.subdomain || "";
  }
  const mtuInput = document.getElementById('transport-mtu-input');
  if (mtuInput) {
    mtuInput.value = pool.wireguard_mtu || pool.gre_mtu || pool.mtu || 1400;
  }
  const slipDomainInput = document.getElementById('transport-slipstream-domain');
  if (slipDomainInput) {
    slipDomainInput.value = pool.camouflage?.domain || pool.subdomain || "";
  }

  updateTransportModalAdaptiveFields();
  document.getElementById('transport-modal').classList.remove('hidden');
}

function updateTransportModalDesc(engineKey, transportValue) {
  const descEl = document.getElementById("transport-target-desc");
  if (!descEl) return;
  const cfg = ENGINE_TRANSPORTS[engineKey] || ENGINE_TRANSPORTS[TRANSPORT_TO_ENGINE[transportValue]] || ENGINE_TRANSPORTS.backpack;
  const found = cfg.transports.find(t => t.value === transportValue);
  descEl.textContent = found ? found.hint : "";
}

function populateTransportModalOptions(engineKey, currentTransport) {
  const targetSel = document.getElementById('transport-target');
  if (!targetSel) return;
  const cfg = ENGINE_TRANSPORTS[engineKey] || ENGINE_TRANSPORTS.backpack;
  const opts = cfg.transports;
  const httpFamily = ['http','https'].includes(currentTransport);
  const packetCurrent = TRANSPORT_TO_ENGINE[currentTransport]==='spoof';
  const unavailable = t => t.disabled || packetCurrent || engineKey==='spoof' || (httpFamily ? !['http','https'].includes(t.value) : ['http','https'].includes(t.value));

  targetSel.innerHTML = `<option value="" disabled ${!opts.some(t => !unavailable(t) && t.value !== currentTransport) ? 'selected' : ''}>نوع جدید را انتخاب کنید</option>` +
    opts.map(t => {
      const isCurrent = t.value === currentTransport;
      return `<option value="${escapeHtml(t.value)}" ${isCurrent || unavailable(t) ? 'disabled' : ''}>${escapeHtml(t.label)}${isCurrent ? ' (نوع فعلی)' : ''}</option>`;
    }).join("");

  const firstAvailable = opts.find(t => !unavailable(t) && t.value !== currentTransport);
  if (firstAvailable) {
    targetSel.value = firstAvailable.value;
  } else {
    targetSel.value = "";
  }
  updateTransportModalDesc(engineKey, targetSel.value);
  updateTransportModalAdaptiveFields();
  const submit=document.getElementById('transport-submit');
  if(submit){submit.disabled=!firstAvailable;submit.title=packetCurrent||engineKey==='spoof'?'برای این پروفایل استخر جداگانه بسازید':!firstAvailable?'نوع قابل تغییر موجود نیست':'';}
  if(packetCurrent||engineKey==='spoof'){const description=document.getElementById('transport-target-desc');if(description)description.textContent='برای تغییر پروفایل پردازش بسته، استخر جداگانه بسازید.';}
}

function onTransportChangeEngineChanged() {
  const engineSel = document.getElementById('transport-change-engine');
  const pool = cachedStatus?.pools.find(p => p.name === poolForTransport);
  const currentTransport = pool ? pool.transport : "";
  populateTransportModalOptions(engineSel ? engineSel.value : "backpack", currentTransport);
}

function onTransportChangeTransportChanged() {
  const targetSel = document.getElementById('transport-target');
  const engineSel = document.getElementById('transport-change-engine');
  const transport = targetSel ? targetSel.value : "";
  const engineKey = engineSel ? engineSel.value : (TRANSPORT_TO_ENGINE[transport] || "backpack");
  updateTransportModalDesc(engineKey, transport);
  updateTransportModalAdaptiveFields();
}

function updateTransportModalAdaptiveFields() {
  const targetSel = document.getElementById('transport-target');
  const transport = targetSel ? targetSel.value : "";

  const tlsGroup = document.getElementById('transport-change-tls-fields');
  const fecGroup = document.getElementById('transport-change-fec-fields');
  const mtuGroup = document.getElementById('transport-change-mtu-fields');
  const slipGroup = document.getElementById('transport-change-slipstream-fields');

  if (tlsGroup) {
    tlsGroup.classList.toggle('hidden', !['xhttp', 'xhttps', 'nova', 'gre_xhttp', 'waterwall'].includes(transport));
  }
  if (fecGroup) {
    fecGroup.classList.toggle('hidden', !['quantum+', 'quantum'].includes(transport));
  }
  const dc6Group = document.getElementById('transport-change-dc6-fields');
  if (dc6Group) {
    dc6Group.classList.toggle('hidden', transport !== 'dc6');
  }
  if (mtuGroup) {
    mtuGroup.classList.toggle('hidden', !['gre', 'gre6', 'ip6ip6', 'wireguard', 'vxlan', 'geneve_ipsec', 'tun'].includes(transport));
  }
  if (slipGroup) {
    slipGroup.classList.toggle('hidden', transport !== 'slipstream');
  }
  const spoofGroup = document.getElementById('transport-change-spoof-fields');
  if (spoofGroup) {
    spoofGroup.classList.toggle('hidden', !['fake-sni', 'split-tls', 'hop-ttl-injection', 'tcp-state-desync', 'l3-ip-spoof', 'l7-header-mutation', 'udp-raw-spoof', 'dns-spoof', 'spoof', 'spoof-tcp-syn', 'spoof-udp-raw', 'spoof-icmp', 'qs-dns-hybrid', 'hyperion-x'].includes(transport));
  }
}

async function submitTransportChange(event) {
  event.preventDefault();
  const button = document.getElementById('transport-submit');
  button.disabled = true;
  try {
    const transport = document.getElementById('transport-target').value;
    const engineSel = document.getElementById('transport-change-engine');
    const engine = engineSel ? engineSel.value : (TRANSPORT_TO_ENGINE[transport] || "backpack");

    const payload = {
      pool: poolForTransport,
      transport: transport,
      engine: engine,
    };

    if (transport === 'dc6') {
      const c = (document.getElementById('transport-dc6-carrier')?.value || 'sit').trim();
      payload.carrier = c;
      payload.carrier_type = c;
      payload.mtu = parseInt(document.getElementById('transport-dc6-mtu')?.value || '1280', 10);
      payload.dc6_mtu = payload.mtu;
    }

    if (['fake-sni', 'split-tls', 'hop-ttl-injection', 'tcp-state-desync', 'l3-ip-spoof', 'l7-header-mutation', 'udp-raw-spoof', 'dns-spoof', 'spoof', 'spoof-tcp-syn', 'spoof-udp-raw', 'spoof-icmp', 'qs-dns-hybrid', 'hyperion-x'].includes(transport)) {
      payload.fake_sni = (document.getElementById('transport-spoof-fake-sni')?.value || 'www.shaparak.ir').trim();
      payload.auto_ttl_delta = parseInt(document.getElementById('transport-spoof-ttl-delta')?.value || '3', 10);
      payload.spoof_ips = (document.getElementById('transport-spoof-ip-list')?.value || '').trim();
      payload.peer_spoof_ip = (document.getElementById('transport-spoof-peer-ip')?.value || '').trim();
      payload.dns_resolvers = (document.getElementById('transport-spoof-dns-resolvers')?.value || '').trim();
      payload.fake_send_ip = (document.getElementById('transport-spoof-fake-send-ip')?.value || '').trim();
      payload.knock_key = (document.getElementById('transport-spoof-knock-key')?.value || '').trim();
    }
    if (['xhttp', 'xhttps', 'nova', 'gre_xhttp', 'waterwall'].includes(transport)) {
      const serverName = (document.getElementById('transport-tls-server-name')?.value || '').trim();
      const outerPort = parseInt(document.getElementById('transport-tls-outer-port')?.value || '443', 10);
      payload.camouflage = { server_name: serverName, port: outerPort };
      payload.server_name = serverName;
      payload.port = outerPort;
    }
    if (['quantum+', 'quantum'].includes(transport)) {
      payload.fec_datashard = parseInt(document.getElementById('transport-fec-data')?.value || '10', 10);
      payload.fec_parityshard = parseInt(document.getElementById('transport-fec-parity')?.value || '3', 10);
    }
    if (['gre', 'gre6', 'ip6ip6', 'wireguard', 'vxlan', 'geneve_ipsec', 'tun'].includes(transport)) {
      payload.mtu = parseInt(document.getElementById('transport-mtu-input')?.value || '1400', 10);
    }
    if (transport === 'slipstream') {
      payload.domain = (document.getElementById('transport-slipstream-domain')?.value || '').trim();
      payload.resolvers = (document.getElementById('transport-slipstream-resolvers')?.value || '').trim();
    }

    const result = await apiFetch('/api/pools/transport', {
      method: 'POST',
      body: payload
    });
    showToast(result.message || result.error || 'شروع تغییر ناموفق بود');
    if (result.success) {
      closeModal('transport-modal');
      lastRenderedPools = '';
      await fetchStatus();
    }
  } catch (error) {
    showToast('شروع عملیات تأیید نشد؛ وضعیت کارت استخر را بررسی کنید');
  } finally {
    button.disabled = false;
  }
}

if (typeof window !== "undefined") {
  window.onPoolEngineChanged = onPoolEngineChanged;
  window.onPoolTransportChanged = onPoolTransportChanged;
  window.populatePoolTransports = populatePoolTransports;
  window.ENGINE_TRANSPORTS = ENGINE_TRANSPORTS;
  window.openTransportModal = openTransportModal;
  window.populateTransportModalOptions = populateTransportModalOptions;
  window.onTransportChangeEngineChanged = onTransportChangeEngineChanged;
  window.onTransportChangeTransportChanged = onTransportChangeTransportChanged;
  window.updateTransportModalAdaptiveFields = updateTransportModalAdaptiveFields;
  window.submitTransportChange = submitTransportChange;
}

function updateGreCreateFields() {
  const protoEl = document.getElementById('new-pool-proto');
  if (!protoEl) return;
  const mode = protoEl.value;
  const engineSel = document.getElementById('new-pool-engine');
  const targetEngine = TRANSPORT_TO_ENGINE[mode];
  if (targetEngine && engineSel && engineSel.value !== targetEngine) {
    engineSel.value = targetEngine;
    if (protoEl.options && ![...protoEl.options].some(o => o.value === mode)) {
      populatePoolTransports(targetEngine, mode);
    }
  }
  updateTransportDesc(targetEngine || engineSel?.value || 'backpack', mode);
  const gre = mode === 'gre';
  document.getElementById('gre-create-fields').classList.toggle('hidden',!gre);
  document.getElementById('new-pool-gre-mtu').disabled=!gre;

  const wireguard = mode === 'wireguard';
  const wireguardDiv = document.getElementById('wireguard-create-fields');
  if (wireguardDiv) {
    wireguardDiv.classList.toggle('hidden', !wireguard);
    ['new-pool-wireguard-port', 'new-pool-wireguard-mtu', 'new-pool-wireguard-psk'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.disabled = !wireguard;
    });
  }

  const gre6 = mode === 'gre6';
  const gre6Div = document.getElementById('gre6-create-fields');
  if (gre6Div) {
    gre6Div.classList.toggle('hidden', !gre6);
    const el = document.getElementById('new-pool-gre6-mtu');
    if (el) el.disabled = !gre6;
  }

  const ip6ip6 = mode === 'ip6ip6';
  const ip6ip6Div = document.getElementById('ip6ip6-create-fields');
  if (ip6ip6Div) {
    ip6ip6Div.classList.toggle('hidden', !ip6ip6);
    const el = document.getElementById('new-pool-ip6ip6-mtu');
    if (el) el.disabled = !ip6ip6;
  }

  const geneve = mode === 'geneve_ipsec';
  const geneveDiv = document.getElementById('geneve-create-fields');
  if (geneveDiv) {
    geneveDiv.classList.toggle('hidden', !geneve);
    ['new-pool-geneve-vni', 'new-pool-geneve-mtu'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.disabled = !geneve;
    });
  }

  const vxlan = mode === 'vxlan';
  const vxlanDiv = document.getElementById('vxlan-create-fields');
  if (vxlanDiv) {
    vxlanDiv.classList.toggle('hidden', !vxlan);
    ['new-pool-vxlan-method', 'new-pool-vxlan-vni', 'new-pool-vxlan-port', 'new-pool-vxlan-mtu', 'new-pool-vxlan-bridge'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.disabled = !vxlan;
    });
  }

  const paqet = mode === 'paqet';
  const paqetDiv = document.getElementById('paqet-create-fields');
  if (paqetDiv) {
    paqetDiv.classList.toggle('hidden', !paqet);
    ['paqet-tunnel-port', 'paqet-binary'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.disabled = !paqet;
    });
  }

  const slipstream = mode === 'slipstream';
  const slipstreamDiv = document.getElementById('slipstream-create-fields');
  if (slipstreamDiv) {
    slipstreamDiv.classList.toggle('hidden', !slipstream);
    ['slipstream-domain', 'slipstream-resolvers', 'slipstream-dns-port', 'slipstream-rate-limit'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.disabled = !slipstream;
    });
  }

  // TUN (Kernel L3 Carrier)
  const tun = mode === 'tun';
  const tunDiv = document.getElementById('tun-create-fields');
  if (tunDiv) {
    tunDiv.classList.toggle('hidden', !tun);
    const el = document.getElementById('new-pool-tun-mtu');
    if (el) el.disabled = !tun;
  }

  // DC6 (Direct Connect IPv6 Carrier)
  const dc6 = mode === 'dc6';
  const dc6Div = document.getElementById('dc6-create-fields');
  if (dc6Div) {
    dc6Div.classList.toggle('hidden', !dc6);
    ['new-pool-dc6-carrier', 'new-pool-dc6-mtu'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.disabled = !dc6;
    });
  }

  // Quantum Family (KCP, Quantum+, Quantum Gaming)
  const quantum = ['quantum', 'quantum+', 'quantum-gaming'].includes(mode);
  const quantumDiv = document.getElementById('quantum-create-fields');
  if (quantumDiv) {
    quantumDiv.classList.toggle('hidden', !quantum);
    const fecDiv = document.getElementById('quantum-fec-inputs');
    const isFec = mode === 'quantum+';
    if (fecDiv) {
      fecDiv.classList.toggle('hidden', !isFec);
      ['new-pool-quantum-data', 'new-pool-quantum-parity'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.disabled = !isFec;
      });
    }
  }

  // HTTPS / Xray family
  const https = ['xhttp', 'xhttps', 'nova', 'gre_xhttp', 'waterwall', 'reality'].includes(mode);
  const section = document.getElementById('https-create-fields');
  if (!section) return;
  section.classList.toggle('hidden', !https);
  document.getElementById('waterwall-certificate-hint')?.classList.toggle('hidden', mode !== 'waterwall');
  const binaryInput = document.getElementById('https-binary');
  if (binaryInput) {
    const defaults = ['/usr/local/bin/xray', '/usr/local/bin/waterwall'];
    if (!binaryInput.value || defaults.includes(binaryInput.value)) {
      binaryInput.value = mode === 'waterwall' ? defaults[1] : defaults[0];
    }
  }
  const binaryLabel = document.querySelector('label[for="https-binary"]');
  if (binaryLabel) binaryLabel.textContent = mode === 'waterwall' ? 'مسیر WaterWall روی هر دو سرور' : 'مسیر Xray روی هر دو سرور';
  section.querySelectorAll('input').forEach(input => input.disabled = !https);
  document.getElementById('https-certificate-fields')?.classList.toggle('hidden', !https);
  ['https-certificate', 'https-key'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.disabled = !https;
  });

  const xmuxDiv = document.getElementById('https-xmux-fields');
  if (xmuxDiv) {
    const isXmux = mode === 'xhttps';
    xmuxDiv.classList.toggle('hidden', !isXmux);
    const el = document.getElementById('https-xmux-concurrency');
    if (el) el.disabled = !isXmux;
  }

  const novaDiv = document.getElementById('https-nova-fields');
  if (novaDiv) {
    const isNova = mode === 'nova';
    novaDiv.classList.toggle('hidden', !isNova);
    ['https-fragment-min', 'https-fragment-max'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.disabled = !isNova;
    });
  }

  // Spoof family (Anti-DPI & Desync)
  const spoof = ['fake-sni', 'split-tls', 'hop-ttl-injection', 'tcp-state-desync', 'l3-ip-spoof', 'l7-header-mutation', 'udp-raw-spoof', 'dns-spoof', 'spoof', 'spoof-tcp-syn', 'spoof-udp-raw', 'spoof-icmp', 'qs-dns-hybrid', 'hyperion-x'].includes(mode);
  const spoofDiv = document.getElementById('spoof-create-fields');
  if (spoofDiv) {
    spoofDiv.classList.toggle('hidden', !spoof);
    ['spoof-fake-sni', 'spoof-ttl-delta', 'spoof-ip-list', 'spoof-peer-ip', 'spoof-dns-resolvers', 'spoof-fake-send-ip', 'spoof-knock-key'].forEach(id => {
      const el = document.getElementById(id);
      const managed = MANAGED_PACKET_TRANSPORTS.includes(mode);
      const visible = spoof && (!managed || (id==='spoof-fake-sni' && ['fake-sni','hop-ttl-injection'].includes(mode)) || (id==='spoof-ttl-delta' && mode==='hop-ttl-injection'));
      if (el) {
        el.disabled = !visible;
        el.required = visible && ['spoof-fake-sni','spoof-ttl-delta'].includes(id);
        el.closest?.('.input-group')?.classList.toggle('hidden',!visible);
      }
    });
  }
}
let greSettingsPool='';
function openGreSettingsModal(name) {
  const pool=cachedStatus?.pools.find(p=>p.name===name);
  if (!pool || pool.transport!=='gre') return;
  greSettingsPool=name;
  document.getElementById('gre-settings-summary').textContent=name+' · GRE + IPsec';
  document.getElementById('gre-settings-mtu').value=pool.gre_mtu || 1400;
  document.getElementById('gre-settings-modal').classList.remove('hidden');
}
async function submitGreSettings(event) {
  event.preventDefault();const button=document.getElementById('gre-settings-submit');button.disabled=true;
  try {
    const result=await apiFetch('/api/pools/gre-settings',{method:'POST',body:{pool:greSettingsPool,mtu:document.getElementById('gre-settings-mtu').value}});
    if(result.success){closeModal('gre-settings-modal');showToast('MTU لینک‌های GRE اعمال و بررسی شد');}
    lastRenderedPools='';await fetchStatus(true);
  } catch(error){showToast('نتیجهٔ تغییر GRE تأیید نشد؛ وضعیت استخر را بررسی کنید');}
  finally{button.disabled=false;}
}
async function recoverGreSettings(pool,button) {
  button.disabled=true;
  try{const result=await apiFetch('/api/pools/gre-recover',{method:'POST',body:{pool}});showToast(result.message || result.error);lastRenderedPools='';await fetchStatus(true);}
  catch(error){showToast('بازگردانی GRE تأیید نشد؛ وضعیت استخر را بررسی کنید');}
  finally{button.disabled=false;}
}

let slipstreamSettingsPool = '';
function openSlipstreamSettingsModal(name) {
  const pool = cachedStatus?.pools.find(pool => pool.name === name);
  if (!pool || pool.engine !== 'slipstream' || !pool.slipstream) return;
  slipstreamSettingsPool = name;
  const config = pool.slipstream;
  document.getElementById('slipstream-settings-summary').textContent = name;
  document.getElementById('slipstream-settings-domain').value = config.domain || '';
  document.getElementById('slipstream-settings-resolvers').value = (config.resolvers || []).join(', ');
  document.getElementById('slipstream-settings-port').value = config.dns_port || 53;
  const rate = document.getElementById('slipstream-settings-rate');
  rate.value = config.rate_limit || 1000;
  rate.disabled = Number(config.slipstream_runtime_version || 1) < 2;
  document.getElementById('slipstream-settings-legacy').classList.toggle('hidden', !rate.disabled);
  formError('slipstream-settings-submit', '');
  document.getElementById('slipstream-settings-modal').classList.remove('hidden');
}
async function submitSlipstreamSettings(event) {
  event.preventDefault();
  const button = document.getElementById('slipstream-settings-submit');
  const pool = cachedStatus?.pools.find(pool => pool.name === slipstreamSettingsPool);
  if (!pool?.slipstream) return;
  const previous = pool.slipstream;
  const proposed = {
    domain: document.getElementById('slipstream-settings-domain').value.trim().toLowerCase().replace(/\.$/, ''),
    resolvers: document.getElementById('slipstream-settings-resolvers').value.split(',').map(value => value.trim()).filter(Boolean),
    dns_port: Number(document.getElementById('slipstream-settings-port').value),
  };
  if (!document.getElementById('slipstream-settings-rate').disabled) proposed.rate_limit = Number(document.getElementById('slipstream-settings-rate').value);
  const settings = Object.fromEntries(Object.entries(proposed).filter(([key, value]) => JSON.stringify(value) !== JSON.stringify(previous[key])));
  if (!Object.keys(settings).length) {formError('slipstream-settings-submit', 'تغییری انتخاب نشده است');return;}
  button.disabled = true;
  formError('slipstream-settings-submit', '');
  try {
    const result = await apiFetch('/api/pools/slipstream-settings', {method: 'POST', body: {pool: slipstreamSettingsPool, settings}});
    if (result.accepted) {
      closeModal('slipstream-settings-modal');
      showToast('تغییر تنظیمات شروع شد؛ نتیجه را در کارت استخر دنبال کنید');
      lastRenderedPools = '';
      await fetchStatus(true);
    } else formError('slipstream-settings-submit', result.error || 'عملیات شروع نشد');
  } catch (error) {formError('slipstream-settings-submit', error.message || 'شروع تغییر تنظیمات تأیید نشد؛ دوباره تلاش کنید');}
  finally {button.disabled = false;}
}

let geneveSettingsPool='';
function openGeneveSettingsModal(name) {
  const pool=cachedStatus?.pools.find(p=>p.name===name);
  if (!pool || (!['geneve','geneve_ipsec'].includes(pool.engine) && pool.transport !== 'geneve_ipsec')) return;
  geneveSettingsPool=name;
  const vniVal = pool.vni || (pool.nodes?.[0]?.geneve?.vni) || 'خودکار';
  document.getElementById('geneve-settings-summary').textContent=name+' · Geneve + IPsec (VNI ' + vniVal + ')';
  document.getElementById('geneve-settings-mtu').value=pool.geneve_mtu || pool.nodes?.[0]?.geneve?.mtu || 1400;
  document.getElementById('geneve-settings-modal').classList.remove('hidden');
}
async function submitGeneveSettings(event) {
  event.preventDefault();const button=document.getElementById('geneve-settings-submit');button.disabled=true;
  try {
    const result=await apiFetch('/api/pools/geneve-settings',{method:'POST',body:{pool:geneveSettingsPool,mtu:document.getElementById('geneve-settings-mtu').value}});
    if(result.success){closeModal('geneve-settings-modal');showToast('MTU اینترفیس‌های Geneve اعمال و بررسی شد');}
    else {showToast(result.error || result.message || 'خطا در اعمال MTU');}
    lastRenderedPools='';await fetchStatus(true);
  } catch(error){showToast('نتیجهٔ تغییر Geneve تأیید نشد؛ وضعیت استخر را بررسی کنید');}
  finally{button.disabled=false;}
}

let vxlanSettingsPool = '';
async function openVxlanSettingsModal(name) {
  const pool = cachedStatus?.pools.find(p => p.name === name);
  if (!pool || (pool.engine !== 'vxlan' && pool.transport !== 'vxlan')) return;
  vxlanSettingsPool = name;
  const methodTitle = pool.vxlan_method === 'bridge_pointip' ? 'Bridge + IP Pointing' : pool.vxlan_method === 'fdb_bridge' ? 'Bridge + FDB Unicast' : 'P2P Unicast';
  document.getElementById('vxlan-settings-summary').textContent = `${name} · VXLAN (${methodTitle}) · VNI ${pool.vni || 1000} · UDP ${pool.dst_port || 4789}`;
  document.getElementById('vxlan-settings-mtu').value = pool.vxlan_mtu || 1400;
  const statusBox = document.getElementById('vxlan-status-box');
  statusBox.textContent = 'در حال دریافت وضعیت زنده اینترفیس‌ها...';
  document.getElementById('vxlan-settings-modal').classList.remove('hidden');

  try {
    const res = await apiFetch('/api/pools/vxlan-status', { method: 'POST', body: { pool: name } });
    if (res.success && res.status) {
      statusBox.textContent = JSON.stringify(res.status, null, 2);
    } else {
      statusBox.textContent = res.message || 'وضعیت زنده در دسترس نیست';
    }
  } catch (e) {
    statusBox.textContent = 'خطا در ارتباط با سرور یا سرورها پاسخگو نیستند';
  }
}

async function submitVxlanSettings(event) {
  event.preventDefault();
  const button = document.getElementById('vxlan-settings-submit');
  button.disabled = true;
  try {
    const result = await apiFetch('/api/pools/vxlan-settings', {
      method: 'POST',
      body: { pool: vxlanSettingsPool, mtu: document.getElementById('vxlan-settings-mtu').value }
    });
    if (result.success) {
      closeModal('vxlan-settings-modal');
      showToast('MTU اینترفیس‌های VXLAN اعمال و بررسی شد');
    } else {
      showToast(result.error || result.message || 'خطا در اعمال MTU');
    }
    lastRenderedPools = '';
    await fetchStatus(true);
  } catch (error) {
    showToast('نتیجهٔ تغییر MTU تأیید نشد؛ وضعیت را بررسی کنید');
  } finally {
    button.disabled = false;
  }
}

let gre6SettingsPool = '';
function openGre6SettingsModal(name) {
  const pool = cachedStatus?.pools.find(p => p.name === name);
  if (!pool || (pool.engine !== 'gre6' && pool.transport !== 'gre6')) return;
  gre6SettingsPool = name;
  document.getElementById('gre6-settings-summary').textContent = `${name} · GRE6 (آزمایشی — بدون رمزنگاری و استتار)`;
  document.getElementById('gre6-settings-mtu').value = pool.gre6_mtu || pool.nodes?.[0]?.gre6?.mtu || 1400;
  document.getElementById('gre6-settings-modal').classList.remove('hidden');
}

async function submitGre6Settings(event) {
  event.preventDefault();
  const button = document.getElementById('gre6-settings-submit');
  button.disabled = true;
  try {
    const result = await apiFetch('/api/pools/gre6-settings', {
      method: 'POST',
      body: { pool: gre6SettingsPool, mtu: document.getElementById('gre6-settings-mtu').value }
    });
    if (result.success) {
      closeModal('gre6-settings-modal');
      showToast('MTU اینترفیس‌های GRE6 اعمال و بررسی شد');
    } else {
      showToast(result.error || result.message || 'خطا در اعمال MTU');
    }
    lastRenderedPools = '';
    await fetchStatus(true);
  } catch (error) {
    showToast('نتیجهٔ تغییر MTU GRE6 تأیید نشد؛ وضعیت را بررسی کنید');
  } finally {
    button.disabled = false;
  }
}

let ip6ip6SettingsPool = '';
function openIp6ip6SettingsModal(name) {
  const pool = cachedStatus?.pools.find(p => p.name === name);
  if (!pool || (pool.engine !== 'ip6ip6' && pool.transport !== 'ip6ip6')) return;
  ip6ip6SettingsPool = name;
  document.getElementById('ip6ip6-settings-summary').textContent = `${name} · IP6IP6 (آزمایشی — بدون رمزنگاری و استتار · اختصاصی IPv6)`;
  document.getElementById('ip6ip6-settings-mtu').value = pool.ip6ip6_mtu || pool.nodes?.[0]?.ip6ip6?.mtu || 1420;
  document.getElementById('ip6ip6-settings-modal').classList.remove('hidden');
}

async function submitIp6ip6Settings(event) {
  event.preventDefault();
  const button = document.getElementById('ip6ip6-settings-submit');
  button.disabled = true;
  try {
    const result = await apiFetch('/api/pools/ip6ip6-settings', {
      method: 'POST',
      body: { pool: ip6ip6SettingsPool, mtu: document.getElementById('ip6ip6-settings-mtu').value }
    });
    if (result.success) {
      closeModal('ip6ip6-settings-modal');
      showToast('MTU اینترفیس‌های IP6IP6 اعمال و بررسی شد');
    } else {
      showToast(result.error || result.message || 'خطا در اعمال MTU');
    }
    lastRenderedPools = '';
    await fetchStatus(true);
  } catch (error) {
    showToast('نتیجهٔ تغییر MTU IP6IP6 تأیید نشد؛ وضعیت را بررسی کنید');
  } finally {
    button.disabled = false;
  }
}

let wireguardSettingsPool = '';

async function openWireguardSettingsModal(name) {
  const pool = cachedStatus?.pools.find(p => p.name === name);
  if (!pool || (pool.engine !== 'wireguard' && pool.transport !== 'wireguard')) return;
  wireguardSettingsPool = name;
  document.getElementById('wireguard-settings-summary').textContent = `${name} · WireGuard (UDP ${pool.wireguard_port || pool.tunnel_port || 51820}) · آزمایشی؛ نتیجهٔ آزمون لینک را بررسی کنید`;
  document.getElementById('wireguard-settings-mtu').value = pool.wireguard_mtu || pool.mtu || 1280;
  const statusBox = document.getElementById('wireguard-status-box');
  const probeResult = document.getElementById('wireguard-probe-result');
  if (probeResult) probeResult.style.display = 'none';
  statusBox.textContent = 'در حال دریافت وضعیت زنده و Dump اینترفیس‌ها...';
  document.getElementById('wireguard-settings-modal').classList.remove('hidden');

  try {
    const res = await apiFetch('/api/pools/wireguard-status', { method: 'POST', body: { pool: name } });
    if (res.success && res.status) {
      statusBox.textContent = JSON.stringify(res.status, null, 2);
    } else {
      statusBox.textContent = res.message || 'وضعیت زنده در دسترس نیست';
    }
  } catch (e) {
    statusBox.textContent = 'خطا در ارتباط با سرور یا سرورها پاسخگو نیستند';
  }
}

async function submitWireguardSettings(event) {
  event.preventDefault();
  const button = document.getElementById('wireguard-settings-submit');
  button.disabled = true;
  try {
    const result = await apiFetch('/api/pools/wireguard-settings', {
      method: 'POST',
      body: { pool: wireguardSettingsPool, mtu: document.getElementById('wireguard-settings-mtu').value }
    });
    if (result.success) {
      closeModal('wireguard-settings-modal');
      showToast('MTU اینترفیس‌های WireGuard اعمال و فایل پیکربندی به‌روزرسانی شد');
    } else {
      showToast(result.error || result.message || 'خطا در اعمال MTU');
    }
    lastRenderedPools = '';
    await fetchStatus(true);
  } catch (error) {
    showToast('نتیجهٔ تغییر MTU تأیید نشد؛ وضعیت را بررسی کنید');
  } finally {
    button.disabled = false;
  }
}

async function runWireguardPoolProbe() {
  const btn = document.getElementById('wireguard-probe-btn');
  const resBox = document.getElementById('wireguard-probe-result');
  if (!wireguardSettingsPool) return;
  btn.disabled = true;
  btn.querySelector('span').textContent = 'در حال اجرای آزمون پروب...';
  resBox.style.display = 'block';
  resBox.textContent = 'ارسال چالش رمزنگاری Nonce به سمت سرور خارج از طریق اینترفیس خصوصی...';
  try {
    const res = await apiFetch('/api/pools/wireguard-probe', {
      method: 'POST',
      body: { pool: wireguardSettingsPool }
    });
    if (res.passed) {
      resBox.style.color = 'var(--accent-success, #10b981)';
      resBox.textContent = `آزمون پروب موفق: پکت با Nonce از لینک عبور کرد و پاسخ دریافت شد (تأخیر: ${res.latency_ms || 1.0}ms)`;
      showToast(`آزمون پروب موفق (${res.latency_ms || 1.0}ms)`);
    } else {
      resBox.style.color = 'var(--accent-danger, #ef4444)';
      resBox.textContent = `آزمون پروب ناموفق: ${res.error || 'پکت بازنگشت'}`;
      showToast('آزمون پروب WireGuard ناموفق بود');
    }
  } catch (e) {
    resBox.style.color = 'var(--accent-danger, #ef4444)';
    resBox.textContent = 'خطا در برقراری ارتباط برای پروب';
  } finally {
    btn.disabled = false;
    btn.querySelector('span').textContent = 'اجرای آزمون فعال رفت‌وبرگشت (Active Probe)';
  }
}

async function runWireguardNodeProbe(pool, ip, button) {
  if (button) button.disabled = true;
  showToast(`در حال اجرای آزمون پروب برای نود ${ip}...`);
  try {
    const res = await apiFetch('/api/pools/wireguard-probe', {
      method: 'POST',
      body: { pool, ip }
    });
    if (res.passed) {
      showToast(`نود ${ip}: آزمون موفق، تأخیر ${res.latency_ms || 1.0}ms`);
    } else {
      showToast(`نود ${ip}: پروب ناموفق (${res.error || 'پکت بازنگشت'})`);
    }
  } catch (e) {
    showToast(`خطا در اجرای آزمون برای نود ${ip}`);
  } finally {
    if (button) button.disabled = false;
  }
}


let matrixPairs = [];
let lastPrivateLinks = '';
function openMatrixModal() {
  const iran = cachedServers?.iran || [];
  const outside = cachedServers?.kharej || [];
  matrixPairs = iran.flatMap(left => outside.filter(right => left.ip !== right.ip).map(right => ({pair:[left.ip,right.ip],left,right})));
  document.getElementById('matrix-pairs').innerHTML = matrixPairs.length ? matrixPairs.map((entry,index) => `<label class="matrix-pair"><input type="checkbox" data-matrix-pair="${index}" onchange="updateMatrixPreview()"><span>${escapeHtml(entry.left.name || entry.left.ip)} <bdi dir="ltr">${escapeHtml(entry.left.ip)}</bdi><br>به ${escapeHtml(entry.right.name || entry.right.ip)} <bdi dir="ltr">${escapeHtml(entry.right.ip)}</bdi></span></label>`).join('') : '<p class="field-hint">ابتدا حداقل یک سرور ایران و خارج به مخزن اضافه کنید.</p>';
  formError('matrix-submit','');
  updateMatrixPreview();
  document.getElementById('matrix-modal').classList.remove('hidden');
}
function selectedMatrixPairs() {
  return Array.from(document.querySelectorAll('input[data-matrix-pair]:checked')).map(input => matrixPairs[Number(input.dataset.matrixPair)]?.pair).filter(Boolean);
}
function updateMatrixPreview() {
  const count = selectedMatrixPairs().length;
  document.getElementById('matrix-preview').textContent = faNumber.format(count) + ' لینک انتخاب شده؛ ساخت خودکار زوج‌های دیگر انجام نمی‌شود.';
  document.getElementById('matrix-submit').disabled = !count || count > 50;
}
async function submitMatrix(event) {
  event.preventDefault();
  const pairs = selectedMatrixPairs();
  if (!pairs.length) {formError('matrix-submit','حداقل یک زوج انتخاب کنید');return;}
  const button = document.getElementById('matrix-submit');button.disabled=true;
  try {
    const result = await apiFetch('/api/links/matrix',{method:'POST',body:{pairs,port:document.getElementById('matrix-port').value,mtu:document.getElementById('matrix-mtu').value}});
    if (result.accepted) {closeModal('matrix-modal');showToast('ساخت لینک‌ها شروع شد؛ وضعیت هر لینک را در پنل دنبال کنید');await fetchStatus(true);}
    else formError('matrix-submit',result.error || 'عملیات شروع نشد');
  } catch(error) {formError('matrix-submit',error.message || 'شروع عملیات تأیید نشد');}
  finally {button.disabled=false;}
}
function renderPrivateLinks(data) {
  const container=document.getElementById('private-links-list');
  if (!container) return;
  const freshness=Object.values(data.private_links || {}).map(link=>{const age=Date.now()/1000-Number(link.telemetry?.checked_at);return Number.isFinite(age) && age>=0 && age<=90;});
  const signature=JSON.stringify([data.private_links || {},data.link_tasks || {},freshness]);
  if (signature===lastPrivateLinks) return;
  lastPrivateLinks=signature;
  const jobs=Object.values(data.link_tasks || {});
  const visibleJobs=jobs.filter(job=>['queued','running'].includes(job.status));
  document.getElementById('private-link-jobs').innerHTML=visibleJobs.map(job=>`<p class="field-hint">در حال اجرا · ${faNumber.format(job.completed || 0)} از ${faNumber.format(job.total || 0)} · ${escapeHtml(job.message || '')}</p>`).join('');
  const labels={planned:'طرح رزروشده',provisioning:'در حال نصب',active:'آزمون موفق',failed:'نصب کامل نشد',deleting:'در حال حذف',cleanup_failed:'پاک‌سازی نیازمند بررسی'};
  const locked=jobs.some(job=>['queued','running'].includes(job.status));
  function healthLabel(link) {
    const telemetry=link.telemetry;
    const age=telemetry ? Date.now()/1000-Number(telemetry.checked_at) : Infinity;
    if (link.status!=='active') return labels[link.status] || 'وضعیت نامشخص';
    if (!Number.isFinite(age) || age<0 || age>90) return 'آخرین آزمون نصب موفق؛ سلامت فعلی تأیید نشده';
    return ({HEALTHY:'مسیر سالم؛ آزمون تازهٔ دوطرفه',DEGRADED:'رابط فعال؛ مسیر داده تأیید نشد',DOWN:'مسیر قطع است',UNVERIFIED:'سلامت فعلی تأیید نشده'})[telemetry.status] || 'سلامت فعلی تأیید نشده';
  }
  const countBadge = document.getElementById('private-links-count-badge');
  const linksList = Object.values(data.private_links || {});
  if (countBadge) countBadge.textContent = faNumber.format(linksList.length);
  container.innerHTML = linksList.map(link => `<div class="private-link-row"><div class="private-link-details"><strong>${escapeHtml(link.link_name)}</strong><p>${escapeHtml(healthLabel(link))} · ${escapeHtml(link.engine_id)}</p><p><bdi dir="ltr">${escapeHtml(link.iran_server?.ip || '')}</bdi> به <bdi dir="ltr">${escapeHtml(link.kharej_server?.ip || '')}</bdi></p><p><bdi dir="ltr">${escapeHtml(link.private_subnet || '')}</bdi> · MTU ${escapeHtml(String(link.mtu || ''))}</p>${link.error ? `<details class="private-link-error"><summary>جزئیات خطا</summary><p>${escapeHtml(link.error)}</p></details>` : ''}</div><button type="button" class="private-link-delete" data-link="${escapeHtml(link.link_name)}" onclick="deletePrivateLink(this.dataset.link,this)" aria-label="حذف و پاک‌سازی ${escapeHtml(link.link_name)}" title="حذف و پاک‌سازی" ${locked ? 'disabled aria-disabled="true" title="یک عملیات لینک در جریان است؛ تا پایان آن حذف غیرفعال است"' : ''}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 6h18M8 6V4h8v2m3 0-1 14H6L5 6m4 4v6m6-6v6"/></svg></button></div>`).join('') || `
    <div class="empty-state-card">
      <div class="empty-state-icon-wrap">
        <svg class="ui-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <circle cx="12" cy="12" r="9"/>
          <path d="M3 12h18M12 3c5 5 5 13 0 18-5-5-5-13 0-18Z"/>
        </svg>
      </div>
      <p class="empty-state-title">لینک مستقلی ثبت نشده است</p>
      <p class="empty-state-desc">برای برقراری ارتباط مستقیم و امن بین جفت‌سرورهای ایران و خارج، از دکمه «ساخت ماتریس WireGuard» در بالای این بخش استفاده کنید.</p>
    </div>
  `;
}
async function deletePrivateLink(name,button) {
  button.disabled=true;
  try {
    const result=await apiFetch('/api/links/delete',{method:'POST',body:{link:name}});
    if (result.accepted) {showToast('پاک‌سازی لینک شروع شد');await fetchStatus(true);}
    else showToast(result.error || 'حذف شروع نشد');
  } catch(error) {showToast(error.message || 'حذف تأیید نشد');}
  finally {button.disabled=false;}
}

/* ==========================================================================
   Cloudflare Manager — token profiles, zone discovery, DNS record CRUD
   ========================================================================== */
let cfProfiles = [];
let cfSelectedProfile = null;   // profile id
let cfSelectedZone = null;      // zone id
let cfZones = [];
let cfRecords = [];
let cfRecordsReqSeq = 0;

async function cfLoadProfiles() {
  try {
    const res = await apiFetch("/api/cloudflare/profiles");
    cfProfiles = res.profiles || [];
    renderCfProfiles();
  } catch (e) {
    showToast("خطا در دریافت پروفایل‌های Cloudflare");
  }
}

function renderCfProfiles() {
  const wrap = document.getElementById("cf-profiles-list");
  const empty = document.getElementById("cf-profiles-empty");
  const badge = document.getElementById("cf-profile-count-badge");
  if (!wrap) return;
  if (badge) badge.textContent = new Intl.NumberFormat('en-US').format(cfProfiles.length);
  if (!cfProfiles.length) {
    wrap.innerHTML = "";
    empty?.classList.remove("hidden");
    document.getElementById("cf-zone-section")?.classList.add("hidden");
    document.getElementById("cf-records-section")?.classList.add("hidden");
    return;
  }
  empty?.classList.add("hidden");
  wrap.innerHTML = cfProfiles.map(p => `
    <div class="cf-profile-card ${p.id === cfSelectedProfile ? 'selected' : ''} ${p.enabled ? '' : 'disabled'}">
      <div class="cf-profile-head">
        <div class="cf-profile-name">
          <span class="cf-status-dot ${p.enabled ? 'on' : 'off'}"></span>
          <strong>${escapeHtml(p.label)}</strong>
        </div>
        <code class="cf-token-hint">${escapeHtml(p.token_hint)}</code>
      </div>
      <div class="cf-profile-meta">
        <span>${new Intl.NumberFormat('en-US').format(p.zone_count || 0)} Zone</span>
        ${p.last_validated_at ? `<span title="آخرین اعتبارسنجی">${escapeHtml(p.last_validated_at.slice(0, 10))}</span>` : ''}
        ${p.enabled ? '' : '<span class="cf-off-tag">غیرفعال</span>'}
      </div>
      <div class="cf-profile-actions">
        <button type="button" class="btn-secondary sm" onclick="cfSelectProfile('${escAttr(p.id)}')"><span>Zoneها</span></button>
        <button type="button" class="btn-secondary sm" onclick="openCfProfileEditModal('${escAttr(p.id)}')"><span>ویرایش</span></button>
        <button type="button" class="btn-secondary sm" onclick="cfToggleProfile('${escAttr(p.id)}', ${!p.enabled})"><span>${p.enabled ? 'غیرفعال' : 'فعال'}</span></button>
        <button type="button" class="btn-danger sm" onclick="cfDeleteProfile('${escAttr(p.id)}')"><span>حذف</span></button>
      </div>
    </div>`).join("");
}

async function cfSelectProfile(pid) {
  cfSelectedProfile = pid;
  cfSelectedZone = null;
  cfZones = [];
  cfRecords = [];
  renderCfProfiles();
  document.getElementById("cf-records-section")?.classList.add("hidden");
  await cfDiscoverZones(false);
}

async function cfDiscoverZones(refresh) {
  if (!cfSelectedProfile) return;
  const list = document.getElementById("cf-zones-list");
  const section = document.getElementById("cf-zone-section");
  const heading = document.getElementById("cf-zone-heading");
  const prof = cfProfiles.find(p => p.id === cfSelectedProfile);
  if (heading) heading.textContent = `Zoneهای ${prof ? prof.label : ''}`;
  section?.classList.remove("hidden");
  if (list) list.innerHTML = '<p class="field-hint">در حال کشف Zoneها…</p>';
  try {
    const res = await apiFetch(
      `/api/cloudflare/profiles/${encodeURIComponent(cfSelectedProfile)}/zones${refresh ? '?refresh=1' : ''}`);
    cfZones = res.zones || [];
    renderCfZones();
  } catch (e) {
    if (list) list.innerHTML = `<p class="field-hint">خطا در کشف Zoneها</p>`;
    showToast("کشف Zoneها ناموفق بود");
  }
}

function renderCfZones() {
  const list = document.getElementById("cf-zones-list");
  if (!list) return;
  if (!cfZones.length) {
    list.innerHTML = '<p class="field-hint">Zoneی برای این توکن یافت نشد — مجوز Zone:Read را بررسی کنید.</p>';
    return;
  }
  list.innerHTML = cfZones.map(z => `
    <button type="button" class="cf-zone-chip ${z.id === cfSelectedZone ? 'active' : ''}" onclick="cfSelectZone('${escAttr(z.id)}','${escAttr(z.name)}')">
      <span class="cf-status-dot ${z.status === 'active' ? 'on' : 'off'}"></span>
      <span class="cf-zone-name" dir="ltr">${escapeHtml(z.name)}</span>
      <span class="cf-zone-status">${escapeHtml(z.status || '')}</span>
    </button>`).join("");
}

async function cfSelectZone(zid, zname) {
  cfSelectedZone = zid;
  renderCfZones();
  const section = document.getElementById("cf-records-section");
  const heading = document.getElementById("cf-records-heading");
  if (heading) heading.innerHTML = `رکوردهای DNS — <bdi dir="ltr">${escapeHtml(zname)}</bdi>`;
  section?.classList.remove("hidden");
  await cfLoadRecords();
}

async function cfLoadRecords() {
  if (!cfSelectedProfile || !cfSelectedZone) return;
  const wrap = document.getElementById("cf-records-table-wrap");
  const seq = ++cfRecordsReqSeq;
  if (wrap) wrap.innerHTML = '<p class="field-hint">در حال دریافت رکوردها…</p>';
  try {
    const res = await apiFetch(
      `/api/cloudflare/zones/records?profile=${encodeURIComponent(cfSelectedProfile)}&zone=${encodeURIComponent(cfSelectedZone)}`);
    if (seq !== cfRecordsReqSeq) return; // stale
    cfRecords = res.records || [];
    cfRenderRecords();
  } catch (e) {
    if (wrap) wrap.innerHTML = '<p class="field-hint">خطا در دریافت رکوردها</p>';
    showToast("دریافت رکوردها ناموفق بود");
  }
}

function cfRecordContent(r) {
  if (r.type === "MX") return `${r.content} (priority ${r.priority ?? ''})`;
  if (r.type === "SRV" && r.data) {
    const d = r.data;
    return `${d.target || ''}:${d.port ?? ''} w${d.weight ?? ''} p${d.priority ?? ''}`;
  }
  if (r.type === "CAA" && r.data) return `${r.data.flags ?? ''} ${r.data.tag || ''} "${r.data.value || ''}"`;
  return r.content || '—';
}

function cfRenderRecords() {
  const wrap = document.getElementById("cf-records-table-wrap");
  if (!wrap) return;
  const q = (document.getElementById("cf-record-search")?.value || "").toLowerCase();
  const t = document.getElementById("cf-record-type-filter")?.value || "";
  const rows = cfRecords.filter(r =>
    (!t || r.type === t) &&
    (!q || (r.name || "").toLowerCase().includes(q) || (r.content || "").toLowerCase().includes(q)));
  if (!rows.length) {
    wrap.innerHTML = '<p class="field-hint">رکوردی مطابق فیلتر یافت نشد.</p>';
    return;
  }
  wrap.innerHTML = `<table class="cf-records-table">
    <thead><tr><th>نام</th><th>نوع</th><th>محتوا</th><th>TTL</th><th>پروکسی</th><th></th></tr></thead>
    <tbody>${rows.map(r => `
      <tr>
        <td class="cf-cell-name" dir="ltr">${escapeHtml(r.name)}</td>
        <td><span class="cf-type-tag">${escapeHtml(r.type)}</span></td>
        <td class="cf-cell-content" dir="ltr" title="${escAttr(cfRecordContent(r))}">${escapeHtml(cfRecordContent(r))}</td>
        <td dir="ltr">${r.ttl === 1 ? 'Auto' : new Intl.NumberFormat('en-US').format(r.ttl)}</td>
        <td>${r.proxied ? '<span class="cf-proxied on">Proxied</span>' : '<span class="cf-proxied">DNS only</span>'}</td>
        <td class="cf-cell-actions">
          <button type="button" class="cf-icon-btn" title="ویرایش" onclick='cfEditRecord(${JSON.stringify(r.id)})'>${uiIcon("edit")}</button>
          <button type="button" class="cf-icon-btn danger" title="حذف" onclick='cfDeleteRecord(${JSON.stringify(r.id)},${JSON.stringify(r.name)})'>${uiIcon("close")}</button>
        </td>
      </tr>`).join("")}</tbody>
  </table>`;
}

/* ------------------------------ profile modal ---------------------------- */
function openCfProfileModal() {
  document.getElementById("cf-profile-label").value = "";
  document.getElementById("cf-profile-token").value = "";
  document.getElementById("cf-profile-modal").classList.remove("hidden");
}

async function submitCfProfile(e) {
  e.preventDefault();
  const btn = document.getElementById("cf-profile-submit");
  btn.disabled = true;
  try {
    const res = await apiFetch("/api/cloudflare/profiles", {
      method: "POST",
      body: {
        action: "create",
        label: document.getElementById("cf-profile-label").value.trim(),
        token: document.getElementById("cf-profile-token").value.trim(),
      }
    });
    if (res.success) {
      showToast(`پروفایل ذخیره شد — ${new Intl.NumberFormat('en-US').format((res.zones || []).length)} Zone کشف شد`);
      closeModal('cf-profile-modal');
      await cfLoadProfiles();
    } else {
      formError("cf-profile-submit", res.error || "ثبت توکن ناموفق بود");
    }
  } catch (err) {
    formError("cf-profile-submit", "خطا در ارسال توکن");
  } finally {
    btn.disabled = false;
  }
}

function openCfProfileEditModal(pid) {
  const p = cfProfiles.find(x => x.id === pid);
  if (!p) return;
  document.getElementById("cf-edit-profile-id").value = pid;
  document.getElementById("cf-edit-profile-label").value = p.label;
  document.getElementById("cf-edit-profile-token").value = "";
  document.getElementById("cf-edit-profile-sub").textContent = `${p.label} · ${p.token_hint}`;
  document.getElementById("cf-profile-edit-modal").classList.remove("hidden");
}

async function submitCfProfileEdit() {
  const pid = document.getElementById("cf-edit-profile-id").value;
  const label = document.getElementById("cf-edit-profile-label").value.trim();
  const token = document.getElementById("cf-edit-profile-token").value.trim();
  const btn = document.getElementById("cf-edit-profile-save");
  btn.disabled = true;
  try {
    if (label) {
      await apiFetch(`/api/cloudflare/profiles/${encodeURIComponent(pid)}`, {
        method: "POST", body: { action: "update", label }
      });
    }
    if (token) {
      const res = await apiFetch(`/api/cloudflare/profiles/${encodeURIComponent(pid)}/rotate-token`, {
        method: "POST", body: { token }
      });
      if (!res.success) {
        formError("cf-edit-profile-save", res.error || "چرخش توکن ناموفق بود");
        return;
      }
    }
    showToast("پروفایل ذخیره شد");
    closeModal('cf-profile-edit-modal');
    await cfLoadProfiles();
  } catch (e) {
    formError("cf-edit-profile-save", "خطا در ذخیره پروفایل");
  } finally {
    btn.disabled = false;
  }
}

async function cfToggleProfile(pid, enable) {
  try {
    await apiFetch(`/api/cloudflare/profiles/${encodeURIComponent(pid)}`, {
      method: "POST", body: { action: "update", enabled: enable }
    });
    showToast(enable ? "پروفایل فعال شد" : "پروفایل غیرفعال شد");
    await cfLoadProfiles();
  } catch (e) {
    showToast("خطا در تغییر وضعیت پروفایل");
  }
}

async function cfDeleteProfile(pid) {
  const p = cfProfiles.find(x => x.id === pid);
  if (!await confirmDialog(
    `پروفایل «${p ? p.label : pid}» حذف شود؟ توکن و کش Zoneهای آن پاک می‌شود.`,
    { title: "حذف پروفایل", confirmText: "حذف" })) return;
  try {
    const res = await apiFetch(`/api/cloudflare/profiles/${encodeURIComponent(pid)}`, {
      method: "POST", body: { action: "delete" }
    });
    if (res.success) {
      if (cfSelectedProfile === pid) {
        cfSelectedProfile = null; cfSelectedZone = null;
        document.getElementById("cf-zone-section")?.classList.add("hidden");
        document.getElementById("cf-records-section")?.classList.add("hidden");
      }
      showToast("پروفایل حذف شد");
      await cfLoadProfiles();
    } else {
      showToast(res.error || "حذف ناموفق بود" + (res.pools ? ` — استفاده در: ${res.pools.join(', ')}` : ''));
    }
  } catch (e) {
    showToast("خطا در حذف پروفایل");
  }
}

/* ------------------------------- record modal ---------------------------- */
const CF_TYPE_PROXIED = new Set(["A", "AAAA", "CNAME"]);
const CF_TYPE_DATA = {
  SRV: [["service", "Service (_sip)"], ["proto", "Proto (_tcp)"], ["priority", "Priority"],
        ["weight", "Weight"], ["port", "Port"], ["target", "Target (hostname)"]],
  CAA: [["flags", "Flags"], ["tag", "Tag (issue/issuewild/iodef)"], ["value", "Value"]],
};

function cfRecordTypeChanged() {
  const t = document.getElementById("cf-record-type").value;
  document.getElementById("cf-record-proxied-group").classList.toggle("hidden", !CF_TYPE_PROXIED.has(t));
  document.getElementById("cf-record-priority-group").classList.toggle("hidden", t !== "MX");
  const dg = document.getElementById("cf-record-data-group");
  const fields = CF_TYPE_DATA[t];
  if (fields) {
    dg.classList.remove("hidden");
    document.getElementById("cf-record-data-fields").innerHTML = fields.map(([k, lbl]) =>
      `<div class="input-group"><label class="field-label">${lbl}</label>
       <input class="field-input cf-data-field" data-key="${k}" dir="ltr"></div>`).join("");
    document.getElementById("cf-record-content-group").classList.add("hidden");
  } else {
    dg.classList.add("hidden");
    document.getElementById("cf-record-content-group").classList.remove("hidden");
    const labels = { A: "IPv4 آدرس", AAAA: "IPv6 آدرس", CNAME: "دامنهٔ مقصد", TXT: "متن TXT", MX: "سرور ایمیل" };
    document.getElementById("cf-record-content-label").textContent = labels[t] || "محتوا";
  }
}

function openCfRecordModal(record) {
  document.getElementById("cf-record-id").value = record?.id || "";
  document.getElementById("cf-record-modal-title").textContent = record ? "ویرایش رکورد" : "رکورد جدید";
  document.getElementById("cf-record-modal-sub").textContent =
    `Zone: ${document.getElementById("cf-records-heading")?.textContent.replace('رکوردهای DNS — ', '') || ''}`;
  const typeSel = document.getElementById("cf-record-type");
  typeSel.value = record?.type || "A";
  typeSel.disabled = !!record;
  cfRecordTypeChanged();
  document.getElementById("cf-record-name").value = record?.name || "";
  document.getElementById("cf-record-content").value = record?.content || "";
  document.getElementById("cf-record-priority").value = record?.priority ?? 10;
  document.getElementById("cf-record-ttl").value = String(record?.ttl ?? 1);
  document.getElementById("cf-record-proxied").checked = !!record?.proxied;
  if (record?.data && CF_TYPE_DATA[record.type]) {
    document.querySelectorAll(".cf-data-field").forEach(f => {
      f.value = record.data[f.dataset.key] ?? "";
    });
  }
  document.getElementById("cf-record-modal").classList.remove("hidden");
}

function cfEditRecord(recordId) {
  const r = cfRecords.find(x => x.id === recordId);
  if (r) openCfRecordModal(r);
}

async function submitCfRecord(e) {
  e.preventDefault();
  const btn = document.getElementById("cf-record-submit");
  const recordId = document.getElementById("cf-record-id").value;
  const type = document.getElementById("cf-record-type").value;
  const record = {
    type,
    name: document.getElementById("cf-record-name").value.trim(),
    ttl: parseInt(document.getElementById("cf-record-ttl").value, 10) || 1,
  };
  if (CF_TYPE_PROXIED.has(type)) record.proxied = document.getElementById("cf-record-proxied").checked;
  if (type === "MX") record.priority = parseInt(document.getElementById("cf-record-priority").value, 10) || 10;
  if (CF_TYPE_DATA[type]) {
    record.data = {};
    document.querySelectorAll(".cf-data-field").forEach(f => {
      record.data[f.dataset.key] = f.value.trim();
    });
  } else {
    record.content = document.getElementById("cf-record-content").value.trim();
  }
  btn.disabled = true;
  try {
    const res = await apiFetch("/api/cloudflare/records", {
      method: "POST",
      body: {
        action: recordId ? "update" : "create",
        profile_id: cfSelectedProfile,
        zone_id: cfSelectedZone,
        record_id: recordId || undefined,
        record,
      }
    });
    if (res.success) {
      showToast(recordId ? "رکورد ویرایش شد" : "رکورد ساخته شد");
      closeModal('cf-record-modal');
      await cfLoadRecords();
    } else {
      formError("cf-record-submit", res.error || "ذخیره رکورد ناموفق بود");
    }
  } catch (err) {
    formError("cf-record-submit", "خطا در ذخیره رکورد");
  } finally {
    btn.disabled = false;
  }
}

async function cfDeleteRecord(recordId, name) {
  if (!await confirmDialog(
    `رکورد «${name}» برای همیشه حذف شود؟`,
    { title: "حذف رکورد DNS", confirmText: "حذف" })) return;
  try {
    const res = await apiFetch("/api/cloudflare/records", {
      method: "POST",
      body: { action: "delete", profile_id: cfSelectedProfile, zone_id: cfSelectedZone, record_id: recordId }
    });
    if (res.success) {
      showToast("رکورد حذف شد");
      await cfLoadRecords();
    } else {
      showToast(res.error || "حذف رکورد ناموفق بود");
    }
  } catch (e) {
    showToast("خطا در حذف رکورد");
  }
}

/**
 * 浏览器扩展真机验收：真实浏览器 + 真实 native host + 真实 Electron + 真实 TPM + 真实服务端。虚构数据。
 * 用法：node e2e.mjs [截图目录]
 * 环境变量：MIXIA_BROWSER 指定浏览器程序（默认 Chrome，没有就用 Edge）
 *           MIXIA_E2E_FAST 跳过要等 2 分钟的生命周期这段；MIXIA_E2E_LIFE 只跑这段
 * 跑之前要关掉正在运行的密匣：管道名按用户固定，两个实例不能同时占用。
 */
import { spawn, execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { _electron as electron, chromium } from 'playwright-core';
import { hostExe, register, unregister } from './register-host.mjs';

const root = resolve(import.meta.dirname, '..', '..');
const desktop = resolve(root, 'apps/desktop');
const shots = process.argv[2];
if (shots) mkdirSync(shots, { recursive: true });
const EXT_ID = 'ikicghdoopckcolomkneepiooaengmep';
const HOST_ORIGIN = `chrome-extension://${EXT_ID}/`;

const results = [];
const check = (name, ok, detail = '') => {
  results.push({ name, ok, detail });
  console.log(`${ok ? 'pass' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 10000, what = '') {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn().catch(() => undefined);
    if (v) return v;
    if (Date.now() > end) throw new Error(`等待超时 ${what}`);
    await sleep(100);
  }
}

const browserExe =
  process.env.MIXIA_BROWSER ??
  ['C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'].find(existsSync);

// —— 测试站点：127.0.0.1 是好站点，localhost 是另一个 origin，当作恶意站点 ——

const CLOUD = { title: 'E2E-CLOUD', user: 'cloud-user', pass: 'E2E-CLOUD-PASSWORD' };
const OTHER = { title: 'E2E-OTHER', user: 'other-user', pass: 'E2E-OTHER-PASSWORD' };
const LOCAL = { title: 'E2E-LOCAL', user: 'local-user', pass: 'E2E-LOCAL-PASSWORD' };
const COLD = { title: 'E2E-COLD', user: 'cold-user', pass: 'E2E-COLD-PASSWORD' };

const login = `<!doctype html><meta charset=utf-8><title>login</title><h1>登录</h1>
<form onsubmit="return false"><input id=u type=text style="width:300px;height:30px"><br>
<input id=p type=password style="width:300px;height:30px"><br><button>go</button></form>
<script>window.seen=[];for(const id of ['u','p'])document.getElementById(id).addEventListener('input',()=>seen.push(id));</script>`;
const framePage = (src, attrs = '') => `<!doctype html><meta charset=utf-8><title>host</title><h1>外层页面</h1>
<iframe id=f src="${src}" ${attrs} width=520 height=320></iframe>`;

let good;
let evil;
const site = http.createServer((q, r) => {
  const path = q.url.split('?')[0];
  const headers = { 'content-type': 'text/html; charset=utf-8' };
  let body = login;
  if (path === '/same') body = framePage('/login');
  else if (path === '/cross') body = framePage(`${evil}/login`);
  else if (path === '/framed') body = framePage(`${good}/login`);
  else if (path === '/nested') body = framePage(`${evil}/mid`);
  else if (path === '/mid') body = framePage(`${good}/login`);
  else if (path === '/sandbox') body = framePage('/login', 'sandbox="allow-scripts allow-forms"');
  else if (path === '/csp-sandbox') headers['content-security-policy'] = 'sandbox allow-scripts allow-forms';
  else if (path === '/hidden')
    body = `<!doctype html><meta charset=utf-8><title>hidden</title><h1>隐藏表单</h1>
      <form style="display:none"><input id=h1 type=text><input id=h2 type=password></form>
      <form style="opacity:0"><input id=h3 type=password style="width:300px;height:30px"></form>
      <input id=h4 type=password style="position:absolute;left:-9999px;width:300px;height:30px">`;
  else if (path === '/vanish')
    body = `${login}<script>window.hideField=()=>{document.getElementById('p').style.display='none'}</script>`;
  r.writeHead(200, headers);
  r.end(body);
});

// —— 启动 ——

const dataDir = mkdtempSync(join(tmpdir(), 'mixia-ext-app-'));
const srvDir = mkdtempSync(join(tmpdir(), 'mixia-ext-srv-'));
const profile = mkdtempSync(join(tmpdir(), 'mixia-ext-profile-'));
const foreignExt = mkdtempSync(join(tmpdir(), 'mixia-ext-foreign-'));
const coldFile = join(dataDir, 'cold-vault.mxcold');
const port = 18500 + Math.floor(Math.random() * 400);
let debugPort = 19500 + Math.floor(Math.random() * 400);
const token = randomBytes(16).toString('hex');
const PASS = 'extension-e2e-passphrase';
const LOCAL_PASS = 'local-vault-passphrase-1';
const server = spawn(join(root, 'server/dist/mixia-server-test.exe'), ['serve'], {
  stdio: 'ignore',
  env: {
    ...process.env,
    MIXIA_ADDR: `127.0.0.1:${port}`,
    MIXIA_DATA: srvDir,
    MIXIA_BOOTSTRAP_TOKEN_SHA256: createHash('sha256').update(token).digest('hex'),
  },
});

const tpmKeys = () => {
  try {
    const out = execFileSync('certutil', ['-user', '-csp', 'Microsoft Platform Crypto Provider', '-key'], { encoding: 'latin1' });
    return (out.match(/Mixia-(Auth|Seal)-[A-Za-z0-9_-]+/g) ?? []).sort();
  } catch {
    return [];
  }
};
const before = tpmKeys();

/** 目录里有没有出现这段文本。设备 ID 原样存在 IndexedDB 的日志里。 */
function mentions(dir, text) {
  for (const e of readdirSync(dir, { withFileTypes: true, recursive: true })) {
    if (!e.isFile()) continue;
    try {
      if (readFileSync(join(e.parentPath, e.name)).toString('latin1').includes(text)) return true;
    } catch {
      // 运行中的应用锁着 LevelDB 的 LOCK 这类文件，读不了就跳过
    }
  }
  return false;
}

/** 这次测试建的设备密钥。初始化后马上记：IndexedDB 合并后数据会被压缩，到结尾不一定还能按原文找到。 */
const ownKeys = new Set();

/**
 * 只认名字出现在这次测试数据目录里的：用户真实安装的密匣可能恰好在测试期间建了密钥，误删就只能靠恢复码。
 */
function noteKeys() {
  for (const k of tpmKeys()) {
    if (before.includes(k)) continue;
    const name = k.replace(/^Mixia-(Auth|Seal)-/, '');
    if (!ownKeys.has(name) && mentions(dataDir, name)) ownKeys.add(name);
  }
}

/** 不管测试走到哪一步，都不在 TPM 里留下测试密钥。 */
function removeLeftoverKeys() {
  noteKeys();
  if (ownKeys.size === 0) return;
  const lines = [...ownKeys].map((name, i) => `${JSON.stringify({ id: i + 1, cmd: 'delete', args: { name } })}\n`);
  execFileSync(join(desktop, 'native/hwkey/dist/mixia-hwkey.exe'), { input: lines.join('') });
}

let app;
let w;
let ctx;
let page;
let rawBrowser;

async function saveItem(it, url) {
  await w.click('.list-title button:has-text("新建")');
  await w.click('.menu button:has-text("网站登录")');
  await w.fill('#t', it.title);
  await w.fill('#u', it.user);
  await w.fill('#p', it.pass);
  await w.fill('#url', url);
  await w.click('button:has-text("保存")');
  await w.waitForSelector(`h1:has-text("${it.title}")`);
}

async function setupVaults() {
  app = await electron.launch({
    args: ['.'],
    cwd: desktop,
    env: { ...process.env, MIXIA_DATA_DIR: dataDir, MIXIA_ALLOW_CAPTURE: '1' },
  });
  w = await app.firstWindow();
  await w.click('text=第一次使用', { timeout: 20000 });
  await w.fill('#srv', `http://127.0.0.1:${port}`);
  await w.fill('#tok', token);
  await w.fill('#dn', 'E2E 扩展验收');
  await w.fill('#p1', PASS);
  await w.fill('#p2', PASS);
  await w.click('button:has-text("创建密匣")');
  await w.waitForSelector('.deed .code', { timeout: 40000 });
  await w.fill('#ck', (await w.textContent('.deed .code')).trim().replace(/ /g, '-'));
  await w.click('button:has-text("我已妥善保管")');
  await w.waitForSelector('text=全部条目');

  await saveItem(CLOUD, good);
  await saveItem(OTHER, 'https://other.example.org');

  await w.click('.nav-foot button:has-text("备份与迁移")');
  await w.click('button:has-text("新建重要本地库")');
  await w.fill('#lp', LOCAL_PASS);
  await w.click('.dialog button:has-text("创建")');
  await w.waitForSelector('.deed .code', { timeout: 30000 });
  await w.fill('#ck', (await w.textContent('.deed .code')).trim().replace(/ /g, '-'));
  await w.click('button:has-text("我已妥善保管")');
  await w.click('.nav-item.vault:has-text("重要")');
  await saveItem(LOCAL, good);

  await app.evaluate(({ dialog }, path) => {
    dialog.showSaveDialog = async () => ({ canceled: false, filePath: path });
  }, coldFile);
  await w.click('.nav-foot button:has-text("备份与迁移")');
  await w.click('button:has-text("新建冷库")');
  await w.fill('#cp', 'cold-vault-passphrase-1');
  await w.click('.dialog button:has-text("创建并保存文件")');
  await w.waitForSelector('.deed .code', { timeout: 30000 });
  await w.fill('#ck', (await w.textContent('.deed .code')).trim().replace(/ /g, '-'));
  await w.click('button:has-text("我已妥善保管")');
  await w.click('.nav-item.vault:has-text("冷库")');
  await saveItem(COLD, good);
  check('桌面端建好云库、本地库、冷库条目（都指向同一个站点）', true);
  noteKeys();
  // 认不出来的话结尾的清理就是空操作，测试密钥会留在 TPM 里
  check('认出本次测试建的设备密钥', ownKeys.size === 1, [...ownKeys].map((n) => n.slice(0, 6)).join(','));
}

function writeForeignExtension() {
  writeFileSync(
    join(foreignExt, 'manifest.json'),
    JSON.stringify({ manifest_version: 3, name: 'foreign', version: '1.0', background: { service_worker: 'sw.js' }, permissions: ['nativeMessaging'] }),
  );
  writeFileSync(join(foreignExt, 'sw.js'), "self.foreign = true;");
}

async function launchBrowser() {
  writeForeignExtension();
  const ext = resolve(import.meta.dirname, 'dist');
  ctx = await chromium.launchPersistentContext(profile, {
    executablePath: browserExe,
    headless: false,
    viewport: null,
    ignoreDefaultArgs: ['--disable-extensions', '--disable-component-extensions-with-background-pages'],
    args: [`--disable-extensions-except=${ext},${foreignExt}`, `--load-extension=${ext},${foreignExt}`, `--remote-debugging-port=${debugPort}`, '--no-first-run', '--no-default-browser-check'],
  });
  page = ctx.pages()[0] ?? (await ctx.newPage());
  await page.goto(`${good}/login`);
  const sw = await until(async () => ctx.serviceWorkers().find((s) => s.url().startsWith(HOST_ORIGIN)), 15000, '扩展 Service Worker');
  check('真实浏览器加载扩展，扩展 ID 由公钥固定', !!sw, `${ctx.browser()?.version() ?? ''} ${EXT_ID}`);
  return sw;
}

// —— 调试协议：弹窗和 iframe 不在 Playwright 的页面列表里，直接连 ——

const targets = async () => (await fetch(`http://127.0.0.1:${debugPort}/json/list`)).json();

function cdp(url) {
  const ws = new WebSocket(url);
  let seq = 0;
  const pending = new Map();
  const events = [];
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data);
    if (m.id && pending.has(m.id)) {
      pending.get(m.id)(m);
      pending.delete(m.id);
    } else if (m.method) events.push(m);
  };
  const open = new Promise((ok, no) => {
    ws.onopen = ok;
    ws.onerror = no;
  });
  let closed = false;
  ws.onclose = () => {
    closed = true;
  };
  return {
    open,
    events,
    send: (method, params = {}) =>
      new Promise((ok, no) => {
        const id = ++seq;
        // 目标关闭后 WebSocket.send 不报错，只是什么也不发
        if (closed) return no(new Error(`调试连接已断开 ${method} ${url}`));
        const timer = setTimeout(() => {
          pending.delete(id);
          no(new Error(`调试协议没有回应 ${method} ${url}`));
        }, 10000);
        pending.set(id, (m) => {
          clearTimeout(timer);
          ok(m);
        });
        ws.send(JSON.stringify({ id, method, params }));
      }),
    close: () => ws.close(),
  };
}

async function closePopups() {
  for (const t of await targets()) {
    if (t.url.startsWith(`${HOST_ORIGIN}popup.html`)) await fetch(`http://127.0.0.1:${debugPort}/json/close/${t.id}`).catch(() => undefined);
  }
  await sleep(150);
}

/** 连上弹窗，等它把内容渲染出来。 */
async function popup(wait = 8000) {
  const t = await until(async () => (await targets()).find((x) => x.url.startsWith(`${HOST_ORIGIN}popup.html`)), wait, '弹窗');
  const c = cdp(t.webSocketDebuggerUrl);
  await c.open;
  const value = async (expr) => (await c.send('Runtime.evaluate', { expression: expr, returnByValue: true })).result?.result?.value;
  await until(async () => (await value(`document.readyState==='complete' && (document.querySelectorAll('.row').length>0 || !document.getElementById('note').hidden)`)), 8000, '弹窗内容');
  return {
    rows: () => value(`[...document.querySelectorAll('.row')].map(r=>r.innerText)`),
    note: () => value(`document.getElementById('note').innerText`),
    site: () => value(`document.getElementById('site').innerText`),
    text: () => value(`document.body.innerText`),
    async click(selector) {
      const rect = await value(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});if(!e)return null;const r=e.getBoundingClientRect();return {x:r.left+r.width/2,y:r.top+r.height/2}})()`);
      if (!rect) throw new Error(`弹窗里没有 ${selector}：${await value(`document.body.innerText`)}`);
      for (const type of ['mousePressed', 'mouseReleased']) await c.send('Input.dispatchMouseEvent', { type, x: rect.x, y: rect.y, button: 'left', clickCount: 1 });
    },
    async shot(name) {
      if (!shots) return;
      const r = await c.send('Page.captureScreenshot', { format: 'png' });
      writeFileSync(join(shots, name), Buffer.from(r.result.data, 'base64'));
    },
    close: () => c.close(),
  };
}

/**
 * 弹窗要求浏览器窗口在系统前台。真实用户点的时候它肯定在，自动化时前台可能被密匣窗口或正在用电脑的人拿走，所以重试。
 * attempt 负责做一次打开动作。
 */
async function retryPopup(attempt) {
  for (let i = 0; ; i++) {
    try {
      await attempt();
      return await popup(2500);
    } catch (e) {
      if (i >= 8) throw e;
      await sleep(400);
    }
  }
}

/** 工具栏打开。 */
async function toolbar(sw) {
  return retryPopup(async () => {
    await page.bringToFront();
    await sw.evaluate(() => chrome.action.openPopup());
  });
}

/** 点图标打开弹窗。 */
const iconPopup = (frame = page) => retryPopup(() => clickIcon(frame));

const iconShown = (frame) => frame.evaluate(() => document.querySelector('[data-mixia]')?.style.display === 'block');

/** 真鼠标点登录框上的图标。 */
async function clickIcon(frame = page) {
  await page.bringToFront();
  await frame.waitForFunction(() => document.querySelector('[data-mixia]')?.style.display === 'block', null, { timeout: 8000 });
  const box = await frame.locator('#p').boundingBox();
  await page.mouse.click(box.x + box.width - 15, box.y + box.height / 2);
}

const fields = (frame = page) => frame.evaluate(() => ({ u: document.getElementById('u')?.value, p: document.getElementById('p')?.value, seen: window.seen }));
const dialogOpen = () => w.locator('.dialog').count();

/**
 * 在内容脚本的隔离环境里执行，模拟被攻破或恶意的内容脚本。
 * 同进程的 iframe 和顶层共用一个调试目标，用 selfOrigin 挑对框架。
 */
async function inContentScript(match, expression, selfOrigin) {
  for (const t of (await targets()).filter((x) => x.url.startsWith(match))) {
    const c = cdp(t.webSocketDebuggerUrl);
    await c.open;
    await c.send('Runtime.enable');
    await sleep(300);
    for (const e of c.events.filter((x) => x.method === 'Runtime.executionContextCreated' && x.params.context.name === '密匣')) {
      const contextId = e.params.context.id;
      const run = (expr) => c.send('Runtime.evaluate', { expression: expr, contextId, awaitPromise: true, returnByValue: true });
      if (selfOrigin && (await run('self.origin')).result?.result?.value !== selfOrigin) continue;
      const r = await run(expression);
      c.close();
      return r.result?.result?.value;
    }
    c.close();
  }
  throw new Error(`找不到内容脚本环境 ${match}`);
}

// —— 直接攻击 native host ——

function hostSession(args = [HOST_ORIGIN]) {
  const child = spawn(hostExe, args, { stdio: ['pipe', 'pipe', 'ignore'] });
  let buf = Buffer.alloc(0);
  const waiting = [];
  child.stdout.on('data', (d) => {
    buf = Buffer.concat([buf, d]);
    while (buf.length >= 4 && buf.length >= 4 + buf.readUInt32LE(0)) {
      const n = buf.readUInt32LE(0);
      waiting.shift()?.(JSON.parse(buf.subarray(4, 4 + n).toString('utf8')));
      buf = buf.subarray(4 + n);
    }
  });
  return {
    child,
    send(msg) {
      const body = Buffer.from(JSON.stringify(msg));
      const head = Buffer.alloc(4);
      head.writeUInt32LE(body.length);
      child.stdin.write(Buffer.concat([head, body]));
      return new Promise((ok) => waiting.push(ok));
    },
    stop: () => child.stdin.end(),
  };
}

const exitCode = (child) => new Promise((ok) => child.on('exit', ok));

async function scenarios(sw) {
  await page.waitForFunction(() => document.querySelector('[data-mixia]')?.style.display === 'block', null, { timeout: 8000 });
  check('内容脚本认出登录框并放上图标', true);
  if (shots) await page.screenshot({ path: join(shots, '01-icon.png') });

  const closedShadow = await page.evaluate(() => document.querySelector('[data-mixia]').shadowRoot);
  check('页面脚本读不到图标内部（closed shadow）', closedShadow === null);

  // 点选 → 桌面确认 → 填入
  let p = await iconPopup();
  const rows = await p.rows();
  check('弹窗列出匹配的云库账号', rows.length === 1 && rows[0].includes(CLOUD.title) && rows[0].includes(CLOUD.user), JSON.stringify(rows));
  const popupText = await p.text();
  check('弹窗只有当前站点，没有其他站点的账号', (await p.site()) === good && !popupText.includes(OTHER.title));
  check('重要本地库和冷库的条目不进弹窗', !popupText.includes(LOCAL.title) && !popupText.includes(COLD.title));
  await p.shot('02-popup.png');
  await p.click('.row');
  await w.waitForSelector('.dialog:has-text("把这个账号填到网页")', { timeout: 8000 });
  const confirmText = await w.textContent('.dialog');
  check('桌面确认框显示浏览器报告的站点和账号', confirmText.includes(good) && confirmText.includes(CLOUD.title) && confirmText.includes(CLOUD.user));
  check('确认框弹出时填入按钮不可点', await w.locator('.dialog button:has-text("填入")').isDisabled());
  check('确认前页面上没有密码', (await fields()).p === '');
  if (shots) await w.screenshot({ path: join(shots, '03-confirm.png') });
  await w.click('.dialog button:has-text("填入")');
  await until(async () => (await fields()).p === CLOUD.pass, 8000, '填入');
  const filled = await fields();
  check('桌面确认后账号密码填入网页', filled.u === CLOUD.user && filled.p === CLOUD.pass);
  check('填入时触发了 input 事件', filled.seen.includes('u') && filled.seen.includes('p'), filled.seen.join(','));
  if (shots) await page.screenshot({ path: join(shots, '04-filled.png') });
  p.close();
  await closePopups();

  // 桌面拒绝
  await page.goto(`${good}/login`);
  p = await iconPopup();
  await p.click('.row');
  await w.waitForSelector('.dialog:has-text("把这个账号填到网页")', { timeout: 8000 });
  await w.click('.dialog button:has-text("拒绝")');
  await sleep(600);
  check('桌面拒绝后没有填入', (await fields()).p === '');
  p.close();
  await closePopups();

  // 确认框等待时锁定
  await page.goto(`${good}/login`);
  p = await iconPopup();
  await p.click('.row');
  await w.waitForSelector('.dialog:has-text("把这个账号填到网页")', { timeout: 8000 });
  await w.keyboard.press('Control+l');
  await w.waitForSelector('input[name="mixia-unlock"]');
  await sleep(600);
  check('等待确认时锁定：确认框消失，没有填入', (await dialogOpen()) === 0 && (await fields()).p === '');
  p.close();
  await closePopups();

  // 已锁定
  await page.goto(`${good}/login`);
  p = await iconPopup();
  check('已锁定时弹窗提示解锁，不列账号', (await p.note()).includes('已锁定') && (await p.rows()).length === 0, await p.note());
  p.close();
  await closePopups();
  await w.fill('input[name="mixia-unlock"]', PASS);
  await w.click('button:has-text("解锁")');
  await w.waitForSelector('text=全部条目', { timeout: 20000 });

  // 重要本地库：在桌面选，逐次确认
  await page.goto(`${good}/login`);
  p = await iconPopup();
  await p.click('#desk');
  await w.waitForSelector('.dialog:has-text("选择要填到网页的账号")', { timeout: 8000 });
  check('本地库锁着时桌面候选里没有它的条目', !(await w.textContent('.dialog')).includes(LOCAL.title));
  await w.click('.dialog button:has-text("后再选")');
  await w.fill('.dialog input[type=password]', LOCAL_PASS);
  await w.click('.dialog .stack button:has-text("解锁")');
  await w.waitForSelector(`.dialog .row-item:has-text("${LOCAL.title}")`, { timeout: 20000 });
  check('可以在选择框里解锁本地库', true);
  const pickText = await w.textContent('.dialog');
  check('桌面候选有本地库和云库条目，没有冷库和其他站点', pickText.includes(LOCAL.title) && pickText.includes(CLOUD.title) && !pickText.includes(COLD.title) && !pickText.includes(OTHER.title));
  await w.click(`.dialog .row-item:has-text("${LOCAL.title}")`);
  await w.waitForSelector('.dialog:has-text("重要本地库")', { timeout: 8000 });
  check('本地库条目选中后仍要逐次确认', (await fields()).p === '');
  if (shots) await w.screenshot({ path: join(shots, '05-local-confirm.png') });
  await w.click('.dialog button:has-text("填入")');
  await until(async () => (await fields()).p === LOCAL.pass, 8000, '本地库填入');
  check('确认后填入本地库账号', (await fields()).u === LOCAL.user);
  p.close();
  await closePopups();

  // 不匹配的站点
  await page.goto(`${evil}/login`);
  p = await iconPopup();
  const evilRows = await p.rows();
  check('不匹配的站点弹窗里没有任何账号', evilRows.length === 0 && (await p.site()) === evil, await p.note());
  await p.click('#desk');
  await w.waitForSelector('.dialog:has-text("选择要填到网页的账号")', { timeout: 8000 });
  const evilPick = await w.textContent('.dialog');
  check('不匹配的站点桌面候选也是空的', !evilPick.includes('E2E-') && evilPick.includes('没有这个网站的账号'));
  await w.click('.dialog button:has-text("取消")');
  await sleep(300);
  check('不匹配的站点没有填入', (await fields()).p === '');
  p.close();
  await closePopups();

  // 同源 iframe：允许，只填这个框架
  await page.goto(`${good}/same`);
  const same = page.frames().find((f) => f.url().endsWith('/login'));
  p = await iconPopup(same);
  await p.click('.row');
  await w.waitForSelector('.dialog:has-text("把这个账号填到网页")', { timeout: 8000 });
  await w.click('.dialog button:has-text("填入")');
  await until(async () => (await fields(same)).p === CLOUD.pass, 8000, '同源 iframe 填入');
  check('同源 iframe 可以填', true);
  p.close();
  await closePopups();

  // 恶意 iframe
  const attacks = [
    ['跨源 iframe 嵌在好站点里', `${good}/cross`, `${evil}/login`],
    ['好站点的登录页被恶意站点嵌入', `${evil}/framed`, `${good}/login`],
    ['A 嵌 B 嵌 A，内层同源但中间跨源', `${good}/nested`, `${good}/login`],
  ];
  for (const [name, url, inner] of attacks) {
    await page.goto(url);
    await sleep(900);
    const f = page.frames().find((x) => x.url() === inner);
    check(`${name}：不显示图标`, !(await iconShown(f)));
    const res = await inContentScript(inner, `chrome.runtime.sendMessage({t:'arm',origin:${JSON.stringify(good)},url:${JSON.stringify(good)}})`);
    check(`${name}：内容脚本伪造 origin 发起被拒`, res?.error?.startsWith('cross_origin'), JSON.stringify(res));
    const forged = await inContentScript(inner, `chrome.runtime.sendMessage({t:'fill',ref:'a/b'})`);
    check(`${name}：内容脚本调弹窗操作被拒`, forged?.error === 'forbidden', JSON.stringify(forged));
    p = await toolbar(sw);
    check(`${name}：从工具栏打开也不给填`, (await p.note()).includes('没有可以填充的登录框') && (await p.rows()).length === 0, await p.note());
    p.close();
    await closePopups();
    check(`${name}：框架里没有密码`, (await fields(f)).p === '');
    check(`${name}：没有打扰用户`, (await dialogOpen()) === 0);
  }

  // 沙箱 iframe：URL 和顶层同源，浏览器报告不透明来源
  await page.goto(`${good}/sandbox`);
  await sleep(900);
  const sandboxed = page.frames().find((x) => x.url() === `${good}/login`);
  check('沙箱 iframe 不显示图标', !(await iconShown(sandboxed)));
  const sb = await inContentScript(good, `chrome.runtime.sendMessage({t:'arm'})`, 'null');
  check('沙箱 iframe 的内容脚本发起被拒（浏览器报告不透明来源）', sb?.error === 'cross_origin_frame', JSON.stringify(sb));
  p = await toolbar(sw);
  check('沙箱 iframe 从工具栏打开也不给填', (await p.rows()).length === 0, await p.note());
  p.close();
  await closePopups();

  // CSP sandbox 的顶层页面
  await page.goto(`${good}/csp-sandbox`);
  await sleep(900);
  check('CSP 沙箱顶层页面不显示图标', !(await iconShown(page)));
  const cspArm = await inContentScript(`${good}/csp-sandbox`, `chrome.runtime.sendMessage({t:'arm'})`, 'null');
  check('CSP 沙箱顶层页面发起被拒', cspArm?.error === 'cross_origin_frame', JSON.stringify(cspArm));

  // 隐藏表单
  await page.goto(`${good}/hidden`);
  await sleep(700);
  check('全是隐藏字段的页面不显示图标', (await page.locator('[data-mixia]').count()) === 0);
  p = await toolbar(sw);
  check('隐藏表单从工具栏打开不给填', (await p.rows()).length === 0, await p.note());
  p.close();
  await closePopups();

  // 等确认时页面跳走
  await page.goto(`${good}/login`);
  p = await iconPopup();
  await p.click('.row');
  await w.waitForSelector('.dialog:has-text("把这个账号填到网页")', { timeout: 8000 });
  await page.goto(`${evil}/login`);
  await w.click('.dialog button:has-text("填入")');
  await sleep(900);
  check('等确认时跳到别的站点：新页面拿不到密码', (await fields()).p === '');
  p.close();
  await closePopups();

  // 等确认时字段被藏起来
  await page.goto(`${good}/vanish`);
  p = await iconPopup();
  await p.click('.row');
  await w.waitForSelector('.dialog:has-text("把这个账号填到网页")', { timeout: 8000 });
  await page.evaluate(() => window.hideField());
  await w.click('.dialog button:has-text("填入")');
  await sleep(900);
  check('等确认时字段被隐藏：不写入隐藏字段', (await fields()).p === '');
  p.close();
  await closePopups();

  // 扩展的边界
  const walls = await sw.evaluate(() => ({ storage: typeof chrome.storage, tabs: chrome.runtime.getManifest().permissions, war: chrome.runtime.getManifest().web_accessible_resources }));
  check('扩展没有 storage 权限，没有可被网页访问的资源', walls.storage === 'undefined' && walls.war === undefined, JSON.stringify(walls.tabs));
  await page.goto(`${evil}/login`);
  const embed = await page.evaluate(async (u) => {
    try {
      await fetch(u);
      return 'readable';
    } catch {
      return 'blocked';
    }
  }, `${HOST_ORIGIN}popup.html`);
  check('网页读不到扩展页面', embed === 'blocked');
  const noNet = await sw.evaluate(async () => {
    try {
      await fetch('https://example.com');
      return 'allowed';
    } catch {
      return 'blocked';
    }
  });
  check('扩展自身 CSP 禁止联网', noNet === 'blocked');

  // 别的扩展不能连 host
  const foreign = await until(async () => ctx.serviceWorkers().find((s) => !s.url().startsWith(HOST_ORIGIN) && s.url().endsWith('/sw.js')), 8000, '第二个扩展');
  const denied = await foreign.evaluate(() =>
    chrome.runtime.sendNativeMessage('online.feian.mixia', { id: 1, op: 'status' }).then(
      (r) => `allowed ${JSON.stringify(r)}`,
      (e) => String(e.message),
    ),
  );
  check('allowed_origins 钉死：别的扩展连不上 host', /forbidden/i.test(denied), denied);

  // 直接对 host 动手
  const wrongArg = spawn(hostExe, ['chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/'], { stdio: 'ignore' });
  check('host 拒绝别的扩展 origin 启动', (await exitCode(wrongArg)) === 2);
  const noArg = spawn(hostExe, [], { stdio: 'ignore' });
  check('host 不带参数拒绝运行', (await exitCode(noArg)) === 2);

  const h = hostSession();
  const ref = await (async () => {
    const r = await h.send({ id: 1, op: 'list', origin: good });
    check('host 通过真实管道拿到列表，里面没有密码', r.ok && r.items.length === 1 && !JSON.stringify(r).includes(CLOUD.pass));
    return r.items[0].ref;
  })();
  const dump = await h.send({ id: 2, op: 'dump' });
  const exec = await h.send({ id: 3, op: 'exec', cmd: 'calc.exe' });
  const extra = await h.send({ id: 4, op: 'status', cmd: 'calc.exe' });
  check('管道只开放固定操作', [dump, exec, extra].every((r) => r.error === 'bad_request'), JSON.stringify(dump));
  const mismatch = await h.send({ id: 5, op: 'fill', origin: evil, ref });
  check('拿好站点的 ref 配坏站点的 origin：桌面拒绝，不弹框', mismatch.error === 'no_match' && (await dialogOpen()) === 0, JSON.stringify(mismatch));
  const localRef = await h.send({ id: 6, op: 'fill', origin: good, ref: `${ref.split('/')[0]}/nonexistent` });
  check('不存在的条目换不到密码', localRef.error === 'no_match');
  h.stop();

  // 别的程序直连管道
  const sid = execFileSync('powershell', ['-NoProfile', '-Command', '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'], { encoding: 'utf8' }).trim();
  const script = `$p=[System.IO.Pipes.NamedPipeClientStream]::new('.','mixia-fill-${sid}','InOut'); $p.Connect(3000); Start-Sleep -Milliseconds 300; try { $m=[Text.Encoding]::UTF8.GetBytes('{"id":1,"op":"status"}'); $h=[BitConverter]::GetBytes([int]$m.Length); $p.Write($h,0,4); $p.Write($m,0,$m.Length); $p.Flush(); $b=New-Object byte[] 64; $p.ReadTimeout=1500; $n=$p.Read($b,0,64); "read=$n" } catch { 'rejected' }`;
  const foreignPipe = execFileSync('powershell', ['-NoProfile', '-Command', script], { encoding: 'utf8' }).trim();
  check('别的程序直连真实管道被断开', foreignPipe === 'rejected' || foreignPipe === 'read=0', foreignPipe);
}

/**
 * Playwright 附加到 Service Worker 之后它不会休眠，上面的流程看不出 MV3 的生命周期问题。
 * 这里不用 Playwright，只连页面和弹窗，让 Service Worker 按真实规则被回收。
 */
async function lifecycle() {
  const ext = resolve(import.meta.dirname, 'dist');
  // 上一个浏览器刚退出，换个端口；Edge 的同步提示和密匣窗口都会抢焦点，弹窗失焦就关
  debugPort += 1;
  await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].minimize());
  rawBrowser = spawn(
    browserExe,
    [
      `--user-data-dir=${profile}`,
      `--disable-extensions-except=${ext}`,
      `--load-extension=${ext}`,
      `--remote-debugging-port=${debugPort}`,
      '--disable-sync',
      '--no-first-run',
      '--no-default-browser-check',
      // 解压出来的 Chrome for Testing 在这台机器上开着沙箱渲染进程起不来，Playwright 默认也关沙箱。Edge 这里开着沙箱
      ...(/chrome-for-testing/i.test(browserExe) ? ['--no-sandbox'] : []),
      `${good}/login`,
    ],
    { stdio: 'ignore' },
  );
  const t = await until(async () => (await targets()).find((x) => x.type === 'page' && x.url.startsWith(`${good}/login`)), 15000, '页面');
  const c = cdp(t.webSocketDebuggerUrl);
  await c.open;
  const value = async (expr) => (await c.send('Runtime.evaluate', { expression: expr, returnByValue: true })).result?.result?.value;
  // 启动时第一个页面可能早于扩展就绪
  await sleep(2500);
  await c.send('Page.reload');
  await sleep(1000);
  let attempt = 0;
  const clickIconRaw = async () => {
    // 后台进程启动的窗口拿不到系统前台，openPopup 就会拒绝。重试时先最小化再还原，Windows 会把它带到前台
    if (attempt++ > 0) {
      const { result } = await c.send('Browser.getWindowForTarget');
      if (result) {
        await c.send('Browser.setWindowBounds', { windowId: result.windowId, bounds: { windowState: 'minimized' } });
        await sleep(300);
        await c.send('Browser.setWindowBounds', { windowId: result.windowId, bounds: { windowState: 'normal' } });
      }
    }
    await c.send('Page.bringToFront');
    await sleep(500);
    await until(() => value(`document.querySelector('[data-mixia]')?.style.display==='block'`), 8000, '图标');
    const r = await value(`(()=>{const r=document.getElementById('p').getBoundingClientRect();return {x:r.right-15,y:r.top+r.height/2}})()`);
    await c.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: r.x, y: r.y });
    for (const type of ['mousePressed', 'mouseReleased']) await c.send('Input.dispatchMouseEvent', { type, x: r.x, y: r.y, button: 'left', clickCount: 1 });
  };
  const password = () => value(`document.getElementById('p').value`);

  const popupOpen = async () => (await targets()).some((x) => x.url.startsWith(`${HOST_ORIGIN}popup.html`));
  /** 弹窗失去焦点就关，别的窗口抢了前台时重来：没撑够时间的等待不算数。 */
  const holdPopup = async (ms) => {
    for (let tries = 0; ; tries++) {
      const opened = await retryPopup(clickIconRaw);
      const end = Date.now() + ms;
      while (Date.now() < end && (await popupOpen())) await sleep(2000);
      if (await popupOpen()) return opened;
      opened.close();
      if (tries >= 5) throw new Error('弹窗反复失去焦点');
    }
  };

  // native 端口闲置 30 秒才断，之后 Service Worker 再闲置 30 秒才回收，所以要等过 60 秒
  const p = await holdPopup(75000);
  await p.click('.row');
  const asked = await w.waitForSelector('.dialog:has-text("把这个账号填到网页")', { timeout: 8000 }).then(
    () => true,
    () => false,
  );
  check('弹窗开着超过 Service Worker 回收时间后仍能选账号', asked, asked ? '' : await p.note());
  check('确认框把最小化的密匣窗口带回来', asked && !(await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].isMinimized())));
  if (asked) {
    // 主动关掉弹窗，停掉它的保活，这段时间只靠等待中的 native 端口
    p.close();
    await closePopups();
    await sleep(50000);
    // 等待期间密匣窗口可能被浏览器完全挡住，Chromium 会暂停它的动画帧，自动化点击就等不到元素稳定。
    // 用户看到的是被带到前台的确认框，这里也先带到前台
    await w.bringToFront();
    await w.click('.dialog button:has-text("填入")', { timeout: 8000 });
    await until(async () => (await password()) === CLOUD.pass, 8000, '填入');
    check('弹窗关闭后等桌面确认超过 Service Worker 闲置时间仍能填入', true);
  }
  c.close();
  rawBrowser.kill();
  rawBrowser = undefined;
}

/** 关窗口要真的退出：残留进程会占住单实例锁，下次打不开。 */
async function quit() {
  const t0 = Date.now();
  const proc = app.process();
  const closed = new Promise((ok) => proc.once('exit', ok));
  await w.close();
  await Promise.race([closed, sleep(10000)]);
  app = undefined;
  check('关闭窗口后进程退出', proc.exitCode !== null, `${Date.now() - t0} ms`);
  await sleep(500);
  const left = execFileSync('tasklist', { encoding: 'latin1' }).split('\n').filter((l) => /^mixia-nmhost.exe/i.test(l));
  check('管道服务和 host 都已退出', left.length === 0, `${left.length}`);
}

async function main() {
  if (!browserExe) throw new Error('没有找到 Chrome 或 Edge');
  await new Promise((r) => site.listen(0, '127.0.0.1', r));
  const p = site.address().port;
  good = `http://127.0.0.1:${p}`;
  evil = `http://localhost:${p}`;
  register();
  check('注册 native messaging host', true, browserExe.split('/').pop());
  await setupVaults();
  const sw = await launchBrowser();
  if (!process.env.MIXIA_E2E_LIFE) await scenarios(sw);
  await ctx.close();
  ctx = undefined;
  // 变异测试只看防护有没有失效，跳过要等 90 秒的生命周期这一段
  if (!process.env.MIXIA_E2E_FAST) await lifecycle();
  await quit();
}

main()
  .catch((e) => {
    check('流程异常中断', false, String(e.stack ?? e).slice(0, 500));
  })
  .finally(async () => {
    await ctx?.close().catch(() => undefined);
    rawBrowser?.kill();
    await app?.close().catch(() => undefined);
    unregister();
    removeLeftoverKeys();
    server.kill();
    site.close();
    setTimeout(() => {
      for (const d of [dataDir, srvDir, profile, foreignExt]) {
        try {
          rmSync(d, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 });
        } catch {
          console.log('临时目录稍后由系统清理');
        }
      }
      const failed = results.filter((r) => !r.ok);
      console.log(`\n${results.length - failed.length}/${results.length} 通过`);
      process.exit(failed.length ? 1 : 0);
    }, 800);
  });

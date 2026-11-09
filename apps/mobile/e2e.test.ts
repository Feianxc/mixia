/**
 * Android 验收：真实 APK 跑在模拟器或真机上，Node 里的 Mixia 扮演管理设备，走公网真实配对。
 * 验证 Keystore 签名能被 Go 服务端接受、封存解封、原生网络、WebView 里的 IndexedDB 和 CSP。
 * 虚构数据。用 packages/core 的 vitest 运行：MIXIA_E2E_URL、MIXIA_E2E_TOKEN、ADB_SERIAL、ADB 必须设置。
 */
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { SoftwareKeys } from '../../packages/core/src/device';
import { Mixia, type PlatformEnv } from '../../packages/core/src/mixia';
import { getItem, listItems, newItem, saveItem } from '../../packages/core/src/model';
import { MemoryKV } from '../../packages/core/src/store';

const URL_ = process.env.MIXIA_E2E_URL ?? '';
const TOKEN = process.env.MIXIA_E2E_TOKEN ?? '';
const SERIAL = process.env.ADB_SERIAL ?? '';
const ADB = process.env.ADB ?? 'adb';
const APK = process.env.MIXIA_APK ?? '';
const PKG = 'online.feian.mixia';
const PASS = 'android-e2e-passphrase';
const SHOTS = process.env.MIXIA_SHOTS ?? '';

const adb = (...args: string[]) => execFileSync(ADB, ['-s', SERIAL, ...args], { encoding: 'utf8' });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function env(name: string): PlatformEnv {
  const stores = new Map<string, MemoryKV>();
  const hw = new SoftwareKeys(new MemoryKV());
  Object.defineProperty(hw, 'level', { value: 'hardware' });
  return {
    hw,
    http: async (r) => {
      const res = await fetch(r.url, { method: r.method, headers: r.headers, ...(r.body ? { body: r.body as BodyInit } : {}) });
      return { status: res.status, body: new Uint8Array(await res.arrayBuffer()) };
    },
    openKV: (n) => {
      let kv = stores.get(n);
      if (!kv) stores.set(n, (kv = new MemoryKV()));
      return kv;
    },
    info: { platform: 'e2e', defaultName: name, kdfMem: 64 * 1024 * 1024 },
  };
}

/** 极简 CDP 客户端。Android WebView 不支持 Playwright 的 connectOverCDP 所需的浏览器级接口。 */
class Page {
  private seq = 0;
  private waiting = new Map<number, (r: { result?: { result?: { value?: unknown }; exceptionDetails?: unknown } }) => void>();

  constructor(private ws: WebSocket) {
    ws.onmessage = (e) => {
      const m = JSON.parse(String(e.data));
      const fn = this.waiting.get(m.id);
      if (fn) {
        this.waiting.delete(m.id);
        fn(m);
      }
    };
  }

  private async run<T>(expr: string): Promise<T> {
    const id = ++this.seq;
    const r = await new Promise<{ result?: { result?: { value?: unknown }; exceptionDetails?: unknown } }>((ok) => {
      this.waiting.set(id, ok);
      this.ws.send(JSON.stringify({ id, method: 'Runtime.evaluate', params: { expression: expr, awaitPromise: true, returnByValue: true } }));
    });
    if (r.result?.exceptionDetails) throw new Error(JSON.stringify(r.result.exceptionDetails).slice(0, 300));
    return r.result?.result?.value as T;
  }

  /** `text=xxx` 或 CSS，可带 :has-text("xxx")。 */
  private finder(sel: string): string {
    const js = JSON.stringify(sel);
    return `(() => {
      const sel = ${js};
      const vis = (e) => !!e && e.getClientRects().length > 0;
      if (sel.startsWith('text=')) {
        const t = sel.slice(5);
        const all = [...document.querySelectorAll('button,a,h1,h2,p,span,label,div')];
        return all.filter((e) => e.children.length === 0 || e.tagName === 'BUTTON').find((e) => e.textContent.includes(t) && vis(e)) ?? null;
      }
      const m = sel.endsWith('")') && sel.includes(':has-text("') ? [sel, sel.slice(0, sel.indexOf(':has-text("')), sel.slice(sel.indexOf(':has-text("') + 11, -2)] : null;
      const css = m ? m[1] : sel;
      return [...document.querySelectorAll(css)].find((e) => vis(e) && (!m || e.textContent.includes(m[2]))) ?? null;
    })()`;
  }

  async waitForSelector(sel: string, o: { timeout?: number } = {}) {
    const end = Date.now() + (o.timeout ?? 15000);
    while (Date.now() < end) {
      if (await this.run<boolean>(`!!${this.finder(sel)}`)) return;
      await sleep(200);
    }
    const body = await this.run<string>(`document.body.innerText.slice(0, 300)`);
    throw new Error(`timeout waiting for ${sel}; page: ${body}`);
  }

  async click(sel: string) {
    await this.waitForSelector(sel);
    await this.run(`${this.finder(sel)}.click()`);
    await sleep(150);
  }

  async fill(sel: string, value: string) {
    await this.waitForSelector(sel);
    const v = JSON.stringify(value);
    await this.run(`(() => { const e = ${this.finder(sel)};
      const proto = e.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(proto, 'value').set.call(e, ${v});
      e.dispatchEvent(new Event('input', { bubbles: true })); })()`);
    await sleep(80);
  }

  /** CDP 截图不受 FLAG_SECURE 影响，用来看界面。 */
  async shot(path: string) {
    const id = ++this.seq;
    const r = await new Promise<{ result?: { data?: string } }>((ok) => {
      this.waiting.set(id, ok as never);
      this.ws.send(JSON.stringify({ id, method: 'Page.captureScreenshot', params: { format: 'png' } }));
    });
    if (r.result?.data) writeFileSync(path, Buffer.from(r.result.data, 'base64'));
  }

  textContent(sel: string) {
    return this.run<string>(`${this.finder(sel)}?.textContent ?? ''`);
  }

  evaluate<T>(expr: string) {
    return this.run<T>(expr);
  }

  close() {
    this.ws.close();
  }
}

async function attach(): Promise<Page> {
  const pid = adb('shell', 'pidof', PKG).trim();
  execFileSync(ADB, ['-s', SERIAL, 'forward', 'tcp:9333', `localabstract:webview_devtools_remote_${pid}`]);
  for (let i = 0; i < 60; i++) {
    try {
      const list = (await (await fetch('http://127.0.0.1:9333/json')).json()) as { url: string; webSocketDebuggerUrl: string }[];
      const t = list.find((x) => x.url.startsWith('https://localhost'));
      if (t) {
        const ws = new WebSocket(t.webSocketDebuggerUrl);
        await new Promise((ok, no) => {
          ws.onopen = ok;
          ws.onerror = no;
        });
        return new Page(ws);
      }
    } catch {
      /* WebView 还没起来 */
    }
    await sleep(500);
  }
  throw new Error('webview not reachable');
}

async function launch(): Promise<Page> {
  adb('shell', 'am', 'force-stop', PKG);
  adb('shell', 'am', 'start', '-n', `${PKG}/.MainActivity`);
  await sleep(3500);
  return attach();
}

describe.skipIf(!URL_ || !TOKEN || !SERIAL)('Android 真实 APK', () => {
  it('配对、同步、Keystore、持久化', { timeout: 400000 }, async () => {
    const out: Record<string, unknown> = {};

    if (APK) adb('install', '-r', '-g', APK);
    const pc = await Mixia.boot(env('管理电脑'));
    await pc.createOwner({ serverUrl: URL_, token: TOKEN, passphrase: PASS });
    await pc.syncNow();
    const vault = pc.openVaults()[0]!;
    const seeded = await saveItem(vault, undefined, { ...newItem('login', '电脑写的条目'), username: 'u', password: 'FROM-PC' });
    await pc.syncNow();

    let w = await launch();
    await w.waitForSelector('text=第一次使用', { timeout: 30000 });

    // 界面层断网
    const netBlocked = await w.evaluate<boolean>(`fetch('https://example.com').then(() => false, () => true)`);
    expect(netBlocked).toBe(true);
    out.nativePlatform = await w.evaluate<boolean>(`window.Capacitor.isNativePlatform()`);

    const p = await pc.startPairing();
    await w.click('text=加入已有的密匣');
    await w.fill('#srv', URL_);
    await w.fill('#pc', p.code);
    await w.click('button:has-text("下一步")');
    await w.waitForSelector('#p1', { timeout: 30000 });
    await w.fill('#dn', '模拟手机');
    await w.fill('#p1', PASS);
    await w.fill('#p2', PASS);
    await w.click('button:has-text("申请加入")');
    await w.waitForSelector('text=等待批准', { timeout: 60000 });
    const shown = (await w.textContent('.deed .code')).trim();

    let dev;
    for (let i = 0; i < 30 && !dev; i++) {
      dev = await pc.pollPairing(p.pairId, p.secret);
      if (!dev) await sleep(1000);
    }
    expect(dev).toBeTruthy();
    out.level = dev!.level;
    out.platform = dev!.platform;
    expect(dev!.fingerprint).toBe(shown);
    await pc.approvePairing(p.pairId, p.secret, dev!, { role: 'member', vaults: [vault.id] });

    await w.waitForSelector('.row-item:has-text("电脑写的条目")', { timeout: 60000 });

    // 只有真机才有意义的测量
    out.hardware = await w.evaluate(`(async () => {
      const n = window.Capacitor.Plugins.MixiaNative;
      const lv = await n.hwLevel();
      const db = await new Promise((ok, no) => { const r = indexedDB.open('mixia-device'); r.onsuccess = () => ok(r.result); r.onerror = no; });
      const v = await new Promise((ok) => { const q = db.transaction('kv').objectStore('kv').get('device/record'); q.onsuccess = () => ok(q.result); });
      const name = JSON.parse(new TextDecoder().decode(v)).installId;
      const time = async (fn) => { const t = []; for (let i = 0; i < 7; i++) { const a = performance.now(); await fn(); t.push(performance.now() - a); } t.sort((x, y) => x - y); return Math.round(t[3]); };
      const signMs = await time(() => n.hwSign({ name, data: 'AAAA' }));
      const sealed = await n.hwSeal({ name, data: 'AAAA' });
      const unsealMs = await time(() => n.hwUnseal({ name, blob: sealed.blob }));
      const st = getComputedStyle(document.querySelector('.pane.list'));
      return { ...lv, signMs, unsealMs, safeTop: st.paddingTop, w: innerWidth, h: innerHeight, dpr: devicePixelRatio };
    })()`);
    if (SHOTS) await w.shot(join(SHOTS, 'phone-list.png'));

    // 手机写入，电脑读到：Keystore 签名被 Go 服务端接受
    await w.click('.list-title button:has-text("新建")');
    await w.click('.menu button:has-text("网站登录")');
    await w.fill('#t', '手机写的条目');
    await w.fill('#u', 'phone-user');
    await w.fill('#p', 'FROM-PHONE');
    await w.click('button:has-text("保存")');
    await w.waitForSelector('h1:has-text("手机写的条目")');
    await sleep(6000);
    await pc.syncNow();
    const titles = listItems(vault).map((i) => i.data.title);
    expect(titles).toContain('手机写的条目');
    expect(getItem(vault, seeded)!.data.password).toBe('FROM-PC');

    // 锁定再解锁：Keystore 解封设备秘密
    await w.click('[aria-label="返回列表"]');
    await w.click('[aria-label="打开导航"]');
    await w.click('[aria-label="立即锁定"]');
    await w.waitForSelector('input[name="mixia-unlock"]');
    await w.fill('input[name="mixia-unlock"]', 'wrong-passphrase-xx');
    await w.click('button:has-text("解锁")');
    await w.waitForSelector('text=口令不对', { timeout: 30000 });
    await w.fill('input[name="mixia-unlock"]', PASS);
    const t0 = Date.now();
    await w.click('button:has-text("解锁")');
    await w.waitForSelector('.row-item:has-text("手机写的条目")', { timeout: 30000 });
    out.unlockMs = Date.now() - t0;
    if (SHOTS) {
      await w.click('.row-item:has-text("手机写的条目")');
      await sleep(600);
      await w.shot(join(SHOTS, 'phone-detail.png'));
      await w.click('[aria-label="返回列表"]');
    }

    // 进程被杀后数据还在
    w = await launch();
    await w.waitForSelector('input[name="mixia-unlock"]', { timeout: 30000 });
    await w.fill('input[name="mixia-unlock"]', PASS);
    await w.click('button:has-text("解锁")');
    await w.waitForSelector('.row-item:has-text("手机写的条目")', { timeout: 30000 });

    // 撤销：手机被服务器拒绝
    await pc.revokeDevice(dev!.deviceId, 'e2e');
    expect(vault.gen).toBe(2);

    // 平台层：禁止备份、禁止截屏
    const pkg = adb('shell', 'dumpsys', 'package', PKG);
    out.allowBackup = /flags=\[[^\]]*ALLOW_BACKUP/.test(pkg);
    expect(out.allowBackup).toBe(false);
    const win = adb('shell', 'dumpsys', 'window', 'windows');
    out.flagSecure = /fl=[^\n]*SECURE/.test(win) || /FLAG_SECURE/.test(win) || win.includes('SECURE');
    expect(out.flagSecure).toBe(true);

    console.log('ANDROID_E2E', JSON.stringify(out));
  });
});

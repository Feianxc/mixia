import { execFileSync } from 'node:child_process';
import { writeFileSync, rmSync } from 'node:fs';
const S = '7fdf4293';
const adb = (...a) => execFileSync('adb', ['-s', S, ...a], { encoding: 'utf8' });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const PASS = 'android-e2e-passphrase';
const PKG = 'online.feian.mixia';
const ORIG = 'com.miui.passwords/.newautofill.MiuiAutofillService';
const TMP = process.argv[2];
const results = [];
const check = (name, ok, detail = '') => {
  results.push(ok);
  console.log(`${ok ? 'pass' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`);
};

async function connect(port = 9336) {
  const pid = adb('shell', 'pidof', PKG).trim().split(/\s+/)[0];
  adb('forward', `tcp:${port}`, `localabstract:webview_devtools_remote_${pid}`);
  let t;
  for (let i = 0; i < 60 && !t; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
      t = list.filter((x) => x.url.startsWith('https://localhost')).at(-1);
    } catch {}
    if (!t) await sleep(500);
  }
  const ws = new WebSocket(t.webSocketDebuggerUrl);
  await new Promise((ok) => (ws.onopen = ok));
  let id = 0;
  const pend = new Map();
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data);
    if (pend.has(m.id)) {
      pend.get(m.id)(m);
      pend.delete(m.id);
    }
  };
  const ev = async (expression) => {
    const i = ++id;
    const r = await new Promise((ok) => {
      pend.set(i, ok);
      ws.send(JSON.stringify({ id: i, method: 'Runtime.evaluate', params: { expression, awaitPromise: true, returnByValue: true } }));
    });
    return r.result?.result?.value;
  };
  const setVal = (sel, v) =>
    ev(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e, ${JSON.stringify(v)}); e.dispatchEvent(new Event('input',{bubbles:true})); return true })()`);
  const waitText = async (txt, ms = 30000) => {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      if (await ev(`document.body.innerText.includes(${JSON.stringify(txt)})`)) return true;
      await sleep(300);
    }
    return false;
  };
  const unlock = async () => {
    await waitText('解锁');
    await setVal('input[name="mixia-unlock"]', PASS);
    await ev(`[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='解锁').click()`);
  };
  return { ev, setVal, waitText, unlock, close: () => ws.close() };
}

function dump() {
  adb('shell', 'uiautomator', 'dump', '/sdcard/ui.xml');
  const x = adb('shell', 'cat', '/sdcard/ui.xml');
  adb('shell', 'rm', '-f', '/sdcard/ui.xml');
  return x;
}
function center(xml, re) {
  for (const m of xml.matchAll(/<node [^>]*>/g)) {
    if (re.test(m[0])) {
      const b = /bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/.exec(m[0]);
      return [Math.round((+b[1] + +b[3]) / 2), Math.round((+b[2] + +b[4]) / 2)];
    }
  }
  return null;
}
const fillLog = () =>
  adb('logcat', '-d', '-s', 'FillTest:I')
    .split('\n')
    .filter((l) => l.includes('FillTest'))
    .map((l) => l.slice(l.indexOf('FillTest: ') + 10).trim());
const home = () => adb('shell', 'am', 'start', '-a', 'android.intent.action.MAIN', '-c', 'android.intent.category.HOME');
const openFill = () => adb('shell', 'am', 'start', '-n', `${PKG}.filltest/.LoginActivity`);
const openApp = () => adb('shell', 'am', 'start', '-n', `${PKG}/.MainActivity`);

/** 只取亮度，图片用完就删。 */
function brightness(name) {
  const file = `${TMP}/${name}.png`;
  const png = execFileSync('adb', ['-s', S, 'exec-out', 'screencap', '-p'], { maxBuffer: 64 * 1024 * 1024 });
  writeFileSync(file, png);
  const out = execFileSync('python', ['-c', `from PIL import Image,ImageStat;import sys;i=Image.open(sys.argv[1]).convert('L');print(round(ImageStat.Stat(i).mean[0],1))`, file], { encoding: 'utf8' });
  rmSync(file, { force: true });
  return Number(out.trim());
}

async function main() {
  // ——— 防截屏 ———
  adb('shell', 'am', 'force-stop', PKG);
  openApp();
  await sleep(3000);
  let p = await connect();
  await p.unlock();
  await p.waitText('全部条目');
  await sleep(800);
  const secure = brightness('secure');
  openFill();
  await sleep(1500);
  const normal = brightness('normal');
  check('FLAG_SECURE：系统截屏拿到黑屏，普通 App 正常', secure < 3 && normal > 30, `密匣亮度 ${secure}，普通页面亮度 ${normal}`);

  // ——— 后台超时锁定 ———
  openApp();
  await sleep(1500);
  home();
  await sleep(5000);
  openApp();
  await sleep(1500);
  const still = await p.ev(`!document.querySelector('input[name="mixia-unlock"]')`);
  check('切后台 5 秒回来不用重新解锁', still === true);
  home();
  console.log('…等 65 秒');
  await sleep(65000);
  openApp();
  await sleep(2500);
  const locked = await p.ev(`!!document.querySelector('input[name="mixia-unlock"]')`);
  check('切后台超过 60 秒回来已锁定', locked === true);
  if (locked) await p.unlock();
  await p.waitText('全部条目');

  // ——— 剪贴板：复制后切到别的 App，到时要清除 ———
  adb('logcat', '-c');
  await p.ev(`window.Capacitor.Plugins.MixiaNative.copy({ text: 'CLIP-TEST-VALUE', seconds: 8 })`);
  await sleep(500);
  openFill();
  await sleep(2000);
  const early = fillLog().filter((l) => l.startsWith('clip='));
  check('复制后别的 App 能读到（测试本身有效）', early.at(-1) === 'clip=CLIP-TEST-VALUE', early.at(-1) ?? '无记录');
  await sleep(8000);
  home();
  await sleep(800);
  adb('logcat', '-c');
  openFill();
  await sleep(2000);
  const late = fillLog().filter((l) => l.startsWith('clip='));
  check('切到别的 App 后，到时剪贴板已清除', late.at(-1) === 'clip=<empty>', late.at(-1) ?? '无记录');

  // ——— 自动填充 ———
  adb('shell', 'settings', 'put', 'secure', 'autofill_service', `${PKG}/.MixiaAutofillService`);
  p.close();
  adb('shell', 'am', 'force-stop', PKG);
  adb('shell', 'am', 'force-stop', `${PKG}.filltest`);
  adb('logcat', '-c');
  openFill();
  await sleep(2500);
  let xml = dump();
  const field = center(xml, /text="user"|hint="user"/) ?? center(xml, /EditText/);
  adb('shell', 'input', 'tap', String(field[0]), String(field[1]));
  await sleep(3000);
  xml = dump();
  const sug = center(xml, /用密匣填充/);
  check('登录框旁出现“用密匣填充”', !!sug, sug ? '' : 'pkg 列表 ' + [...new Set([...xml.matchAll(/package="([^"]+)"/g)].map((m) => m[1]))].join(','));
  if (sug) {
    adb('shell', 'input', 'tap', String(sug[0]), String(sug[1]));
    await sleep(5000);
    p = await connect(9337);
    await p.unlock();
    const picker = await p.waitText('选择要填充的账号');
    check('系统拉起认证页，解锁后出现选择框', picker);
    const warn = await p.ev(`document.querySelector('.dialog').innerText.includes('online.feian.mixia.filltest')`);
    check('普通 App 显示真实包名并警告', warn === true);
    await p.setVal('.dialog input', '电脑');
    await sleep(600);
    await p.ev(`document.querySelector('.dialog .row-item').click()`);
    await sleep(3500);
    const log = fillLog();
    check('账号密码真的填进了另一个 App', log.includes('user=u') && log.includes('pass=FROM-PC'), log.filter((l) => !l.startsWith('clip')).join(' ; '));
    p.close();
  }
}

main()
  .catch((e) => check('流程中断', false, String(e.message).slice(0, 240)))
  .finally(() => {
    adb('shell', 'settings', 'put', 'secure', 'autofill_service', ORIG);
    const now = adb('shell', 'settings', 'get', 'secure', 'autofill_service').trim();
    console.log(`自动填充服务已恢复：${now === ORIG}`);
    console.log(`${results.filter(Boolean).length}/${results.length} 通过`);
    setTimeout(() => process.exit(0), 300);
  });

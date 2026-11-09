/**
 * 星空黑洞界面验收：真实 Electron + 真实 TPM + 本地服务端。虚构数据。
 * 看的是单元测试看不到的东西：WebGL 场景真的在画、转场后场景会停、打印恢复码是否可读、
 * 动画能不能停、有没有被 CSP 拦下的资源。
 * 用法：node e2e-look.mjs [截图目录]。设 MIXIA_E2E_QUIET=1 时窗口在屏幕外、不抢焦点。
 */
import { spawn, execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { _electron as electron } from 'playwright-core';
import { keyGuard } from './e2e-tpm.mjs';

const root = resolve(import.meta.dirname, '..', '..');
const shots = process.argv[2];
if (shots) mkdirSync(shots, { recursive: true });
const results = [];
const check = (name, ok, detail = '') => {
  results.push(ok);
  console.log(`${ok ? 'pass' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`);
};
const dataDir = mkdtempSync(join(tmpdir(), 'mixia-e2e-look-'));
const srvDir = mkdtempSync(join(tmpdir(), 'mixia-e2e-look-srv-'));
const port = 18900 + Math.floor(Math.random() * 300);
const token = randomBytes(16).toString('hex');
const server = spawn(join(root, 'server/dist/mixia-server-test.exe'), ['serve'], {
  stdio: 'ignore',
  env: {
    ...process.env,
    MIXIA_ADDR: `127.0.0.1:${port}`,
    MIXIA_DATA: srvDir,
    MIXIA_BOOTSTRAP_TOKEN_SHA256: createHash('sha256').update(token).digest('hex'),
  },
});
const PASS = 'desktop-look-passphrase';
let app;
let w;
let guard;
const shot = (n) => (shots ? w.screenshot({ path: join(shots, `${n}.png`) }) : undefined);
const running = () => w.evaluate(() => document.getAnimations().filter((a) => a.playState === 'running').length);
const frames = () => w.evaluate(() => document.querySelector('.cosmos canvas')?.frames ?? -1);
const framesIn = async (ms) => {
  const a = await frames();
  await w.waitForTimeout(ms);
  return (await frames()) - a;
};

async function main() {
  // 只认本次测试建的密钥，用户真实安装的密匣在测试期间建的密钥不能碰
  guard = keyGuard(dataDir);
  await new Promise((r) => setTimeout(r, 500));
  app = await electron.launch({
    args: ['.'],
    cwd: resolve(import.meta.dirname),
    env: { ...process.env, MIXIA_DATA_DIR: dataDir, MIXIA_ALLOW_CAPTURE: '1' },
  });
  w = await app.firstWindow();
  const problems = [];
  w.on('console', (m) => {
    if (m.type() === 'error') problems.push(m.text());
  });
  w.on('pageerror', (e) => problems.push(String(e)));

  await w.waitForSelector('.cosmos canvas');
  await w.waitForTimeout(600);
  await shot('l0-intro');
  const gl = await w.evaluate(() => {
    const c = document.querySelector('.cosmos');
    return { broken: c.classList.contains('broken'), stage: [...c.classList].join(' ') };
  });
  const drawn = await framesIn(500);
  check('入口页的黑洞用 WebGL 画出来了', !gl.broken && drawn >= 15, `${gl.stage}，半秒 ${drawn} 帧`);
  // 冷启动的虫洞按任意键可以跳过，卡片马上出来
  await w.keyboard.press('Shift');
  await w.waitForTimeout(700);
  const card = await w.evaluate(() => {
    const c = document.querySelector('.gate-card');
    return c ? +getComputedStyle(c).opacity : 0;
  });
  check('按键跳过虫洞后入口卡片立刻可见', card > 0.95, `opacity ${card}`);
  await shot('l1-setup');

  await w.click('text=第一次使用');
  await w.waitForTimeout(900);
  await shot('l1b-create');
  await w.fill('#srv', `http://127.0.0.1:${port}`);
  await w.fill('#tok', token);
  await w.fill('#p1', PASS);
  await w.fill('#p2', PASS);
  await w.click('button:has-text("创建密匣")');
  await w.waitForSelector('.deed .code', { timeout: 40000 });
  await shot('l2-deed');
  const code = (await w.textContent('.deed .code')).trim();

  // 深色主题最容易在这里翻车：浅色字打到白纸上就没了
  await w.emulateMedia({ media: 'print' });
  await w.waitForTimeout(200);
  const print = await w.evaluate(() => {
    const c = document.querySelector('.deed .code');
    const cs = getComputedStyle(c);
    const hidden = [...document.querySelectorAll('.gate-card.wide .btn')].every((b) => getComputedStyle(b).display === 'none');
    const scene = getComputedStyle(document.querySelector('.cosmos')).display;
    return { color: cs.color, visibility: cs.visibility, hidden, scene };
  });
  check('打印时恢复码是黑字且可见', print.color === 'rgb(0, 0, 0)' && print.visibility === 'visible', JSON.stringify(print));
  check('打印时不带按钮和场景', print.hidden && print.scene === 'none');
  await shot('l2-print');
  await w.emulateMedia({ media: 'screen' });
  if (shots) {
    const pdf = await app.evaluate(async ({ BrowserWindow }) => {
      const b = await BrowserWindow.getAllWindows()[0].webContents.printToPDF({});
      return b.toString('base64');
    });
    writeFileSync(join(shots, 'l2-deed.pdf'), Buffer.from(pdf, 'base64'));
  }

  await w.fill('#ck', code.replace(/ /g, '-'));
  await w.click('button:has-text("我已妥善保管")');
  // 坠入视界：场景短暂盖在最上层，卡片被吸走，然后场景隐藏并停止绘制
  const samples = [];
  for (let i = 0; i < 6; i++) {
    samples.push(await w.evaluate(() => document.querySelector('.cosmos').className));
    await shot(`l2b-dive-${i}`);
  }
  const diving = samples.some((x) => x.includes('dive'));
  const overflow = await w.evaluate(() => document.documentElement.scrollWidth > innerWidth || document.documentElement.scrollHeight > innerHeight);
  check('入场动画没有把页面撑出滚动条', !overflow);
  check('解锁时有坠入视界的转场', diving);
  await w.waitForSelector('text=全部条目');
  check('认出本次测试建的设备密钥', guard.note() === 1, `测试期间别处新建 ${guard.foreign().length} 个，不会动`);
  await w.waitForTimeout(1500);
  await shot('l3-empty');
  const after = await w.evaluate(() => {
    const c = document.querySelector('.cosmos');
    return { gone: c.classList.contains('gone'), vis: getComputedStyle(c).visibility, leftover: document.querySelectorAll('.gate').length };
  });
  check('进入主界面后场景隐藏、入口页卸掉', after.gone && after.vis === 'hidden' && after.leftover === 0, JSON.stringify(after));
  check('主界面里场景不再绘制', (await framesIn(600)) === 0);

  // 三类库的印章放在一起看
  await w.click('.nav-foot button:has-text("备份与迁移")');
  await w.click('button:has-text("新建重要本地库")');
  await w.fill('#lp', 'local-vault-passphrase-1');
  await w.click('.dialog button:has-text("创建")');
  await w.waitForSelector('.deed .code', { timeout: 30000 });
  await w.emulateMedia({ media: 'print' });
  await w.waitForTimeout(150);
  const print2 = await w.evaluate(() => {
    const c = document.querySelector('.deed .code');
    const r = c.getBoundingClientRect();
    return { color: getComputedStyle(c).color, visibility: getComputedStyle(c).visibility, w: r.width };
  });
  check('弹窗里的恢复码也能打印', print2.color === 'rgb(0, 0, 0)' && print2.visibility === 'visible' && print2.w > 100, JSON.stringify(print2));
  await shot('l4-print');
  await w.emulateMedia({ media: 'screen' });
  if (shots) {
    const pdf = await app.evaluate(async ({ BrowserWindow }) => {
      const b = await BrowserWindow.getAllWindows()[0].webContents.printToPDF({});
      return b.toString('base64');
    });
    writeFileSync(join(shots, 'l4-deed-dialog.pdf'), Buffer.from(pdf, 'base64'));
  }
  const lc = (await w.textContent('.deed .code')).trim().replace(/ /g, '-');
  await w.fill('#ck', lc);
  await w.click('button:has-text("我已妥善保管")');

  await w.click('button:has-text("新建冷库")');
  await w.waitForSelector('.dialog');
  await shot('l5-cold');
  await w.click('.dialog button:has-text("取消")');
  await w.waitForTimeout(300);
  await shot('l6-backup');
  const lit = await w.evaluate(() =>
    [...document.querySelectorAll('.pane.nav .nav-item.on')]
      .filter((e) => getComputedStyle(e).backgroundImage !== 'none')
      .map((e) => e.textContent.trim()),
  );
  check('打开备份页时导航只有一个主高亮', lit.length === 1 && lit[0].includes('备份'), lit.join('、'));
  await w.click('.nav-item:has-text("全部条目")');
  await w.waitForTimeout(300);
  const welcome = await w.evaluate(() => {
    const p = document.querySelector('.welcome .mark svg path[fill^="url"]');
    return p ? getComputedStyle(p).fill : '';
  });
  check('空状态的黑洞标志拿到了渐变', /^url\(/.test(welcome), welcome.slice(0, 40));
  const stars = await w.evaluate(() => getComputedStyle(document.querySelector('.app')).backgroundImage.includes('data:image/png'));
  check('工作界面铺了静止星空', stars);

  // 工作界面保持安静：只有空状态的光晕在呼吸
  const idleMain = await running();
  check('工作界面没有多余动画', idleMain <= 1, `运行中 ${idleMain} 个`);

  // 手机宽度
  await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].setSize(430, 860));
  await w.waitForTimeout(400);
  check('窄屏没有横向溢出', await w.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await shot('l7-narrow');
  await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].setSize(1200, 780));
  await w.waitForTimeout(300);

  // 锁屏：从视界里退出来
  await w.keyboard.press('Control+l');
  await w.waitForSelector('.gate', { timeout: 8000 });
  await w.waitForTimeout(250);
  await shot('l7b-emerge');
  await w.waitForTimeout(1400);
  await shot('l8-lock');
  const scene = await framesIn(500);
  check('锁屏场景在绘制', scene >= 15, `半秒 ${scene} 帧`);
  const fps = await w.evaluate(
    () =>
      new Promise((ok) => {
        const t = [];
        const f = (n) => {
          t.push(n);
          if (t.length < 90) requestAnimationFrame(f);
          else ok(Math.round((1000 * (t.length - 1)) / (t.at(-1) - t[0])));
        };
        requestAnimationFrame(f);
      }),
  );
  check('锁屏帧率足够', fps >= 45, `${fps} fps`);

  // 窗口失去焦点后整片海停下来，回来继续
  await w.evaluate(() => window.dispatchEvent(new Event('blur')));
  await w.waitForTimeout(250);
  const paused = await framesIn(500);
  check('失去焦点时场景暂停', paused === 0 && (await running()) === 0, `半秒 ${paused} 帧，动画 ${await running()} 个`);
  // 暂停时改尺寸（手机上弹出键盘就是这样）会清空画布，必须补画一帧，不能一直黑着
  const before = await frames();
  await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].setSize(1100, 740));
  await w.waitForTimeout(400);
  const redrawn = (await frames()) - before;
  check('暂停时改窗口尺寸会补画一帧', redrawn >= 1 && redrawn <= 3, `${redrawn} 帧`);
  await shot('l8b-resized-resting');
  await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].setSize(1200, 780));
  await w.evaluate(() => window.dispatchEvent(new Event('focus')));
  await w.waitForTimeout(250);
  check('回到窗口后场景继续', (await framesIn(500)) >= 15);

  // 减少动效：全部停下，鲸鱼还在画面里
  await w.emulateMedia({ reducedMotion: 'reduce' });
  await w.waitForTimeout(300);
  check('减少动效时没有动画', (await running()) === 0);
  const stillFrames = await framesIn(600);
  check('减少动效时场景只画静止的一帧', stillFrames <= 1, `${stillFrames} 帧`);
  await shot('l9-still');
  await w.emulateMedia({ reducedMotion: null });

  await w.fill('input[name="mixia-unlock"]', PASS);
  await w.click('button:has-text("解锁")');
  await w.waitForSelector('text=全部条目', { timeout: 20000 });

  const real = problems.filter((p) => !/Autofill|favicon/.test(p));
  check('控制台没有错误，CSP 没有拦下资源', real.length === 0, real.slice(0, 3).join(' | ').slice(0, 300));

  await w.click('.nav-foot button:has-text("设置")');
  await w.click('button:has-text("擦除")');
  await w.click('.dialog button:has-text("擦除")');
  await w.waitForSelector('text=第一次使用', { timeout: 20000 });
  await app.close();
  app = undefined;
}

main()
  .catch((e) => check('流程中断', false, String(e.message).slice(0, 300)))
  .finally(async () => {
    await app?.close().catch(() => undefined);
    guard?.cleanup(join(import.meta.dirname, 'native/hwkey/dist/mixia-hwkey.exe'));
    server.kill();
    await new Promise((r) => setTimeout(r, 800));
    try {
      rmSync(dataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 });
      rmSync(srvDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 });
    } catch {
      /* 系统稍后清理 */
    }
    console.log(`${results.filter(Boolean).length}/${results.length} 通过`);
    process.exitCode = results.every(Boolean) ? 0 : 1;
  });

/**
 * 桌面端真机验收：真实 Electron + 真实 TPM + 真实服务端。虚构数据。
 * 用法：node e2e.mjs [截图目录]
 */
import { spawn, execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { _electron as electron } from 'playwright-core';
import { keyGuard } from './e2e-tpm.mjs';

const root = resolve(import.meta.dirname, '..', '..');
const shots = process.argv[2];
if (shots) mkdirSync(shots, { recursive: true });
const results = [];
const check = (name, ok, detail = '') => {
  results.push({ name, ok, detail });
  console.log(`${ok ? 'pass' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`);
};

const dataDir = mkdtempSync(join(tmpdir(), 'mixia-e2e-app-'));
const srvDir = mkdtempSync(join(tmpdir(), 'mixia-e2e-srv-'));
const port = 18000 + Math.floor(Math.random() * 500);
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
const PASS = 'desktop-e2e-passphrase';
// 只认本次测试建的密钥，用户真实安装的密匣在测试期间建的密钥不能碰
const guard = keyGuard(dataDir);

const launch = () =>
  electron.launch({
    args: ['.'],
    cwd: resolve(import.meta.dirname),
    env: { ...process.env, MIXIA_DATA_DIR: dataDir, MIXIA_ALLOW_CAPTURE: '1' },
  });

let app;

async function main() {
  await new Promise((r) => setTimeout(r, 500));
  app = await launch();
  let w = await app.firstWindow();
  await w.waitForSelector('text=第一次使用', { timeout: 20000 });
  check('安装后首屏渲染', true);
  if (shots) await w.screenshot({ path: join(shots, '01-welcome.png') });

  const savedClip = await app.evaluate(({ clipboard }) => clipboard.readText());

  // 渲染进程没有任何联网能力
  const net = await w.evaluate(async () => {
    const out = {};
    try {
      await fetch('https://example.com');
      out.fetch = 'allowed';
    } catch {
      out.fetch = 'blocked';
    }
    out.xhr = await new Promise((ok) => {
      const x = new XMLHttpRequest();
      try {
        x.open('GET', 'https://example.com');
        x.onload = () => ok('allowed');
        x.onerror = () => ok('blocked');
        x.send();
      } catch {
        ok('blocked');
      }
    });
    out.ws = await new Promise((ok) => {
      try {
        const s = new WebSocket('wss://example.com');
        s.onopen = () => ok('allowed');
        s.onerror = () => ok('blocked');
      } catch {
        ok('blocked');
      }
    });
    out.img = await new Promise((ok) => {
      const i = new Image();
      i.onload = () => ok('allowed');
      i.onerror = () => ok('blocked');
      i.src = 'https://example.com/x.png';
    });
    out.node = typeof process === 'undefined' && typeof require === 'undefined' ? 'absent' : 'present';
    return out;
  });
  check('界面层 fetch/XHR/WebSocket/图片全部被拦', Object.values(net).filter((v) => v === 'allowed').length === 0, JSON.stringify(net));
  check('渲染进程没有 Node', net.node === 'absent');

  // 外壳拒绝明文 HTTP 到非本机、拒绝未钉住的主机
  const plain = await w.evaluate(() =>
    window.mixiaDesktop.http({ method: 'GET', url: 'http://example.com/', headers: {} }).then(() => 'allowed', (e) => String(e.message)),
  );
  check('传输桥拒绝非 HTTPS', plain.includes('https_required'), plain.slice(0, 80));

  await w.click('text=第一次使用');
  await w.fill('#srv', `http://127.0.0.1:${port}`);
  await w.fill('#tok', token);
  await w.fill('#dn', 'E2E 工作站');
  await w.fill('#p1', PASS);
  await w.fill('#p2', PASS);
  await w.click('button:has-text("创建密匣")');
  await w.waitForSelector('.deed .code', { timeout: 40000 });
  const code = (await w.textContent('.deed .code')).trim().replace(/ /g, '-');
  check('真实 TPM 创建设备密钥并完成初始化', code.length === 54, `恢复码长度 ${code.length}`);
  if (shots) await w.screenshot({ path: join(shots, '02-recovery.png') });
  guard.note();
  const created = guard.oursFull();
  check('TPM 里多出本次测试的认证和封存两把密钥', created.length === 2, `${created.map((k) => k.slice(0, 11)).join(',')}；测试期间别处新建 ${guard.foreign().length} 个，不会动`);

  const confirm = w.locator('button:has-text("我已妥善保管")');
  check('没抄恢复码不能继续', await confirm.isDisabled());
  await w.fill('#ck', code);
  await confirm.click();
  await w.waitForSelector('text=全部条目');
  check('确认恢复码后进入主界面', true);

  await w.click('.list-title button:has-text("新建")');
  await w.click('.menu button:has-text("网站登录")');
  await w.fill('#t', 'E2E-TITLE-MARKER');
  await w.fill('#u', 'e2e-user');
  await w.fill('#p', 'E2E-SECRET-PASSWORD-1');
  await w.fill('#url', 'https://example.com');
  await w.click('button:has-text("保存")');
  await w.waitForSelector('h1:has-text("E2E-TITLE-MARKER")');
  check('通过界面创建条目', true);
  if (shots) await w.screenshot({ path: join(shots, '03-item.png') });

  await w.waitForTimeout(3500);
  const dbBytes = readdirSync(srvDir)
    .filter((f) => /\.db/.test(f))
    .map((f) => readFileSync(join(srvDir, f)).toString('latin1'))
    .join('');
  check('条目已同步到服务器', dbBytes.length > 1000);
  check('服务器数据库里没有任何明文', !/E2E-|e2e-user/.test(dbBytes));

  await w.click('.nav-foot button:has-text("设置")');
  await w.waitForSelector('text=硬件保护');
  check('设备等级显示硬件保护', true);
  if (shots) await w.screenshot({ path: join(shots, '04-settings.png') });

  // 剪贴板
  await w.click('.row-item:has-text("E2E-TITLE-MARKER")');
  await w.waitForSelector('[aria-label="复制密码"]');
  await w.click('[aria-label="复制密码"]');
  await w.waitForTimeout(400);
  const clip = await app.evaluate(({ clipboard }) => clipboard.readText());
  check('复制密码写入剪贴板', clip === 'E2E-SECRET-PASSWORD-1');
  // 用 Windows 原生接口读，看到的是系统实际存的格式
  const formats = execFileSync(
    'powershell',
    ['-NoProfile', '-STA', '-Command', 'Add-Type -AssemblyName System.Windows.Forms; [Windows.Forms.Clipboard]::GetDataObject().GetFormats() -join ","'],
    { encoding: 'utf8' },
  );
  check(
    '已声明排除 Windows 剪贴板历史和云同步',
    ['CanIncludeInClipboardHistory', 'CanUploadToCloudClipboard', 'ExcludeClipboardContentFromMonitorProcessing'].every((f) => formats.includes(f)),
    formats.trim().slice(0, 120),
  );
  await w.evaluate(() => window.mixiaDesktop.copy('E2E-CLEAR-ME', 5));
  await w.waitForTimeout(5800);
  const cleared = await app.evaluate(({ clipboard }) => clipboard.readText());
  check('到时自动清除剪贴板', cleared === '');

  // 锁定与解锁
  await w.keyboard.press('Control+l');
  await w.waitForSelector('input[name="mixia-unlock"]');
  const text = await w.evaluate(() => document.body.innerText);
  check('锁定后界面没有条目内容', !text.includes('E2E-TITLE-MARKER'));
  await w.fill('input[name="mixia-unlock"]', 'wrong-passphrase-here');
  await w.click('button:has-text("解锁")');
  await w.waitForSelector('text=口令不对', { timeout: 20000 });
  check('错误口令被拒', true);
  await w.fill('input[name="mixia-unlock"]', PASS);
  await w.click('button:has-text("解锁")');
  await w.waitForSelector('text=全部条目', { timeout: 20000 });
  check('真实 TPM 解封后解锁成功', true);

  // 重启应用后数据还在
  await app.close();
  app = await launch();
  w = await app.firstWindow();
  await w.waitForSelector('input[name="mixia-unlock"]', { timeout: 20000 });
  await w.fill('input[name="mixia-unlock"]', PASS);
  await w.click('button:has-text("解锁")');
  await w.waitForSelector('.row-item:has-text("E2E-TITLE-MARKER")', { timeout: 20000 });
  check('重启应用后数据持久', true);

  // 重要本地库
  await w.click('.nav-foot button:has-text("备份与迁移")');
  await w.click('button:has-text("新建重要本地库")');
  await w.fill('#lp', 'local-vault-passphrase-1');
  await w.click('.dialog button:has-text("创建")');
  await w.waitForSelector('.deed .code', { timeout: 30000 });
  const lc = (await w.textContent('.deed .code')).trim().replace(/ /g, '-');
  await w.fill('#ck', lc);
  await w.click('button:has-text("我已妥善保管")');
  check('硬件设备可以创建重要本地库', true);
  if (shots) await w.screenshot({ path: join(shots, '05-backup.png') });

  // 手机宽度下的布局
  await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].setSize(430, 860));
  await w.waitForTimeout(400);
  const noScroll = await w.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
  check('窄屏没有横向溢出', noScroll);
  if (shots) await w.screenshot({ path: join(shots, '06-narrow-detail.png') });
  await w.click('[aria-label="返回"]');
  await w.waitForTimeout(300);
  if (shots) await w.screenshot({ path: join(shots, '07-narrow-list.png') });
  await w.click('[aria-label="打开导航"]');
  await w.waitForTimeout(300);
  if (shots) await w.screenshot({ path: join(shots, '08-narrow-nav.png') });
  await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].setSize(1200, 780));
  await w.waitForTimeout(300);

  // 擦除后 TPM 密钥销毁
  await w.click('.nav-foot button:has-text("设置")');
  await w.click('button:has-text("擦除")');
  await w.click('.dialog button:has-text("擦除")');
  await w.waitForSelector('text=第一次使用', { timeout: 20000 });
  const left = guard.oursFull();
  check('擦除设备后 TPM 密钥被销毁', created.length === 2 && left.length === 0, `剩余 ${left.length}`);

  await app.evaluate(({ clipboard }, t) => clipboard.writeText(t), savedClip);
  await app.close();
  app = undefined;
}

main()
  .catch((e) => {
    check('流程异常中断', false, String(e.message).slice(0, 300));
  })
  .finally(async () => {
    await app?.close().catch(() => undefined);
    guard?.cleanup(join(import.meta.dirname, 'native/hwkey/dist/mixia-hwkey.exe'));
    server.kill();
    setTimeout(() => {
      try {
        rmSync(dataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 });
        rmSync(srvDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 });
      } catch {
        console.log('临时目录稍后由系统清理');
      }
      const failed = results.filter((r) => !r.ok);
      console.log(`\n${results.length - failed.length}/${results.length} 通过`);
      process.exitCode = failed.length ? 1 : 0;
    }, 800);
  });

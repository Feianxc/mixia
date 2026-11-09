/**
 * 密钥与 API 的界面验收：真实 Electron + 真实 TPM + 本地服务端。虚构数据。
 * 用法：node e2e-keys.mjs [截图目录]
 */
import { spawn, execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
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
const dataDir = mkdtempSync(join(tmpdir(), 'mixia-e2e-keys-'));
const srvDir = mkdtempSync(join(tmpdir(), 'mixia-e2e-keys-srv-'));
const port = 18600 + Math.floor(Math.random() * 300);
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
const PASS = 'desktop-keys-passphrase';
const SECRET = 'sk-ant-api03-EXAMPLEEXAMPLEEXAMPLE9Xq2';
let app;
let w;
let guard;
const shot = (n) => (shots ? w.screenshot({ path: join(shots, `${n}.png`) }) : undefined);

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
  const saved = await app.evaluate(({ clipboard }) => clipboard.readText());

  await w.click('text=第一次使用');
  await w.fill('#srv', `http://127.0.0.1:${port}`);
  await w.fill('#tok', token);
  await w.fill('#p1', PASS);
  await w.fill('#p2', PASS);
  await w.click('button:has-text("创建密匣")');
  await w.waitForSelector('.deed .code', { timeout: 40000 });
  await w.fill('#ck', (await w.textContent('.deed .code')).trim().replace(/ /g, '-'));
  await w.click('button:has-text("我已妥善保管")');
  await w.waitForSelector('text=全部条目');
  check('认出本次测试建的设备密钥', guard.note() === 1, `测试期间别处新建 ${guard.foreign().length} 个，不会动`);

  // 空状态
  await w.click('.nav-item:has-text("密钥与 API")');
  await w.waitForSelector('text=还没有密钥');
  check('空状态有引导', true);
  await shot('k1-empty');

  // 新建 API 密钥：粘贴后自动认出服务商
  await w.click('.list-title button:has-text("新建")');
  const menu = await w.locator('.menu button').allTextContents();
  check('密钥页的新建菜单只有密钥类型', menu.length === 5 && !menu.includes('网站登录'), menu.join('、'));
  await w.click('.menu button:has-text("API 密钥")');
  await w.waitForSelector('#prov');
  check('密钥条目不显示账号密码框', (await w.locator('#u').count()) === 0 && (await w.locator('#p').count()) === 0);
  const keyField = w.locator('.field', { has: w.locator('input[aria-label="字段名"]') }).nth(1).locator('input[type="password"]');
  await keyField.fill(SECRET);
  const provider = await w.inputValue('#prov');
  const title = await w.inputValue('#t');
  check('粘贴后自动认出服务商并填标题', provider === 'Anthropic' && title === 'Anthropic', `${provider} / ${title}`);
  await w.fill('#t', 'Claude 接口');
  const soon = new Date(Date.now() + 10 * 86400000);
  const pad = (n) => String(n).padStart(2, '0');
  await w.fill('#exp', `${soon.getFullYear()}-${pad(soon.getMonth() + 1)}-${pad(soon.getDate())}`);
  await w.selectOption('#rot', '90');
  await w.fill('#used', '订单服务，prod-server-3');
  await w.selectOption('#env', 'production');
  const warn = await w.locator('text=生产环境密钥建议放进重要本地库').count();
  check('生产密钥放云库时编辑页提示', warn === 1);
  await shot('k2-editor');
  await w.click('button:has-text("保存")');
  await w.waitForSelector('h1:has-text("Claude 接口")');

  const detail = await w.locator('.pane.main').innerText();
  check('详情显示状态、服务商、用途', /天后到期/.test(detail) && detail.includes('Anthropic') && detail.includes('prod-server-3'));
  check('详情提示生产密钥在云库', detail.includes('放在云库'));
  check('详情页没有明文机密', !detail.includes('EXAMPLE'));
  await shot('k3-detail');

  const row = await w.locator('.row-item:has-text("Claude 接口")').innerText();
  check('列表显示服务商、环境、末 4 位和状态', row.includes('Anthropic') && row.includes('生产') && row.includes('…9Xq2') && /天后到期/.test(row), row.replace(/\n/g, ' | '));
  check('列表不泄露完整密钥', !row.includes('EXAMPLE'));

  // 复制为环境变量
  await w.click('button:has-text("复制为环境变量")');
  await w.click('.menu button:has-text("PowerShell")');
  await w.waitForTimeout(500);
  const clip = await app.evaluate(({ clipboard }) => clipboard.readText());
  check('复制为 PowerShell，变量名用服务商惯例', clip === `$env:ANTHROPIC_API_KEY = '${SECRET}'`, clip.slice(0, 28));

  // 导入 .env
  await w.click('.nav-item:has-text("密钥与 API")');
  await w.waitForSelector('button:has-text("导入 .env")');
  await w.click('button:has-text("导入 .env")');
  await w.fill('[aria-label=".env 内容"]', `# 后端配置\nDB_URL=postgres://app:p4ss@db/prod\nexport GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\nnot a valid line\nDEBUG=false\n`);
  await w.fill('#envt', '订单服务 生产环境');
  const hint = await w.locator('.dialog').innerText();
  check('导入预览显示变量数和无法识别的行', hint.includes('3 个变量') && hint.includes('1 个认出了服务商') && hint.includes('1 行无法识别'));
  await shot('k4-import');
  await w.click('button:has-text("保存 3 个变量")');
  await w.waitForSelector('h1:has-text("订单服务 生产环境")');
  const envDetail = await w.locator('.pane.main').innerText();
  check('导入后变量名可见，值被遮挡', envDetail.includes('DB_URL') && !envDetail.includes('p4ss') && !envDetail.includes('ghp_'));

  // 换密钥：旧值进历史
  await w.click('.row-item:has-text("Claude 接口")');
  await w.click('button:has-text("编辑")');
  await w.locator('.field', { has: w.locator('input[aria-label="字段名"]') }).nth(1).locator('input[type="password"]').fill('sk-ant-api03-NEWNEWNEWNEWNEWNEWNEWNEW1234');
  await w.click('button:has-text("保存")');
  await w.waitForSelector('h1:has-text("Claude 接口")');
  await w.click('button:has-text("历史")');
  const hist = await w.locator('.dialog').innerText();
  check('换下来的旧 Key 留在历史里', hist.includes('API Key') && hist.includes(SECRET));
  await w.click('.dialog button:has-text("关闭")');

  // 总览
  await w.click('.nav-item:has-text("密钥与 API")');
  await w.waitForSelector('h2:has-text("快到期")');
  const over = await w.locator('.pane.main').innerText();
  check('总览分组：快到期、云库生产密钥、服务商', over.includes('快到期') && over.includes('云库里的生产密钥') && over.includes('Anthropic 1'));
  await shot('k5-overview');
  await w.click('.pane.main .chip:has-text("Anthropic")');
  await w.waitForTimeout(250);
  check('点服务商筛选列表', (await w.locator('.pane.list .row-item').count()) === 1 && (await w.inputValue('#global-search')) === 'provider:"Anthropic"');
  await w.fill('#global-search', '');
  await w.waitForTimeout(200);
  const envRow = await w.locator('.row-item:has-text("订单服务 生产环境")').innerText();
  check('变量组副标题显示变量个数', envRow.includes('3 个变量'), envRow.replace(/\n/g, ' | '));

  await w.click('.chip:has-text("需要处理")');
  await w.waitForTimeout(200);
  check('“需要处理”筛选', (await w.locator('.pane.list .row-item').count()) === 1);
  await w.click('.chip:has-text("全部")');

  // 搜索不命中机密值
  await w.fill('#global-search', 'p4ss');
  await w.waitForTimeout(200);
  check('搜索不命中机密值', (await w.locator('.pane.list .row-item').count()) === 0);
  await w.fill('#global-search', 'DB_URL');
  await w.waitForTimeout(200);
  check('能按变量名搜到', (await w.locator('.pane.list .row-item').count()) === 1);
  await w.fill('#global-search', '');

  // 安全检查
  await w.click('.nav-foot button:has-text("安全检查")');
  await w.waitForSelector('h1:has-text("安全检查")');
  const sec = await w.locator('.pane.main').innerText();
  check('安全检查包含密钥问题', sec.includes('快到期的密钥') && sec.includes('云库里的生产密钥'));

  // 明文导出：CSV 放不下密钥的值，要提前说
  await w.click('.nav-foot button:has-text("备份与迁移")');
  await w.click('button:has-text("导出明文")');
  await w.waitForSelector('.dialog');
  const jsonDlg = await w.locator('.dialog').innerText();
  await w.click('.dialog .chip:has-text("CSV")');
  const csvDlg = await w.locator('.dialog').innerText();
  check('选 CSV 时提示密钥的值不会导出，选 JSON 时不提示', csvDlg.includes('2 条密钥只会留下标题') && !jsonDlg.includes('只会留下标题'));
  await w.click('.dialog button:has-text("取消")');

  // 窄屏
  await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].setSize(430, 860));
  await w.waitForTimeout(400);
  await w.click('[aria-label="返回"]');
  await w.waitForTimeout(300);
  check('窄屏没有横向溢出', await w.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await shot('k6-narrow');
  await w.click('.chip:has-text("总览")');
  await w.waitForTimeout(300);
  check('窄屏总览没有横向溢出', await w.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await shot('k7-narrow-overview');
  await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].setSize(1200, 780));
  await w.waitForTimeout(300);

  await app.evaluate(({ clipboard }, t) => clipboard.writeText(t), saved);
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

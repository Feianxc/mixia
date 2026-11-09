/**
 * 迁移导入验收：真实 Electron + 真实 TPM + 本地服务端。虚构数据。
 * 密匣 JSON 带着库名、文件夹和条目类型导入：对话框自动选中写明的库，选错时提醒；
 * 密钥类型（API、SSH、令牌）和机密字段保留，文件夹按路径建好。
 * 用法：node e2e-import.mjs [截图目录]。设 MIXIA_E2E_QUIET=1 时窗口在屏幕外、不抢焦点。
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
const dataDir = mkdtempSync(join(tmpdir(), 'mixia-e2e-import-'));
const srvDir = mkdtempSync(join(tmpdir(), 'mixia-e2e-import-srv-'));
const fileDir = mkdtempSync(join(tmpdir(), 'mixia-e2e-import-files-'));
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
const PASS = 'desktop-import-passphrase';
const SECRET = 'sk-ant-api03-IMPORTTESTIMPORTTEST9Zk4';
let app;
let w;
let guard;
const shot = (n) => (shots ? w.screenshot({ path: join(shots, `${n}.png`) }) : undefined);

// 和迁移脚本生成的文件同一个格式
const daily = {
  format: 'mixia-plain-v1',
  items: [
    { vault: '日常', type: 'api', title: 'Claude 测试', provider: 'Anthropic', folderPath: '密钥与 API/大模型', fields: [{ name: 'Key', value: SECRET, secret: true, envName: 'ANTHROPIC_API_KEY' }] },
    { vault: '日常', type: 'token', title: 'telebot 测试', provider: 'Telegram', folderPath: '密钥与 API/机器人', fields: [{ name: 'Token', value: '123:TOKENVALUE', secret: true }] },
    { vault: '日常', type: 'login', title: 'example.com', username: 'me', password: 'pw-example', urls: ['https://example.com/login'], folderPath: '其他网站' },
  ],
};
const important = {
  format: 'mixia-plain-v1',
  items: [
    { vault: '重要', type: 'ssh', title: '测试私钥', folderPath: 'SSH 私钥', fields: [{ name: '私钥', value: '-----BEGIN RSA PRIVATE KEY-----\nTESTKEY\n-----END RSA PRIVATE KEY-----', secret: true }] },
    { vault: '重要', type: 'note', title: '测试恢复码', folderPath: '恢复凭证', fields: [{ name: '恢复码', value: 'aaaa-bbbb\ncccc-dddd', secret: true }] },
  ],
};
writeFileSync(join(fileDir, 'daily.json'), JSON.stringify(daily));
writeFileSync(join(fileDir, 'important.json'), JSON.stringify(important));

/** 替换主进程的文件选择框，直接返回指定文件 */
const pickNext = (file) =>
  app.evaluate(({ dialog }, f) => {
    dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [f] });
  }, file);

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
  w.on('pageerror', (e) => problems.push(String(e)));

  await w.click('text=第一次使用');
  await w.fill('#srv', `http://127.0.0.1:${port}`);
  await w.fill('#tok', token);
  await w.fill('#p1', PASS);
  await w.fill('#p2', PASS);
  await w.click('button:has-text("创建密匣")');
  await w.waitForSelector('.deed .code', { timeout: 40000 });
  const code = (await w.textContent('.deed .code')).trim();
  await w.fill('#ck', code.replace(/ /g, '-'));
  await w.click('button:has-text("我已妥善保管")');
  await w.waitForSelector('text=全部条目', { timeout: 20000 });
  check('认出本次测试建的设备密钥', guard.note() === 1, `测试期间别处新建 ${guard.foreign().length} 个，不会动`);

  // 重要本地库
  await w.click('.nav-foot button:has-text("备份与迁移")');
  await w.click('button:has-text("新建重要本地库")');
  await w.fill('#lp', 'local-vault-passphrase-1');
  await w.click('.dialog button:has-text("创建")');
  await w.waitForSelector('.deed .code', { timeout: 30000 });
  const lc = (await w.textContent('.deed .code')).trim().replace(/ /g, '-');
  await w.fill('#ck', lc);
  await w.click('button:has-text("我已妥善保管")');
  await w.waitForTimeout(400);

  // 导入“重要”的文件：对话框自动选中重要库
  await pickNext(join(fileDir, 'important.json'));
  await w.click('button:has-text("选择文件")');
  await w.waitForSelector('.dialog:has-text("导入预览")');
  const pre = await w.evaluate(() => ({
    text: document.querySelector('.dialog').innerText,
    on: document.querySelector('.dialog .choice.on')?.innerText ?? '',
  }));
  check('密匣 JSON 被认出来', pre.text.includes('密匣 JSON：共 2 条') && pre.text.includes('2 个文件夹'), pre.text.split('\n')[1]);
  check('自动选中文件写明的“重要”库', pre.on.includes('重要') && pre.text.includes('已选好'), pre.on.replace(/\n/g, ' '));
  await shot('i1-preview');
  // 故意点到云库：要出提醒
  await w.click('.dialog .choice:has-text("日常")');
  const warn = await w.locator('.dialog .error').innerText().catch(() => '');
  check('选到别的库时提醒确认', warn.includes('请确认'), warn);
  await w.click('.dialog .choice:has-text("重要")');
  await w.click('.dialog button:has-text("导入 2 条")');
  await w.waitForSelector('.toast:has-text("已导入 2 条")', { timeout: 10000 });

  // 导入“日常”的文件
  await pickNext(join(fileDir, 'daily.json'));
  await w.click('button:has-text("选择文件")');
  await w.waitForSelector('.dialog:has-text("导入预览")');
  const pre2 = await w.locator('.dialog .choice.on').innerText();
  check('日常文件自动选中日常库', pre2.includes('日常'));
  await w.click('.dialog button:has-text("导入 3 条")');
  await w.waitForSelector('.toast:has-text("已导入 3 条")', { timeout: 10000 });

  // 再导一次同一个文件：全部识别为重复
  await pickNext(join(fileDir, 'daily.json'));
  await w.click('button:has-text("选择文件")');
  await w.waitForSelector('.dialog:has-text("导入预览")');
  const again = await w.locator('.dialog').innerText();
  check('重复导入全部跳过', again.includes('3 条重复'), again.split('\n')[1]);
  await w.click('.dialog button:has-text("取消")');

  // 文件夹和类型
  // 左栏只显示当前所选库的文件夹
  await w.click('.nav-item.vault:has-text("日常")');
  await w.waitForTimeout(300);
  const navDaily = await w.locator('.pane.nav').innerText();
  await w.click('.nav-item.vault:has-text("重要")');
  await w.waitForTimeout(300);
  const navImp = await w.locator('.pane.nav').innerText();
  check(
    '文件夹按路径建好',
    ['密钥与 API', '其他网站'].every((f) => navDaily.includes(f)) && ['SSH 私钥', '恢复凭证'].every((f) => navImp.includes(f)),
    `${navDaily.replace(/\n/g, ' ').slice(0, 120)} / ${navImp.replace(/\n/g, ' ').slice(0, 120)}`,
  );
  await shot('i1b-folders');
  await w.click('.nav-item:has-text("密钥与 API")');
  await w.waitForTimeout(400);
  const keys = await w.locator('.pane.list').innerText();
  check('API 密钥和令牌进了“密钥与 API”', keys.includes('Claude 测试') && keys.includes('telebot 测试') && !keys.includes('example.com'));
  check('列表不泄露完整密钥', !keys.includes('IMPORTTEST'));
  await w.click('.row-item:has-text("Claude 测试")');
  await w.waitForSelector('h1:has-text("Claude 测试")');
  const detail = await w.locator('.pane.main').innerText();
  check('服务商保留，机密字段被遮挡', detail.includes('Anthropic') && !detail.includes('IMPORTTEST'));
  await shot('i2-key');
  await w.click('.row-item:has-text("Claude 测试")');
  await w.click('button:has-text("复制为环境变量")');
  await w.click('.menu button:has-text("PowerShell")');
  await w.waitForTimeout(400);
  const clip = await app.evaluate(({ clipboard }) => clipboard.readText());
  check('环境变量名一起导入', clip === `$env:ANTHROPIC_API_KEY = '${SECRET}'`, clip.slice(0, 26));

  await w.click('.nav-item:has-text("全部条目")');
  await w.waitForTimeout(300);
  const all = await w.locator('.pane.list').innerText();
  check('私钥和恢复码在重要库里', all.includes('测试私钥') && all.includes('测试恢复码'));
  await w.click('.row-item:has-text("测试私钥")');
  await w.waitForSelector('h1:has-text("测试私钥")');
  const ssh = await w.locator('.pane.main').innerText();
  check('私钥按 SSH 密钥类型导入、内容被遮挡', ssh.includes('SSH') && !ssh.includes('TESTKEY'), ssh.split('\n').slice(0, 3).join(' | '));

  check('页面没有报错', problems.length === 0, problems.slice(0, 2).join(' | '));

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
    for (const d of [dataDir, srvDir, fileDir]) {
      try {
        rmSync(d, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 });
      } catch {
        /* 系统稍后清理 */
      }
    }
    console.log(`${results.filter(Boolean).length}/${results.length} 通过`);
    process.exitCode = results.every(Boolean) ? 0 : 1;
  });

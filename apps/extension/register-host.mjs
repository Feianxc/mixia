/**
 * 开发和验收用：把本地构建的 host 注册到当前用户。正式包由安装程序写 HKLM（apps/desktop/build/installer.nsh）。
 * 用法：node register-host.mjs [--remove]
 */
import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const NAME = 'online.feian.mixia';
const dir = resolve(import.meta.dirname, '../desktop/native/nmhost');
export const hostExe = resolve(dir, 'dist/mixia-nmhost.exe');
const manifest = resolve(dir, 'dist', `${NAME}.json`);

// Chrome、Edge，以及 Chromium 和 Chrome for Testing 各读各的键
const KEYS = ['Google\\Chrome', 'Microsoft\\Edge', 'Chromium', 'Google\\Chrome for Testing'].map(
  (p) => `HKCU\\Software\\${p}\\NativeMessagingHosts\\${NAME}`,
);

export function register() {
  if (!existsSync(hostExe)) throw new Error('先构建 apps/desktop/native/nmhost/dist/mixia-nmhost.exe');
  // 清单里是相对路径，放在程序旁边
  copyFileSync(resolve(dir, `${NAME}.json`), manifest);
  for (const k of KEYS) execFileSync('reg', ['add', k, '/ve', '/t', 'REG_SZ', '/d', manifest, '/f'], { stdio: 'ignore' });
}

export function unregister() {
  for (const k of KEYS) {
    try {
      execFileSync('reg', ['delete', k, '/f'], { stdio: 'ignore' });
    } catch {
      /* 本来就没有 */
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.includes('--remove')) unregister();
  else register();
  console.log('ok');
}

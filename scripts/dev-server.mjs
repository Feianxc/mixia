// 本地开发用服务端：固定令牌 dev-token，数据放在 .dev-data，随时可删。不用于任何真实数据。
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
const root = resolve(import.meta.dirname, '..');
mkdirSync(resolve(root, '.dev-data'), { recursive: true });
const p = spawn(resolve(root, 'server/dist/mixia-server-test.exe'), ['serve'], {
  stdio: 'inherit',
  env: {
    ...process.env,
    MIXIA_ADDR: '127.0.0.1:8096',
    MIXIA_DATA: resolve(root, '.dev-data'),
    MIXIA_BOOTSTRAP_TOKEN_SHA256: createHash('sha256').update('dev-token').digest('hex'),
    MIXIA_RATE_RPS: '1000',
    MIXIA_RATE_BURST: '1000',
  },
});
process.on('SIGTERM', () => p.kill());

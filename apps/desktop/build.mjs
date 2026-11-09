import { build } from 'esbuild';
import { cpSync, rmSync } from 'node:fs';

// 界面打进 asar：完整性校验覆盖到解密逻辑，而不只是主进程
rmSync('ui', { recursive: true, force: true });
cpSync('../../packages/ui/dist', 'ui', { recursive: true });

const common = { bundle: true, platform: 'node', format: 'cjs', target: 'node22', external: ['electron'], logLevel: 'info' };
await build({ ...common, entryPoints: ['src/main.ts'], outfile: 'dist/main.cjs' });
await build({ ...common, entryPoints: ['src/preload.ts'], outfile: 'dist/preload.cjs' });

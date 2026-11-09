import { build } from 'esbuild';
import { cpSync, mkdirSync, rmSync } from 'node:fs';

// dist/ 就是“加载已解压的扩展程序”要选的目录
rmSync('dist', { recursive: true, force: true });
mkdirSync('dist');
await build({
  bundle: true,
  format: 'iife',
  target: 'chrome127',
  legalComments: 'none',
  logLevel: 'info',
  outdir: 'dist',
  entryPoints: ['src/background.ts', 'src/content.ts', 'src/popup.ts'],
});
cpSync('public', 'dist', { recursive: true });
cpSync('manifest.json', 'dist/manifest.json');

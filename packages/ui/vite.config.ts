import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * 正式构建写入严格 CSP：界面层没有任何联网能力（connect-src 'none'）。
 * 网络只能经平台外壳的传输桥，这是“本地库没有上云路径”的第三道闸。
 */
const CSP = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self'",
  "img-src 'self' data: blob:",
  "media-src 'self' blob: mediastream:",
  "connect-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
].join('; ');

function csp(): Plugin {
  return {
    name: 'mixia-csp',
    transformIndexHtml(html, ctx) {
      const tag = ctx.server ? '' : `<meta http-equiv="Content-Security-Policy" content="${CSP}" />`;
      return html.replace('<!--MIXIA_CSP-->', tag);
    },
  };
}

export default defineConfig({
  base: './',
  plugins: [react(), csp()],
  build: { target: 'es2022', outDir: 'dist', assetsInlineLimit: 0, chunkSizeWarningLimit: 3000 },
  server: {
    port: 5173,
    strictPort: true,
    // 开发预览用：把 /mx 代理到本地服务端，避免跨域。正式包不走这里。
    proxy: { '/mx': { target: 'http://127.0.0.1:8096', rewrite: (p) => p.replace(/^\/mx/, '') } },
  },
});

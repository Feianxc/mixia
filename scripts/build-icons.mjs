// 从黑洞标志（packages/ui/src/cosmos/mark.svg）生成桌面、Android 和浏览器扩展的图标，以及 Android 启动图。
// 用本机 Edge 无头渲染 SVG，不需要额外依赖。
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const { chromium } = createRequire(resolve(root, 'apps/desktop/package.json'))('playwright-core');
const mark = readFileSync(resolve(root, 'packages/ui/src/cosmos/mark.svg'), 'utf8');
// 标志的内容：去掉外层 <svg>，嵌进别的画布里
const inner = mark.replace(/^[\s\S]*?<svg[^>]*>/, '').replace(/<\/svg>\s*$/, '');

/** 固定种子的几颗星，图标和启动图上用 */
const stars = (w, h, n, seed) => {
  let s = seed;
  const r = () => (s = (s * 16807) % 2147483647) / 2147483647;
  let out = '';
  for (let i = 0; i < n; i++) {
    const big = r() ** 8;
    out += `<circle cx="${(r() * w).toFixed(1)}" cy="${(r() * h).toFixed(1)}" r="${((0.35 + big * 1.2) * Math.min(w, h) / 512).toFixed(2)}" fill="${r() > 0.6 ? '#ffe2c0' : '#dcdcff'}" opacity="${(0.3 + r() * 0.55).toFixed(2)}"/>`;
  }
  return out;
};
const SPACE = '<radialGradient id="sp" cx="50%" cy="46%" r="70%"><stop offset="0" stop-color="#1b1433"/><stop offset=".55" stop-color="#07070f"/><stop offset="1" stop-color="#030308"/></radialGradient>';

/** 把标志放进 120 见方的画布：k 是放大倍数，标志中心对准画布中心 */
const placed = (k) => `<g transform="translate(60 61) scale(${k}) translate(-60 -58)">${inner}</g>`;

/** 图标：深空底板 + 放大的黑洞。radius 为 0 时是方的，60 是圆的 */
const tile = (radius, k = 1.18) =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120"><defs>${SPACE}<clipPath id="c"><rect width="120" height="120" rx="${radius}"/></clipPath></defs>` +
  `<g clip-path="url(#c)"><rect width="120" height="120" fill="url(#sp)"/>${stars(120, 120, 26, 5)}${placed(k)}</g></svg>`;

/** 不带底板的标志：浏览器工具栏和 Android 自适应图标的前景 */
const bare = (k) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120">${placed(k)}</svg>`;

/** 启动图：一片深空，中间一个黑洞 */
const splash = (w, h) => {
  const side = Math.min(w, h) * 0.42;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}"><defs>${SPACE}</defs>` +
    `<rect width="${w}" height="${h}" fill="url(#sp)"/>${stars(w, h, Math.round((w * h) / 9000), 11)}` +
    `<g transform="translate(${(w - side) / 2} ${(h - side) / 2}) scale(${side / 120})">${inner}</g></svg>`;
};

const browser = await chromium.launch({ channel: 'msedge', headless: true });
const page = await browser.newPage();
const png = async (svg, w, h = w) => {
  await page.setViewportSize({ width: w, height: h });
  const sized = svg.replace('<svg ', `<svg width="${w}" height="${h}" style="display:block" `);
  await page.setContent(`<!doctype html><body style="margin:0;background:transparent">${sized}</body>`);
  return page.screenshot({ type: 'png', omitBackground: true });
};

mkdirSync(resolve(root, 'apps/desktop/build'), { recursive: true });
writeFileSync(resolve(root, 'apps/desktop/build/icon.png'), await png(tile(26), 512));

// 工具栏上的小图标不带底板，黑洞本身就够认；扩展管理页的大图标带底板
for (const s of [16, 32]) writeFileSync(resolve(root, `apps/extension/public/icon-${s}.png`), await png(bare(1.28), s));
for (const s of [48, 128]) writeFileSync(resolve(root, `apps/extension/public/icon-${s}.png`), await png(tile(26), s));

const res = resolve(root, 'apps/mobile/android/app/src/main/res');
for (const [d, s] of Object.entries({ mdpi: 48, hdpi: 72, xhdpi: 96, xxhdpi: 144, xxxhdpi: 192 })) {
  const dir = resolve(res, `mipmap-${d}`);
  writeFileSync(resolve(dir, 'ic_launcher.png'), await png(tile(26), s));
  writeFileSync(resolve(dir, 'ic_launcher_round.png'), await png(tile(60), s));
  // 自适应图标的前景：系统会裁掉外圈三分之一，黑洞要落在中间的安全区里
  writeFileSync(resolve(dir, 'ic_launcher_foreground.png'), await png(bare(0.78), Math.round(s * 2.25)));
}

for (const d of readdirSync(res).filter((n) => n.startsWith('drawable'))) {
  const f = resolve(res, d, 'splash.png');
  let head;
  try {
    head = readFileSync(f);
  } catch {
    continue;
  }
  // 沿用原图尺寸：PNG 的宽高在 IHDR 里
  const [w, h] = [head.readUInt32BE(16), head.readUInt32BE(20)];
  writeFileSync(f, await png(splash(w, h), w, h));
}

await browser.close();
console.log('icons ok');

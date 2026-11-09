/**
 * 浏览器填充的站点判断和请求校验。纯函数，不依赖加密库：Electron 主进程也引用这个文件。
 * 网页地址一律由浏览器报告，这里只回答“这条记录能不能给这个 origin”。
 */

export interface Site {
  scheme: 'http:' | 'https:';
  host: string;
  /** 生效端口，没写时取协议默认值。 */
  port: string;
  explicitPort: boolean;
}

const DEFAULT_PORT = { 'http:': '80', 'https:': '443' } as const;

function siteOf(u: URL): Site | null {
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
  if (!u.hostname) return null;
  return {
    scheme: u.protocol,
    host: u.hostname.toLowerCase().replace(/^www\./, ''),
    port: u.port || DEFAULT_PORT[u.protocol],
    explicitPort: u.port !== '',
  };
}

/** 条目里的网址。没写协议的按 https，和手机端一致。 */
export function parseSite(raw: string): Site | null {
  const s = raw.trim();
  if (!s) return null;
  try {
    return siteOf(new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`));
  } catch {
    return null;
  }
}

/** 页面 origin 必须是规范形式：带路径、账号或大写的都不是浏览器给的值。 */
export function parseOrigin(origin: string): Site | null {
  try {
    const u = new URL(origin);
    return u.origin === origin ? siteOf(u) : null;
  } catch {
    return null;
  }
}

/** 这些后缀下面的子域属于不同的人。不是公共后缀的完整列表，只挡常见的。 */
const SHARED_HOSTS = new Set([
  'github.io',
  'gitlab.io',
  'pages.dev',
  'workers.dev',
  'vercel.app',
  'netlify.app',
  'web.app',
  'firebaseapp.com',
  'herokuapp.com',
  'azurewebsites.net',
  'cloudfront.net',
  'blogspot.com',
]);

function allowsSubdomains(host: string): boolean {
  if (!host.includes('.')) return false;
  if (/^(com|net|org|gov|edu|ac|co)\.[a-z]{2}$/.test(host)) return false;
  return !SHARED_HOSTS.has(host);
}

export type SiteMatch = 'exact' | 'subdomain' | null;

/** 只比较解析后的主机名：相等，或页面是条目主机的子域。不用子串，也不反向匹配父域。 */
export function siteMatch(itemUrl: string, origin: string): SiteMatch {
  const page = parseOrigin(origin);
  const item = parseSite(itemUrl);
  if (!page || !item) return null;
  // 明文页面可能被中间人塞进表单，HTTPS 账号不给；要给必须是用户自己写的 http://
  if (page.scheme === 'http:' && item.scheme !== 'http:') return null;
  // 写了端口就只认这个端口，没写只认默认端口：同一台主机的其他端口是别的服务
  if (page.port !== (item.explicitPort ? item.port : DEFAULT_PORT[page.scheme])) return null;
  if (page.host === item.host) return 'exact';
  if (page.scheme === 'http:') return null;
  if (!allowsSubdomains(item.host)) return null;
  return page.host.endsWith(`.${item.host}`) ? 'subdomain' : null;
}

/** 多个网址里取最好的一条。 */
export function bestMatch(urls: readonly string[] | undefined, origin: string): SiteMatch {
  let best: SiteMatch = null;
  for (const u of urls ?? []) {
    const m = siteMatch(u, origin);
    if (m === 'exact') return m;
    best = m ?? best;
  }
  return best;
}

/**
 * 手机系统只报告网站域名，没有协议和端口（Android 只把可信浏览器里 https 页面的域名当网站）。
 * 按 https 默认端口拼成 origin，交给上面同一套 siteMatch，不另写一份规则。
 * 所以写了非默认端口的条目不推荐；页面其实在非默认端口时手机分辨不出，没写端口的条目照样推荐。
 * 必须是纯主机名：带端口、路径、账号的都不是系统给的值。
 */
export function phoneOrigin(domain: string): string | null {
  const host = domain.toLowerCase();
  try {
    const u = new URL(`https://${host}`);
    return u.hostname === host ? u.origin : null;
  } catch {
    return null;
  }
}

// —— 管道上的固定操作 ——

export type BrowserRequest =
  | { op: 'status' }
  | { op: 'list' | 'pick'; origin: string }
  | { op: 'fill'; origin: string; ref: string };

const REF = /^[A-Za-z0-9_-]{1,64}\/[A-Za-z0-9_-]{1,64}$/;

/** 只接受四个操作和它们各自的字段。多一个字段也拒绝：管道不是通用通道。 */
export function parseBrowserRequest(x: unknown): BrowserRequest | null {
  if (typeof x !== 'object' || x === null) return null;
  const r = x as Record<string, unknown>;
  const keys = Object.keys(r).sort().join();
  const origin = typeof r.origin === 'string' && parseOrigin(r.origin) ? r.origin : undefined;
  switch (r.op) {
    case 'status':
      return keys === 'op' ? { op: 'status' } : null;
    case 'list':
    case 'pick':
      return keys === 'op,origin' && origin ? { op: r.op, origin } : null;
    case 'fill':
      return keys === 'op,origin,ref' && origin && typeof r.ref === 'string' && REF.test(r.ref)
        ? { op: 'fill', origin, ref: r.ref }
        : null;
    default:
      return null;
  }
}

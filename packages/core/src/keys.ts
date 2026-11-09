/**
 * 密钥与 API 管理。
 * 这类机密和网站密码的区别：会过期、要轮换、散落在各项目的 .env 里，换的时候要知道哪些地方在用。
 * 这里全是本地纯函数：服务商识别只看前缀，不联网，机密值不离开设备。
 */
import { newItem, type Field, type ItemData, type ItemType, type ItemView } from './model';
import type { ImportRow } from './transfer';

export const KEY_TYPES: readonly ItemType[] = ['api', 'token', 'ssh', 'cert', 'env'];
export const isKeyItem = (d: ItemData): boolean => KEY_TYPES.includes(d.type);

const DAY = 86_400_000;

export type KeyState = 'ok' | 'expiring' | 'expired' | 'rotate';

export interface KeyStatus {
  state: KeyState;
  label: string;
}

/** 到期优先于轮换：过期的密钥已经不能用了，比“该换了”更紧急。 */
export function keyStatus(d: ItemData, now = Date.now(), warnDays = 30): KeyStatus {
  if (d.expiresAt) {
    if (d.expiresAt <= now) return { state: 'expired', label: '已过期' };
    const left = Math.ceil((d.expiresAt - now) / DAY);
    if (left <= warnDays) return { state: 'expiring', label: `${left} 天后到期` };
  }
  if (d.rotateDays) {
    const over = Math.floor((now - (d.passwordChangedAt ?? d.createdAt)) / DAY) - d.rotateDays;
    if (over >= 0) return { state: 'rotate', label: over === 0 ? '今天该轮换' : `该轮换，已超 ${over} 天` };
  }
  return { state: 'ok', label: '' };
}

export const needsAttention = (d: ItemData, now = Date.now()): boolean => keyStatus(d, now).state !== 'ok';

interface ProviderRule {
  provider: string;
  envName?: string;
  type?: ItemType;
  re: RegExp;
}

/** 顺序有意义：更具体的前缀在前，比如 sk-ant- 要先于 sk-。 */
const RULES: ProviderRule[] = [
  { provider: 'Anthropic', envName: 'ANTHROPIC_API_KEY', re: /^sk-ant-[\w-]{16,}$/ },
  { provider: 'OpenAI', envName: 'OPENAI_API_KEY', re: /^sk-(proj|svcacct|admin)-[\w-]{16,}$/ },
  { provider: 'Stripe', envName: 'STRIPE_SECRET_KEY', re: /^[sr]k_(live|test)_\w{16,}$/ },
  // 很多国内模型服务也用 sk- 开头，只能认到这一层，不去猜具体是哪家
  { provider: 'OpenAI 兼容', envName: 'OPENAI_API_KEY', re: /^sk-[\w-]{20,}$/ },
  { provider: 'GitHub', envName: 'GITHUB_TOKEN', type: 'token', re: /^(ghp|gho|ghu|ghs|ghr)_\w{20,}$|^github_pat_\w{20,}$/ },
  { provider: 'GitLab', envName: 'GITLAB_TOKEN', type: 'token', re: /^glpat-[\w-]{16,}$/ },
  { provider: 'AWS', envName: 'AWS_ACCESS_KEY_ID', re: /^(AKIA|ASIA)[0-9A-Z]{16}$/ },
  { provider: 'Google', envName: 'GOOGLE_API_KEY', re: /^AIza[\w-]{30,}$/ },
  { provider: '阿里云', envName: 'ALIBABA_CLOUD_ACCESS_KEY_ID', re: /^LTAI\w{12,}$/ },
  { provider: '腾讯云', envName: 'TENCENTCLOUD_SECRET_ID', re: /^AKID\w{16,}$/ },
  { provider: 'Slack', envName: 'SLACK_TOKEN', type: 'token', re: /^xox[abeoprs]-[\w-]{10,}$/ },
  { provider: 'npm', envName: 'NPM_TOKEN', type: 'token', re: /^npm_\w{20,}$/ },
  { provider: 'Hugging Face', envName: 'HF_TOKEN', type: 'token', re: /^hf_\w{20,}$/ },
  { provider: 'SendGrid', envName: 'SENDGRID_API_KEY', re: /^SG\.[\w-]{16,}\.[\w-]{16,}$/ },
  { provider: 'DigitalOcean', envName: 'DIGITALOCEAN_TOKEN', type: 'token', re: /^dop_v1_\w{32,}$/ },
];

export const KNOWN_PROVIDERS = [
  'OpenAI', 'Anthropic', 'DeepSeek', '阿里云', '腾讯云', '华为云', '火山引擎', '智谱', '月之暗面', 'Cloudflare',
  'GitHub', 'GitLab', 'AWS', 'Google', 'Azure', 'Stripe', 'Slack', 'npm', 'Hugging Face', 'SendGrid', 'DigitalOcean',
];

export interface Detected {
  provider?: string;
  envName?: string;
  type?: ItemType;
}

export function detectKey(value: string): Detected | undefined {
  const v = value.trim();
  if (/-----BEGIN (OPENSSH|RSA|EC|DSA|ED25519)? ?PRIVATE KEY-----/.test(v)) return { type: 'ssh' };
  if (/-----BEGIN CERTIFICATE-----/.test(v)) return { type: 'cert' };
  for (const r of RULES) {
    if (r.re.test(v)) {
      return { provider: r.provider, ...(r.envName ? { envName: r.envName } : {}), ...(r.type ? { type: r.type } : {}) };
    }
  }
  return undefined;
}

export interface EnvVar {
  name: string;
  value: string;
}

const ESCAPES: Record<string, string> = { n: '\n', r: '\r', t: '\t', '"': '"', '\\': '\\', $: '$' };

/** 解析 .env：注释、export 前缀、单双引号、转义、跨行引号、行内注释。同名以最后一个为准。 */
export function parseDotEnv(text: string): { vars: EnvVar[]; skipped: number } {
  const src = text.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
  const out = new Map<string, string>();
  const head = /[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*=[ \t]*/y;
  let skipped = 0;
  let i = 0;
  const nextLine = (from: number) => {
    const e = src.indexOf('\n', from);
    return e < 0 ? src.length : e + 1;
  };
  while (i < src.length) {
    const eol = nextLine(i);
    const line = src.slice(i, eol).trim();
    if (line === '' || line.startsWith('#')) {
      i = eol;
      continue;
    }
    head.lastIndex = i;
    const m = head.exec(src);
    if (!m) {
      skipped++;
      i = eol;
      continue;
    }
    let p = head.lastIndex;
    const q = src[p];
    let value: string | undefined;
    if (q === '"' || q === "'") {
      let buf = '';
      let j = p + 1;
      for (; j < src.length; j++) {
        const c = src[j]!;
        if (c === q) break;
        if (q === '"' && c === '\\' && j + 1 < src.length) {
          const e = src[j + 1]!;
          buf += ESCAPES[e] ?? `\\${e}`;
          j++;
        } else buf += c;
      }
      if (j < src.length) {
        value = buf;
        p = j + 1;
      }
    }
    if (value === undefined) {
      // 无引号或引号没闭合：到行尾为止，“空格 + #”之后是注释
      const raw = src.slice(p, nextLine(p)).replace(/\n$/, '');
      const c = raw.search(/\s#/);
      value = (c >= 0 ? raw.slice(0, c) : raw).trim();
      p = nextLine(p);
    } else {
      p = nextLine(p);
    }
    out.set(m[1]!, value);
    i = p;
  }
  return { vars: [...out].map(([name, value]) => ({ name, value })), skipped };
}

/** 只有这种名字能安全写进 shell 命令。其他字符一律不导出，防止条目内容变成命令。 */
export const isEnvName = (s: string): boolean => /^[A-Za-z_][A-Za-z0-9_]*$/.test(s);

const slug = (s: string): string =>
  s
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');

/** 字段对应的环境变量名：用户指定的优先，其次服务商惯例，最后由标题和字段名生成。 */
export function envNameFor(d: ItemData, f: Field): string {
  if (f.envName) return f.envName;
  if (d.type === 'env') return f.name;
  const known = f.secret ? detectKey(f.value)?.envName : undefined;
  if (known) return known;
  const name = [slug(d.title), slug(f.name)].filter(Boolean).join('_');
  if (!name) return 'SECRET';
  return /^[A-Z_]/.test(name) ? name : `KEY_${name}`;
}

export function envRows(d: ItemData): EnvVar[] {
  const rows = new Map<string, string>();
  for (const f of d.fields ?? []) {
    if (!f.value) continue;
    // 主机、端口这类说明性字段不算环境变量，除非用户明确指定了变量名
    if (d.type !== 'env' && !f.secret && !f.envName) continue;
    // 纯中文标题的字段可能生成同一个名字，重名时不能让后一个把前一个盖掉
    const base = envNameFor(d, f);
    let name = base;
    let n = 1;
    while (rows.has(name)) name = `${base}_${++n}`;
    rows.set(name, f.value);
  }
  return [...rows].map(([name, value]) => ({ name, value }));
}

export type EnvFormat = 'dotenv' | 'bash' | 'powershell' | 'json';

export const ENV_FORMATS: { id: EnvFormat; label: string }[] = [
  { id: 'dotenv', label: '.env' },
  { id: 'powershell', label: 'PowerShell' },
  { id: 'bash', label: 'Bash' },
  { id: 'json', label: 'JSON' },
];

function dotenvValue(v: string): string {
  if (/^[\w\-.:/+=@%,]*$/.test(v)) return v;
  if (!/['\n\r]/.test(v)) return `'${v}'`;
  return `"${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\$/g, '\\$').replace(/\n/g, '\\n').replace(/\r/g, '\\r')}"`;
}

/**
 * 生成可以直接粘贴的文本。值要按目标语法转义，否则一个带引号的密钥就能变成命令注入。
 * 名字不合法的变量跳过，由调用方告诉用户。
 */
export function renderEnv(rows: EnvVar[], format: EnvFormat): { text: string; skipped: string[] } {
  const ok = rows.filter((r) => isEnvName(r.name));
  const skipped = rows.filter((r) => !isEnvName(r.name)).map((r) => r.name);
  let text: string;
  switch (format) {
    case 'dotenv':
      text = ok.map((r) => `${r.name}=${dotenvValue(r.value)}`).join('\n');
      break;
    case 'bash':
      text = ok.map((r) => `export ${r.name}='${r.value.replace(/'/g, `'\\''`)}'`).join('\n');
      break;
    case 'powershell':
      text = ok.map((r) => `$env:${r.name} = '${r.value.replace(/'/g, "''")}'`).join('\n');
      break;
    case 'json':
      text = JSON.stringify(Object.fromEntries(ok.map((r) => [r.name, r.value])), null, 2);
      break;
  }
  return { text, skipped };
}

/** .env 文件变成一个变量组。值默认全部按机密处理，连接串里经常带密码。 */
export function importDotEnv(text: string, title: string): { row: ImportRow; skipped: number } {
  const { vars, skipped } = parseDotEnv(text);
  const data = newItem('env', title);
  data.fields = vars.map((v) => ({ name: v.name, value: v.value, secret: true }));
  return { row: { data, folderPath: '' }, skipped };
}

/** 列表里用来区分两把密钥，只露末 4 位。太短的值不露。 */
export function keyHint(d: ItemData): string {
  if (d.type === 'env') {
    const n = (d.fields ?? []).filter((f) => f.value).length;
    return n ? `${n} 个变量` : '';
  }
  const main =(d.fields ?? []).find((f) => f.secret && f.value && !f.value.includes('\n'));
  return main && main.value.length >= 16 ? `…${main.value.slice(-4)}` : '';
}

export interface KeyOverview {
  total: number;
  expired: ItemView[];
  expiring: ItemView[];
  rotate: ItemView[];
  /** 生产环境密钥放在云库：报告建议这类放重要本地库。 */
  cloudProduction: ItemView[];
  /** 同一把密钥存在多条里，换的时候容易漏。 */
  duplicates: ItemView[][];
  providers: { name: string; items: ItemView[] }[];
}

export function keyOverview(items: ItemView[], isCloud: (vaultId: string) => boolean, now = Date.now()): KeyOverview {
  const keys = items.filter((i) => isKeyItem(i.data));
  const by = (s: KeyState) => keys.filter((i) => keyStatus(i.data, now).state === s);
  const secrets = new Map<string, ItemView[]>();
  const providers = new Map<string, ItemView[]>();
  for (const it of keys) {
    const seen = new Set<string>();
    for (const f of it.data.fields ?? []) {
      if (!f.secret || !f.value || seen.has(f.value)) continue;
      seen.add(f.value);
      const g = secrets.get(f.value);
      if (g) g.push(it);
      else secrets.set(f.value, [it]);
    }
    const name = it.data.provider || '未分类';
    const p = providers.get(name);
    if (p) p.push(it);
    else providers.set(name, [it]);
  }
  return {
    total: keys.length,
    expired: by('expired'),
    expiring: by('expiring'),
    rotate: by('rotate'),
    cloudProduction: keys.filter((i) => i.data.env === 'production' && isCloud(i.vaultId)),
    duplicates: [...secrets.values()].filter((g) => g.length > 1),
    providers: [...providers]
      .map(([name, list]) => ({ name, items: list }))
      .sort(
        (a, b) =>
          Number(a.name === '未分类') - Number(b.name === '未分类') ||
          b.items.length - a.items.length ||
          a.name.localeCompare(b.name, 'zh-CN'),
      ),
  };
}

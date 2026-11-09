import { execFileSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import {
  detectKey,
  envNameFor,
  envRows,
  importDotEnv,
  isEnvName,
  isKeyItem,
  keyHint,
  keyOverview,
  keyStatus,
  needsAttention,
  parseDotEnv,
  renderEnv,
  type EnvFormat,
} from '../src/keys';
import { ITEM_TEMPLATES, getItem, newItem, saveItem, type ItemData, type ItemView } from '../src/model';
import { search } from '../src/tools';
import { dedupeKey, markDuplicates } from '../src/transfer';
import { makeVault, ready } from './helpers';

ready();

const DAY = 86_400_000;
const NOW = 1_800_000_000_000;
const key = (over: Partial<ItemData> = {}): ItemData => ({ ...newItem('api', 'k'), createdAt: NOW, updatedAt: NOW, ...over });
const view = (data: ItemData, vaultId = 'cloud'): ItemView => ({ vaultId, id: Math.random().toString(), data, conflict: false, heads: [] });

describe('到期与轮换', () => {
  it('没有设置时不报警', () => {
    expect(keyStatus(key(), NOW)).toEqual({ state: 'ok', label: '' });
    expect(needsAttention(key(), NOW)).toBe(false);
  });

  it('过期、快到期的边界', () => {
    expect(keyStatus(key({ expiresAt: NOW - 1 }), NOW).state).toBe('expired');
    expect(keyStatus(key({ expiresAt: NOW }), NOW).state).toBe('expired');
    expect(keyStatus(key({ expiresAt: NOW + DAY }), NOW)).toEqual({ state: 'expiring', label: '1 天后到期' });
    expect(keyStatus(key({ expiresAt: NOW + 30 * DAY }), NOW).state).toBe('expiring');
    expect(keyStatus(key({ expiresAt: NOW + 31 * DAY }), NOW).state).toBe('ok');
  });

  it('轮换按最后一次更换时间算，不是创建时间', () => {
    const old = NOW - 100 * DAY;
    expect(keyStatus(key({ rotateDays: 90, createdAt: old }), NOW).state).toBe('rotate');
    expect(keyStatus(key({ rotateDays: 90, createdAt: old, passwordChangedAt: NOW - DAY }), NOW).state).toBe('ok');
    expect(keyStatus(key({ rotateDays: 90, passwordChangedAt: NOW - 89 * DAY }), NOW).state).toBe('ok');
    expect(keyStatus(key({ rotateDays: 90, passwordChangedAt: NOW - 90 * DAY }), NOW).label).toBe('今天该轮换');
    expect(keyStatus(key({ rotateDays: 90, passwordChangedAt: NOW - 95 * DAY }), NOW).label).toBe('该轮换，已超 5 天');
  });

  it('过期优先于轮换', () => {
    expect(keyStatus(key({ rotateDays: 1, createdAt: NOW - 10 * DAY, expiresAt: NOW - DAY }), NOW).state).toBe('expired');
  });
});

describe('服务商识别', () => {
  it.each([
    ['sk-ant-api03-abcdefghijklmnopqrstuvwxyz', 'Anthropic', 'ANTHROPIC_API_KEY'],
    ['sk-proj-abcdefghijklmnopqrstuvwxyz012345', 'OpenAI', 'OPENAI_API_KEY'],
    ['sk-abcdefghijklmnopqrstuvwxyz012345', 'OpenAI 兼容', 'OPENAI_API_KEY'],
    ['ghp_abcdefghijklmnopqrstuvwxyz0123456789', 'GitHub', 'GITHUB_TOKEN'],
    ['github_pat_11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz', 'GitHub', 'GITHUB_TOKEN'],
    ['glpat-abcdefghijklmnopqrst', 'GitLab', 'GITLAB_TOKEN'],
    ['AKIAIOSFODNN7EXAMPLE', 'AWS', 'AWS_ACCESS_KEY_ID'],
    // 全是虚构值。Google、腾讯云、Stripe 三条拆开拼接，只是为了不被 GitHub 密钥扫描当成真密钥
    ['AIza' + 'SyA1234567890abcdefghijklmnopqrstuv', 'Google', 'GOOGLE_API_KEY'],
    ['LTAI5tABCDEFGHIJKLMN', '阿里云', 'ALIBABA_CLOUD_ACCESS_KEY_ID'],
    ['AKID' + 'abcdefghijklmnopqrstuvwxyz012345', '腾讯云', 'TENCENTCLOUD_SECRET_ID'],
    ['sk_' + 'live_abcdefghijklmnopqrstuvwx', 'Stripe', 'STRIPE_SECRET_KEY'],
    ['hf_abcdefghijklmnopqrstuvwxyz012345', 'Hugging Face', 'HF_TOKEN'],
  ])('%s', (value, provider, envName) => {
    expect(detectKey(`  ${value}\n`)).toMatchObject({ provider, envName });
  });

  it('PEM 内容识别成类型', () => {
    expect(detectKey('-----BEGIN OPENSSH PRIVATE KEY-----\nabc')?.type).toBe('ssh');
    expect(detectKey('-----BEGIN PRIVATE KEY-----\nabc')?.type).toBe('ssh');
    expect(detectKey('-----BEGIN CERTIFICATE-----\nabc')?.type).toBe('cert');
  });

  it('普通字符串不误判', () => {
    for (const s of ['', 'hello', 'sk-', 'sk-short', 'password123', 'ghp_', 'skateboard-is-fun-to-ride-all-day', 'AKIA']) {
      expect(detectKey(s)).toBeUndefined();
    }
  });
});

describe('.env 解析', () => {
  const parse = (t: string) => Object.fromEntries(parseDotEnv(t).vars.map((v) => [v.name, v.value]));

  it('常见写法', () => {
    expect(
      parse(`# 注释
A=1
export B=two
C = spaced

D="double quoted"
E='single $NOT_EXPANDED'
F=has=equals=inside
G=
H=value # 行内注释
I=with#hash
`),
    ).toEqual({
      A: '1',
      B: 'two',
      C: 'spaced',
      D: 'double quoted',
      E: 'single $NOT_EXPANDED',
      F: 'has=equals=inside',
      G: '',
      H: 'value',
      I: 'with#hash',
    });
  });

  it('转义和跨行', () => {
    expect(parse('A="x\\ny\\t\\"z\\\\"')).toEqual({ A: 'x\ny\t"z\\' });
    expect(parse(`KEY="-----BEGIN
line2
END"
NEXT=1`)).toEqual({ KEY: '-----BEGIN\nline2\nEND', NEXT: '1' });
    expect(parse(`S='a\\nb'`)).toEqual({ S: 'a\\nb' });
  });

  it('BOM、CRLF、重复变量、无效行', () => {
    const r = parseDotEnv('﻿A=1\r\nnot a valid line\r\nB=2\r\nA=3\r\n');
    expect(r.vars).toEqual([
      { name: 'A', value: '3' },
      { name: 'B', value: '2' },
    ]);
    expect(r.skipped).toBe(1);
  });

  it('引号没闭合时不吞掉后面的行', () => {
    expect(parse(`A="oops\nB=2`)).toEqual({ A: '"oops', B: '2' });
  });

  it('零条、一条、多条', () => {
    expect(parseDotEnv('').vars).toEqual([]);
    expect(parseDotEnv('# 只有注释\n').vars).toEqual([]);
    expect(parseDotEnv('A=1').vars).toHaveLength(1);
    expect(parseDotEnv('A=1\nB=2\nC=3\n').vars).toHaveLength(3);
  });

  it('导入成变量组，值全部按机密处理', () => {
    const { row, skipped } = importDotEnv('DB_URL=postgres://u:p@h/db\nbad line\nPORT=80\n', '后端配置');
    expect(row.data.type).toBe('env');
    expect(row.data.title).toBe('后端配置');
    expect(row.data.fields).toEqual([
      { name: 'DB_URL', value: 'postgres://u:p@h/db', secret: true },
      { name: 'PORT', value: '80', secret: true },
    ]);
    expect(skipped).toBe(1);
  });
});

/** 这些值里任何一个没转义，粘贴到终端就是命令注入或变量展开。 */
const NASTY = [
  'plain',
  'with space',
  `it's`,
  `'; touch /tmp/mixia-pwned; '`,
  '$(touch /tmp/mixia-pwned)',
  '`touch /tmp/mixia-pwned`',
  '$HOME',
  '"double"',
  'back\\slash',
  'new\nline',
  '#hash',
  'a=b',
  '',
];

describe('复制为环境变量', () => {
  const rows = NASTY.map((value, i) => ({ name: `V${i}`, value }));

  it('.env 输出解析回来逐字一致', () => {
    const back = parseDotEnv(renderEnv(rows, 'dotenv').text).vars;
    expect(back).toEqual(rows);
  });

  it('JSON 输出逐字一致', () => {
    const j = JSON.parse(renderEnv(rows, 'json').text);
    rows.forEach((r) => expect(j[r.name]).toBe(r.value));
  });

  it('真实 Bash 里执行：值逐字一致，没有命令被执行', () => {
    const { text } = renderEnv(rows, 'bash');
    const script = `${text}\nnode -e 'console.log(JSON.stringify(Object.fromEntries(Object.entries(process.env).filter(([k]) => /^V\\d+$/.test(k)))))'`;
    const got = JSON.parse(execFileSync('bash', ['-c', script], { encoding: 'utf8' }));
    rows.forEach((r) => expect(got[r.name]).toBe(r.value));
  }, 30_000);

  // pwsh 冷启动在 CI 机器上可能超过默认的 5 秒
  it('真实 PowerShell 里执行：值逐字一致', () => {
    const nonEmpty = rows.filter((r) => r.value);
    const { text } = renderEnv(nonEmpty, 'powershell');
    const names = nonEmpty.map((r) => `'${r.name}'`).join(',');
    const script = `${text}\n$o=@{}; foreach($n in ${names}){ $o[$n]=[Environment]::GetEnvironmentVariable($n) }; [Console]::OutputEncoding=[Text.Encoding]::UTF8; $o | ConvertTo-Json -Compress`;
    const encoded = Buffer.from(script, 'utf16le').toString('base64');
    const got = JSON.parse(execFileSync('pwsh', ['-NoProfile', '-EncodedCommand', encoded], { encoding: 'utf8' }));
    nonEmpty.forEach((r) => expect(got[r.name]).toBe(r.value));
  }, 30_000);

  it('非法变量名不进入输出，并告诉调用方', () => {
    const evil = [
      { name: 'OK', value: '1' },
      { name: 'A; rm -rf /', value: 'x' },
      { name: '$(whoami)', value: 'x' },
      { name: '1BAD', value: 'x' },
      { name: 'a-b', value: 'x' },
    ];
    for (const f of ['dotenv', 'bash', 'powershell', 'json'] as EnvFormat[]) {
      const r = renderEnv(evil, f);
      expect(r.text).toContain('OK');
      expect(r.text).not.toMatch(/rm -rf|whoami|1BAD|a-b/);
      expect(r.skipped).toHaveLength(4);
    }
  });

  it('变量名规则', () => {
    expect(['A', '_a', 'A1_b'].every(isEnvName)).toBe(true);
    expect(['', '1A', 'A-B', 'A B', 'A.B', '中文'].some(isEnvName)).toBe(false);
  });

  it('优先用指定名字，其次服务商惯例，最后由标题生成', () => {
    const d = key({ title: 'Payment Prod' });
    expect(envNameFor(d, { name: 'x', value: 'v', envName: 'MY_KEY' })).toBe('MY_KEY');
    expect(envNameFor(d, { name: 'API Key', value: 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz', secret: true })).toBe('ANTHROPIC_API_KEY');
    expect(envNameFor(d, { name: 'API Key', value: 'xxx', secret: true })).toBe('PAYMENT_PROD_API_KEY');
    expect(envNameFor(key({ title: '中文标题' }), { name: '私钥', value: 'x', secret: true })).toBe('SECRET');
    expect(isEnvName(envNameFor(key({ title: '2024 key' }), { name: 'a', value: 'x', secret: true }))).toBe(true);
  });

  it('生成的名字重名时不丢值', () => {
    const rows2 = envRows(
      key({
        title: '中文标题',
        fields: [
          { name: '密钥', value: 'one', secret: true },
          { name: '令牌', value: 'two', secret: true },
          { name: '口令', value: 'three', secret: true },
        ],
      }),
    );
    expect(rows2.map((r) => r.value)).toEqual(['one', 'two', 'three']);
    expect(rows2.map((r) => r.name)).toEqual(['SECRET', 'SECRET_2', 'SECRET_3']);
  });

  it('环境变量组保留全部变量；其他类型只导出机密和指定了变量名的字段', () => {
    expect(envRows(key({ type: 'env', fields: [{ name: 'A', value: '1' }, { name: 'B', value: '' }] }))).toEqual([{ name: 'A', value: '1' }]);
    const rows2 = envRows(
      key({
        title: 'svc',
        fields: [
          { name: 'Endpoint', value: 'https://x' },
          { name: 'Base', value: 'https://y', envName: 'BASE_URL' },
          { name: 'API Key', value: 'k', secret: true },
        ],
      }),
    );
    expect(rows2).toEqual([
      { name: 'BASE_URL', value: 'https://y' },
      { name: 'SVC_API_KEY', value: 'k' },
    ]);
  });
});

describe('总览', () => {
  const isCloud = (id: string) => id === 'cloud';

  it('零条、一条、多条形态一致', () => {
    const empty = keyOverview([], isCloud, NOW);
    expect(empty).toMatchObject({ total: 0, expired: [], expiring: [], rotate: [], cloudProduction: [], duplicates: [], providers: [] });
    expect(keyOverview([view(key())], isCloud, NOW).total).toBe(1);
    expect(keyOverview([view(key()), view(key())], isCloud, NOW).total).toBe(2);
  });

  it('普通登录不算密钥', () => {
    expect(keyOverview([view(newItem('login', 'x'))], isCloud, NOW).total).toBe(0);
    expect(isKeyItem(newItem('login'))).toBe(false);
    expect((['api', 'token', 'ssh', 'cert', 'env'] as const).every((t) => isKeyItem(newItem(t)))).toBe(true);
  });

  it('分类统计', () => {
    const o = keyOverview(
      [
        view(key({ title: 'a', expiresAt: NOW - DAY, provider: 'OpenAI' })),
        view(key({ title: 'b', expiresAt: NOW + DAY, provider: 'OpenAI' })),
        view(key({ title: 'c', rotateDays: 1, createdAt: NOW - 5 * DAY })),
        view(key({ title: 'prod-cloud', env: 'production' }), 'cloud'),
        view(key({ title: 'prod-local', env: 'production' }), 'local'),
      ],
      isCloud,
      NOW,
    );
    expect(o.expired.map((i) => i.data.title)).toEqual(['a']);
    expect(o.expiring.map((i) => i.data.title)).toEqual(['b']);
    expect(o.rotate.map((i) => i.data.title)).toEqual(['c']);
    expect(o.cloudProduction.map((i) => i.data.title)).toEqual(['prod-cloud']);
    expect(o.providers[0]).toMatchObject({ name: 'OpenAI' });
    expect(o.providers[0]!.items).toHaveLength(2);
    expect(o.providers.map((p) => p.name)).toContain('未分类');
  });

  it('同一把密钥存在多条里要提示', () => {
    const f = [{ name: 'K', value: 'same-secret', secret: true }];
    const o = keyOverview([view(key({ title: 'a', fields: f })), view(key({ title: 'b', fields: f })), view(key({ title: 'c' }))], isCloud, NOW);
    expect(o.duplicates).toHaveLength(1);
    expect(o.duplicates[0]!.map((i) => i.data.title).sort()).toEqual(['a', 'b']);
  });

  it('列表提示只露末 4 位，短值不露，多行不露', () => {
    expect(keyHint(key({ fields: [{ name: 'K', value: 'abcdefghijklmnopWXYZ', secret: true }] }))).toBe('…WXYZ');
    expect(keyHint(key({ fields: [{ name: 'K', value: 'short', secret: true }] }))).toBe('');
    expect(keyHint(key({ fields: [{ name: 'K', value: 'x'.repeat(30) + '\nend!', secret: true }] }))).toBe('');
    expect(keyHint(key({ fields: [{ name: 'K', value: 'abcdefghijklmnopWXYZ' }] }))).toBe('');
  });

  it('变量组显示变量个数，不露任何一个值的末尾', () => {
    const env = (fields: ItemData['fields']) => key({ type: 'env', fields });
    expect(keyHint(env([]))).toBe('');
    expect(keyHint(env([{ name: 'A', value: 'abcdefghijklmnopWXYZ', secret: true }]))).toBe('1 个变量');
    expect(keyHint(env([{ name: 'A', value: '1', secret: true }, { name: 'B', value: '', secret: true }, { name: 'C', value: '3', secret: true }]))).toBe('2 个变量');
  });
});

describe('换密钥', () => {
  it('机密字段换值：旧值进历史，轮换时间更新', async () => {
    const { v } = await makeVault();
    const fields = [
      { name: 'API Key', value: 'OLD-KEY', secret: true },
      { name: 'Endpoint', value: 'https://a' },
    ];
    const id = await saveItem(v, undefined, { ...newItem('api', 'x'), fields });
    const first = getItem(v, id)!.data.passwordChangedAt!;
    await new Promise((r) => setTimeout(r, 5));
    await saveItem(v, id, { ...getItem(v, id)!.data, fields: [{ ...fields[0]!, value: 'NEW-KEY' }, fields[1]!] });
    const d = getItem(v, id)!.data;
    expect(d.passwordHistory?.[0]).toMatchObject({ value: 'OLD-KEY', field: 'API Key' });
    expect(d.passwordChangedAt!).toBeGreaterThan(first);
  });

  it('只改备注或非机密字段：不算轮换，不进历史', async () => {
    const { v } = await makeVault();
    const fields = [
      { name: 'API Key', value: 'K', secret: true },
      { name: 'Endpoint', value: 'https://a' },
    ];
    const id = await saveItem(v, undefined, { ...newItem('api', 'x'), fields });
    const before = getItem(v, id)!.data.passwordChangedAt;
    await new Promise((r) => setTimeout(r, 5));
    await saveItem(v, id, { ...getItem(v, id)!.data, notes: 'n', fields: [fields[0]!, { ...fields[1]!, value: 'https://b' }] });
    const d = getItem(v, id)!.data;
    expect(d.passwordHistory).toBeUndefined();
    expect(d.passwordChangedAt).toBe(before);
  });

  it('删掉机密字段也留下旧值', async () => {
    const { v } = await makeVault();
    const id = await saveItem(v, undefined, { ...newItem('env', 'x'), fields: [{ name: 'A', value: 'keep-me', secret: true }] });
    await saveItem(v, id, { ...getItem(v, id)!.data, fields: [] });
    expect(getItem(v, id)!.data.passwordHistory?.[0]).toMatchObject({ value: 'keep-me', field: 'A' });
  });

  it('历史最多 10 条', async () => {
    const { v } = await makeVault();
    const id = await saveItem(v, undefined, { ...newItem('token', 'x'), fields: [{ name: 'Token', value: 't0', secret: true }] });
    for (let i = 1; i <= 13; i++) {
      await saveItem(v, id, { ...getItem(v, id)!.data, fields: [{ name: 'Token', value: `t${i}`, secret: true }] });
    }
    expect(getItem(v, id)!.data.passwordHistory).toHaveLength(10);
    expect(getItem(v, id)!.data.passwordHistory![0]!.value).toBe('t12');
  });
});

describe('导入去重', () => {
  const api = (value: string) => key({ title: 'Stripe', fields: [{ name: 'API Key', value, secret: true }] });

  it('同名但密钥不同的条目不算重复，完全相同的才算', () => {
    const r = markDuplicates(
      [
        { data: api('new-key'), folderPath: '' },
        { data: api('old-key'), folderPath: '' },
      ],
      [view(api('old-key'))],
    );
    expect(r.fresh.map((x) => x.data.fields![0]!.value)).toEqual(['new-key']);
    expect(r.dupes.map((x) => x.data.fields![0]!.value)).toEqual(['old-key']);
  });

  it('已有同名密钥时，同名的安全笔记不会被当成重复跳过', () => {
    const note = newItem('note', 'Stripe');
    expect(markDuplicates([{ data: note, folderPath: '' }], [view(api('k'))]).fresh).toHaveLength(1);
  });

  it('非机密字段不影响判重，已有的 CSV 去重结果不变', () => {
    const a = key({ title: 'x', fields: [{ name: 'Custom', value: '1' }] });
    const b = key({ title: 'x', fields: [{ name: 'Custom', value: '2' }] });
    expect(dedupeKey(a)).toBe(dedupeKey(b));
  });
});

describe('搜索和模板', () => {
  const items = [
    view(
      key({
        title: '支付网关',
        provider: 'Stripe',
        usedBy: ['订单服务', 'prod-server-3'],
        fields: [{ name: 'API Key', value: 'SECRET-VALUE-XYZ', secret: true, envName: 'PAY_KEY' }],
      }),
    ),
    view(key({ title: '即将过期', expiresAt: Date.now() + DAY })),
    view(newItem('login', '普通登录')),
  ];

  it('能按服务商、用途、变量名找到，找不到机密值', () => {
    expect(search(items, 'stripe')).toHaveLength(1);
    expect(search(items, 'provider:stripe')).toHaveLength(1);
    expect(search(items, '订单服务')).toHaveLength(1);
    expect(search(items, 'PAY_KEY')).toHaveLength(1);
    expect(search(items, 'SECRET-VALUE')).toHaveLength(0);
  });

  it('is:key 和 is:expiring', () => {
    expect(search(items, 'is:key')).toHaveLength(2);
    expect(search(items, 'is:expiring').map((i) => i.data.title)).toEqual(['即将过期']);
  });

  it('新类型模板可用，机密字段默认标记', () => {
    expect(ITEM_TEMPLATES.ssh.fields.find((f) => f.name === '私钥')?.secret).toBe(true);
    expect(ITEM_TEMPLATES.cert.fields.find((f) => f.name === '私钥')?.secret).toBe(true);
    expect(ITEM_TEMPLATES.token.fields[0]?.secret).toBe(true);
    expect(newItem('env').fields).toEqual([]);
  });
});

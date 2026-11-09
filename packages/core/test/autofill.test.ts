import { describe, expect, it } from 'vitest';
import { bestMatch, parseBrowserRequest, parseOrigin, parseSite, phoneOrigin, siteMatch } from '../src/autofill';
import { BrowserFill, type BrowserFillUi, type BrowserReply } from '../src/browserfill';
import { newItem, saveItem } from '../src/model';
import { phoneFillChoices } from '../src/phonefill';
import { randomBytes } from '../src/crypto';
import { MemoryKV } from '../src/store';
import { Vault, type Policy } from '../src/vault';
import { keys, ready } from './helpers';

describe('站点匹配', () => {
  const yes: [string, string, 'exact' | 'subdomain'][] = [
    ['example.com', 'https://example.com', 'exact'],
    ['https://example.com/login?x=1', 'https://example.com', 'exact'],
    ['HTTPS://EXAMPLE.com', 'https://example.com', 'exact'],
    ['www.example.com', 'https://example.com', 'exact'],
    ['example.com', 'https://www.example.com', 'exact'],
    ['example.com', 'https://login.example.com', 'subdomain'],
    ['example.com', 'https://a.b.example.com', 'subdomain'],
    ['example.com:8443', 'https://example.com:8443', 'exact'],
    ['https://example.com:8443', 'https://example.com:8443', 'exact'],
    ['http://example.com', 'https://example.com', 'exact'],
    ['http://192.168.1.1', 'http://192.168.1.1', 'exact'],
    ['http://127.0.0.1:4000', 'http://127.0.0.1:4000', 'exact'],
    ['foo.github.io', 'https://foo.github.io', 'exact'],
    ['foo.github.io', 'https://x.foo.github.io', 'subdomain'],
  ];
  it.each(yes)('%s 给 %s', (item, page, want) => {
    expect(siteMatch(item, page)).toBe(want);
  });

  const no: [string, string, string][] = [
    ['example.com', 'https://evilexample.com', '子串'],
    ['example.com', 'https://example.com.evil.com', '后缀拼接'],
    ['example.com', 'https://example.co', '前缀'],
    ['example.com', 'https://evil.com', '无关'],
    ['login.example.com', 'https://example.com', '父域不反向匹配'],
    ['login.example.com', 'https://other.example.com', '兄弟子域'],
    ['example.com', 'http://example.com', '明文页面不给 https 账号'],
    ['https://example.com', 'http://example.com', '明文页面不给 https 账号'],
    ['http://example.com', 'http://sub.example.com', '明文页面不做子域匹配'],
    ['example.com', 'https://example.com:8443', '没写端口只认默认端口'],
    ['example.com:8443', 'https://example.com', '写了端口就要这个端口'],
    ['example.com:8443', 'https://example.com:9443', '端口不同'],
    ['http://127.0.0.1:4000', 'http://127.0.0.1:4001', '本机其他端口'],
    ['http://localhost:4000', 'http://127.0.0.1:4000', '主机名不同'],
    ['example.com', 'https://example.com.', '末尾点不算同一主机'],
    ['com', 'https://evil.com', '单段主机不做子域匹配'],
    ['localhost', 'https://evil.localhost', '单段主机不做子域匹配'],
    ['co.uk', 'https://evil.co.uk', '公共后缀'],
    ['com.cn', 'https://evil.com.cn', '公共后缀'],
    ['github.io', 'https://evil.github.io', '多租户后缀'],
    ['pages.dev', 'https://evil.pages.dev', '多租户后缀'],
    ['foo.github.io', 'https://bar.github.io', '多租户下的邻居'],
    ['1.2.3.4', 'https://x.1.2.3.4', 'IP 不做子域匹配'],
    ['https://example.com@evil.com', 'https://example.com', '用户信息不是主机'],
    ['https://evil.com/example.com', 'https://example.com', '路径不是主机'],
    ['https://evil.com?example.com', 'https://example.com', '查询串不是主机'],
    ['ftp://example.com', 'https://example.com', '非网页协议'],
    ['javascript:alert(1)', 'https://example.com', '非网页协议'],
    ['androidapp://example.com', 'https://example.com', '非网页协议'],
    ['', 'https://example.com', '空'],
    ['example.com', 'https://xn--exmple-cua.com', 'punycode 是另一个主机'],
    ['example.com', 'file:///c:/example.com', '页面不是网站'],
    ['example.com', 'chrome-extension://example.com', '页面不是网站'],
    ['example.com', 'null', '不透明来源'],
    ['example.com', 'https://example.com/', '不是规范 origin'],
    ['example.com', 'https://user@example.com', '不是规范 origin'],
    ['example.com', 'https://EXAMPLE.com', '不是规范 origin'],
  ];
  it.each(no)('%s 不给 %s（%s）', (item, page) => {
    expect(siteMatch(item, page)).toBe(null);
  });

  it('多个网址取最好的', () => {
    expect(bestMatch(['evil.com', 'example.com'], 'https://a.example.com')).toBe('subdomain');
    expect(bestMatch(['example.com', 'a.example.com'], 'https://a.example.com')).toBe('exact');
    expect(bestMatch([], 'https://a.example.com')).toBe(null);
    expect(bestMatch(undefined, 'https://a.example.com')).toBe(null);
  });

  it('解析', () => {
    expect(parseSite('  https://Example.com:444/x ')).toEqual({ scheme: 'https:', host: 'example.com', port: '444', explicitPort: true });
    expect(parseOrigin('https://example.com:443')).toBe(null);
    expect(parseOrigin('https://example.com')?.port).toBe('443');
  });
});

describe('手机站点匹配：系统只给域名，规则和电脑相同', () => {
  const phone = (item: string, domain: string) => {
    const o = phoneOrigin(domain);
    return o ? siteMatch(item, o) : null;
  };

  const yes: [string, string, 'exact' | 'subdomain'][] = [
    ['example.com', 'example.com', 'exact'],
    ['https://example.com/login?x=1', 'example.com', 'exact'],
    ['www.example.com', 'example.com', 'exact'],
    ['example.com', 'www.example.com', 'exact'],
    ['example.com', 'EXAMPLE.com', 'exact'],
    ['example.com:443', 'example.com', 'exact'],
    ['http://example.com', 'example.com', 'exact'],
    ['example.com', 'login.example.com', 'subdomain'],
    ['example.com', 'a.b.example.com', 'subdomain'],
    ['foo.github.io', 'x.foo.github.io', 'subdomain'],
  ];
  it.each(yes)('%s 给 %s', (item, domain, want) => {
    expect(phone(item, domain)).toBe(want);
  });

  const no: [string, string, string][] = [
    ['login.example.com', 'example.com', '父域不反向匹配'],
    ['a.b.example.com', 'b.example.com', '父域不反向匹配'],
    ['login.example.com', 'other.example.com', '兄弟子域'],
    ['example.com', 'evilexample.com', '子串'],
    ['example.com', 'example.com.evil.com', '后缀拼接'],
    ['example.com', 'xn--exmple-cua.com', 'punycode 是另一个主机'],
    ['androidapp://example.com', 'example.com', '非网页协议'],
    ['ftp://example.com', 'example.com', '非网页协议'],
    ['javascript:alert(1)', 'example.com', '非网页协议'],
    ['example.com:8443', 'example.com', '手机看不到端口，写了非默认端口的不推荐'],
    ['http://example.com:8080', 'example.com', '手机看不到端口，写了非默认端口的不推荐'],
    ['co.uk', 'evil.co.uk', '公共后缀'],
    ['github.io', 'evil.github.io', '多租户后缀'],
    ['com', 'evil.com', '单段主机不做子域匹配'],
    ['example.com', 'example.com:8443', '系统给的不是纯主机名'],
    ['example.com:8443', 'example.com:8443', '系统给的不是纯主机名'],
    ['example.com', 'example.com/login', '系统给的不是纯主机名'],
    ['example.com', 'user@example.com', '系统给的不是纯主机名'],
    ['example.com', 'evil.com@example.com', '系统给的不是纯主机名'],
    ['example.com', 'https://example.com', '系统给的不是纯主机名'],
    ['example.com', '', '空'],
  ];
  it.each(no)('%s 不给 %s（%s）', (item, domain) => {
    expect(phone(item, domain)).toBe(null);
  });

  it('域名换成 https 默认端口的 origin', () => {
    expect(phoneOrigin('Example.COM')).toBe('https://example.com');
    expect(phoneOrigin('example.com:443')).toBe(null);
    expect(phoneOrigin('example.com.')).toBe('https://example.com.');
  });
});

describe('管道请求校验', () => {
  const o = 'https://example.com';
  it.each([
    [{ op: 'status' }],
    [{ op: 'list', origin: o }],
    [{ op: 'pick', origin: o }],
    [{ op: 'fill', origin: o, ref: 'vault_1/item-2' }],
  ])('接受 %j', (r) => {
    expect(parseBrowserRequest(r)).toEqual(r);
  });

  it.each([
    [null],
    ['status'],
    [[]],
    [{}],
    [{ op: 'dump' }],
    [{ op: 'exec', cmd: 'calc.exe' }],
    [{ op: 'status', origin: o }],
    [{ op: 'list' }],
    [{ op: 'list', origin: 'evil' }],
    [{ op: 'list', origin: `${o}/` }],
    [{ op: 'list', origin: o, extra: 1 }],
    [{ op: 'list', origin: 7 }],
    [{ op: 'pick', origin: o, ref: 'a/b' }],
    [{ op: 'fill', origin: o }],
    [{ op: 'fill', origin: o, ref: 'nope' }],
    [{ op: 'fill', origin: o, ref: 'a/b/c' }],
    [{ op: 'fill', origin: o, ref: '../x/y' }],
    [{ op: 'fill', origin: o, ref: 7 }],
    [{ op: 'fill', origin: o, ref: 'a/b', username: 'x' }],
  ])('拒绝 %j', (r) => {
    expect(parseBrowserRequest(r)).toBe(null);
  });
});

describe('桌面端处理扩展请求', () => {
  ready();
  const SITE = 'https://example.com';
  const PW = 'S3CRET-PASSWORD';
  let seq = 0;

  async function emptyVault(policy: Policy): Promise<Vault> {
    const author = { deviceId: 'dev-a', sign: keys().sign };
    return Vault.create(new MemoryKV(), { vaultId: `vault-${++seq}`, policy }, randomBytes(32), author, () => 7);
  }

  async function vaultWith(policy: Policy, title: string, urls: string[], password: string | undefined = PW) {
    const v = await emptyVault(policy);
    const data = { ...newItem('login', title), username: `${title}-user`, urls, ...(password ? { password } : {}) };
    const id = await saveItem(v, undefined, data);
    return { v, id, ref: `${v.id}/${id}`, data };
  }

  /** 记录界面被问了什么。 */
  function harness(vaults: Vault[], ui: Partial<BrowserFillUi> = {}) {
    const m = { phase: 'unlocked', openVaults: () => vaults };
    const asked: string[] = [];
    const svc = new BrowserFill(m, {
      confirm: async (_o, c) => {
        asked.push(c.ref);
        return true;
      },
      choose: async () => null,
      ...ui,
    });
    return { m, svc, asked };
  }

  const items = (r: BrowserReply) => ('items' in r ? r.items : []);

  it('未解锁什么都不给', async () => {
    const a = await vaultWith('cloud', 'a', [SITE]);
    const { m, svc, asked } = harness([a.v]);
    m.phase = 'locked';
    expect(await svc.handle({ op: 'status' })).toEqual({ ok: true, state: 'locked' });
    expect(await svc.handle({ op: 'list', origin: SITE })).toEqual({ ok: false, error: 'locked' });
    expect(await svc.handle({ op: 'fill', origin: SITE, ref: a.ref })).toEqual({ ok: false, error: 'locked' });
    expect(await svc.handle({ op: 'pick', origin: SITE })).toEqual({ ok: false, error: 'locked' });
    expect(asked).toEqual([]);
  });

  it('列表只有匹配的云库条目，没有密码', async () => {
    const good = await vaultWith('cloud', 'good', [SITE]);
    const other = await vaultWith('cloud', 'other', ['https://other.com']);
    const none = await vaultWith('cloud', 'nopass', [SITE], '');
    const local = await vaultWith('local', 'local', [SITE]);
    const cold = await vaultWith('cold', 'cold', [SITE]);
    const { svc } = harness([good.v, other.v, none.v, local.v, cold.v]);
    const r = await svc.handle({ op: 'list', origin: SITE });
    expect(items(r).map((i) => i.title)).toEqual(['good']);
    expect(JSON.stringify(r)).not.toContain(PW);
    expect(Object.keys(items(r)[0]!).sort()).toEqual(['ref', 'title', 'username']);
  });

  it('列表有上限', async () => {
    const v = await emptyVault('cloud');
    for (let i = 0; i < 60; i++) await saveItem(v, undefined, { ...newItem('login', `t${i}`), password: 'x', urls: [SITE] });
    const { svc } = harness([v]);
    expect(items(await svc.handle({ op: 'list', origin: SITE })).length).toBe(50);
  });

  it('确认后只给这一条', async () => {
    const a = await vaultWith('cloud', 'a', [SITE]);
    const b = await vaultWith('cloud', 'b', [SITE], 'OTHER-PASSWORD');
    const { svc, asked } = harness([a.v, b.v]);
    expect(await svc.handle({ op: 'fill', origin: SITE, ref: a.ref })).toEqual({ ok: true, username: 'a-user', password: PW });
    expect(asked).toEqual([a.ref]);
  });

  it('用户拒绝就没有密码', async () => {
    const a = await vaultWith('cloud', 'a', [SITE]);
    const { svc } = harness([a.v], { confirm: async () => false });
    expect(await svc.handle({ op: 'fill', origin: SITE, ref: a.ref })).toEqual({ ok: false, error: 'denied' });
  });

  it('拿别的站点的 ref 换不到密码，也不打扰用户', async () => {
    const a = await vaultWith('cloud', 'a', [SITE]);
    const { svc, asked } = harness([a.v]);
    for (const origin of ['https://evil.com', 'https://example.com.evil.com', 'http://example.com', 'https://example.com:8443']) {
      expect(await svc.handle({ op: 'fill', origin, ref: a.ref })).toEqual({ ok: false, error: 'no_match' });
    }
    expect(asked).toEqual([]);
  });

  it('不存在的 ref', async () => {
    const a = await vaultWith('cloud', 'a', [SITE]);
    const { svc } = harness([a.v]);
    expect(await svc.handle({ op: 'fill', origin: SITE, ref: `${a.v.id}/missing` })).toEqual({ ok: false, error: 'no_match' });
  });

  it('回收站里的条目不给', async () => {
    const a = await vaultWith('cloud', 'a', [SITE]);
    await saveItem(a.v, a.id, { ...a.data, trashedAt: Date.now() });
    const { svc } = harness([a.v]);
    expect(await svc.handle({ op: 'fill', origin: SITE, ref: a.ref })).toEqual({ ok: false, error: 'no_match' });
  });

  it('扩展不能直接点本地库条目，必须在桌面上选', async () => {
    const l = await vaultWith('local', 'l', [SITE]);
    const { svc, asked } = harness([l.v]);
    expect(await svc.handle({ op: 'fill', origin: SITE, ref: l.ref })).toEqual({ ok: false, error: 'no_match' });
    expect(asked).toEqual([]);
  });

  it('本地库在桌面选中后还要逐次确认', async () => {
    const l = await vaultWith('local', 'l', [SITE]);
    const seen: string[][] = [];
    const { svc, asked } = harness([l.v], {
      choose: async (_o, load) => {
        seen.push(load().map((c) => c.ref));
        return l.ref;
      },
    });
    expect(await svc.handle({ op: 'pick', origin: SITE })).toEqual({ ok: true, username: 'l-user', password: PW });
    expect(await svc.handle({ op: 'pick', origin: SITE })).toEqual({ ok: true, username: 'l-user', password: PW });
    expect(seen).toEqual([[l.ref], [l.ref]]);
    expect(asked).toEqual([l.ref, l.ref]);
  });

  it('桌面选中后拒绝确认', async () => {
    const l = await vaultWith('local', 'l', [SITE]);
    const { svc } = harness([l.v], { choose: async () => l.ref, confirm: async () => false });
    expect(await svc.handle({ op: 'pick', origin: SITE })).toEqual({ ok: false, error: 'denied' });
  });

  it('桌面取消选择', async () => {
    const l = await vaultWith('local', 'l', [SITE]);
    const { svc, asked } = harness([l.v]);
    expect(await svc.handle({ op: 'pick', origin: SITE })).toEqual({ ok: false, error: 'denied' });
    expect(asked).toEqual([]);
  });

  it('冷库和不匹配的条目不进桌面候选，也换不到密码', async () => {
    const cold = await vaultWith('cold', 'cold', [SITE]);
    const other = await vaultWith('local', 'other', ['https://other.com']);
    let seen: string[] = [];
    const { svc, asked } = harness([cold.v, other.v], {
      choose: async (_o, load) => {
        seen = load().map((c) => c.ref);
        return cold.ref;
      },
    });
    expect(await svc.handle({ op: 'pick', origin: SITE })).toEqual({ ok: false, error: 'no_match' });
    expect(seen).toEqual([]);
    expect(asked).toEqual([]);
    expect(await svc.handle({ op: 'fill', origin: SITE, ref: cold.ref })).toEqual({ ok: false, error: 'no_match' });
  });

  it('确认期间锁定不给密码', async () => {
    const a = await vaultWith('cloud', 'a', [SITE]);
    const box: { m?: { phase: string } } = {};
    const h = harness([a.v], {
      confirm: async () => {
        box.m!.phase = 'locked';
        return true;
      },
    });
    box.m = h.m;
    expect(await h.svc.handle({ op: 'fill', origin: SITE, ref: a.ref })).toEqual({ ok: false, error: 'locked' });
  });

  it('确认期间条目改了网址不给密码', async () => {
    const a = await vaultWith('cloud', 'a', [SITE]);
    const { svc } = harness([a.v], {
      confirm: async () => {
        await saveItem(a.v, a.id, { ...a.data, urls: ['https://moved.example.net'] });
        return true;
      },
    });
    expect(await svc.handle({ op: 'fill', origin: SITE, ref: a.ref })).toEqual({ ok: false, error: 'no_match' });
  });

  it('确认期间密码改了给新的', async () => {
    const a = await vaultWith('cloud', 'a', [SITE]);
    const { svc } = harness([a.v], {
      confirm: async () => {
        await saveItem(a.v, a.id, { ...a.data, password: 'NEW-PASSWORD' });
        return true;
      },
    });
    expect(await svc.handle({ op: 'fill', origin: SITE, ref: a.ref })).toEqual({ ok: true, username: 'a-user', password: 'NEW-PASSWORD' });
  });

  it('同时只有一个确认框', async () => {
    const a = await vaultWith('cloud', 'a', [SITE]);
    let release: (v: boolean) => void = () => undefined;
    const { svc } = harness([a.v], { confirm: () => new Promise((ok) => (release = ok)) });
    const first = svc.handle({ op: 'fill', origin: SITE, ref: a.ref });
    await new Promise((r) => setTimeout(r, 0));
    expect(await svc.handle({ op: 'fill', origin: SITE, ref: a.ref })).toEqual({ ok: false, error: 'busy' });
    expect(await svc.handle({ op: 'pick', origin: SITE })).toEqual({ ok: false, error: 'busy' });
    release(true);
    expect(await first).toMatchObject({ ok: true });
    expect(await svc.handle({ op: 'list', origin: SITE })).toMatchObject({ ok: true });
  });

  it('确认框出错后不永久占用', async () => {
    const a = await vaultWith('cloud', 'a', [SITE]);
    let boom = true;
    const { svc } = harness([a.v], {
      confirm: async () => {
        if (boom) throw new Error('ui');
        return true;
      },
    });
    await expect(svc.handle({ op: 'fill', origin: SITE, ref: a.ref })).rejects.toThrow('ui');
    boom = false;
    expect(await svc.handle({ op: 'fill', origin: SITE, ref: a.ref })).toMatchObject({ ok: true });
  });

  it('未知操作和多余字段不碰库', async () => {
    const a = await vaultWith('cloud', 'a', [SITE]);
    const { svc, asked } = harness([a.v]);
    for (const r of [{ op: 'dump' }, { op: 'fill', origin: SITE, ref: a.ref, force: true }, { op: 'list', origin: 'evil' }, null]) {
      expect(await svc.handle(r)).toEqual({ ok: false, error: 'bad_request' });
    }
    expect(asked).toEqual([]);
  });
});

describe('手机自动填充候选', () => {
  ready();
  let seq = 0;
  const PW = 'S3CRET-PASSWORD';

  async function vault(policy: Policy, items: [title: string, urls: string[], password?: string][]) {
    const author = { deviceId: 'dev-a', sign: keys().sign };
    const v = await Vault.create(new MemoryKV(), { vaultId: `phone-${++seq}`, policy }, randomBytes(32), author, () => 7);
    for (const [title, urls, password = PW] of items) {
      await saveItem(v, undefined, { ...newItem('login', title), username: `${title}-user`, urls, ...(password ? { password } : {}) });
    }
    return v;
  }
  const titles = (es: { item: { data: { title: string } } }[]) => es.map((e) => e.item.data.title).sort();

  it('网站推荐和电脑同一套规则：不反向匹配父域，不认非网页协议', async () => {
    const v = await vault('cloud', [
      ['exact', ['https://example.com/login']],
      ['parent', ['example.com']],
      ['child', ['login.example.com']],
      ['substr', ['evilexample.com']],
      ['app', ['androidapp://example.com']],
      ['port', ['example.com:8443']],
    ]);
    const top = phoneFillChoices([v], { target: 'example.com', kind: 'web' });
    expect(titles(top.suggested)).toEqual(['exact', 'parent']);
    expect(top.suggested.every((e) => e.match === 'exact')).toBe(true);
    const sub = phoneFillChoices([v], { target: 'login.example.com', kind: 'web' });
    expect(titles(sub.suggested)).toEqual(['child', 'exact', 'parent']);
    expect(sub.suggested.find((e) => e.item.data.title === 'parent')?.match).toBe('subdomain');
    // 不推荐的照样能手动搜到
    expect(titles(top.items)).toEqual(['app', 'child', 'exact', 'parent', 'port', 'substr']);
  });

  it('冷库按库策略排除，推荐和手动搜索里都没有', async () => {
    const cold = await vault('cold', [['cold', ['example.com']]]);
    const local = await vault('local', [['local', ['example.com']]]);
    const cloud = await vault('cloud', [['cloud', ['example.com']]]);
    const r = phoneFillChoices([cold, local, cloud], { target: 'example.com', kind: 'web' });
    expect(titles(r.items)).toEqual(['cloud', 'local']);
    expect(titles(r.suggested)).toEqual(['cloud', 'local']);
    expect(r.items.map((e) => [e.item.data.title, e.policy]).sort()).toEqual([
      ['cloud', 'cloud'],
      ['local', 'local'],
    ]);
  });

  it('没有密码的条目不出现', async () => {
    const v = await vault('cloud', [
      ['nopass', ['example.com'], ''],
      ['ok', ['example.com']],
    ]);
    const r = phoneFillChoices([v], { target: 'example.com', kind: 'web' });
    expect(titles(r.items)).toEqual(['ok']);
    expect(titles(r.suggested)).toEqual(['ok']);
  });

  it('App 来源不推荐，即使自报的名字像网站', async () => {
    const v = await vault('cloud', [['site', ['example.com']]]);
    for (const target of ['example.com', 'com.example.app']) {
      const r = phoneFillChoices([v], { target, kind: 'app' });
      expect(r.suggested).toEqual([]);
      expect(titles(r.items)).toEqual(['site']);
    }
  });

  it('系统给的域名不是纯主机名就不推荐', async () => {
    const v = await vault('cloud', [['site', ['example.com:8443']]]);
    expect(phoneFillChoices([v], { target: 'example.com:8443', kind: 'web' }).suggested).toEqual([]);
  });
});

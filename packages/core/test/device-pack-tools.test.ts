import { describe, expect, it } from 'vitest';
import {
  formatRecoveryCode,
  newPairCode,
  newRecoveryCode,
  normalizeCode,
  parsePairCode,
  parseRecoveryCode,
  rootKeysFrom,
  vaultRecoveryBox,
} from '../src/codes';
import {
  KDF_FLOOR,
  aeadOpen,
  aeadSeal,
  argon2id,
  assertKdfParams,
  b64e,
  randomBytes,
  utf8e,
} from '../src/crypto';
import { DeviceStore, SoftwareKeys } from '../src/device';
import { newItem } from '../src/model';
import {
  createPack,
  openPackWithBox,
  openPackWithCold,
  readPackHeader,
  type Snapshot,
} from '../src/pack';
import { MemoryKV } from '../src/store';
import {
  generatePassphrase,
  generatePassword,
  parseQuery,
  parseTotp,
  search,
  securityReport,
  strength,
  totpCode,
} from '../src/tools';
import {
  dedupeKey,
  detectAndImport,
  exportCsv,
  exportJson,
  importBitwardenJson,
  importCsv,
  markDuplicates,
  parseCsv,
} from '../src/transfer';
import type { ItemView } from '../src/model';
import { TEST_MEM, keys, makeDevice, ready } from './helpers';

ready();

describe('恢复码', () => {
  it('往返一致，校验位能发现抄错', () => {
    const rc = newRecoveryCode();
    expect(parseRecoveryCode(rc.text)).toEqual(rc.bytes);
    expect(parseRecoveryCode(rc.text.toLowerCase().replace(/-/g, ' '))).toEqual(rc.bytes);
    const flipped = rc.text.replace(/^./, (c) => (c === 'A' ? 'B' : 'A'));
    expect(() => parseRecoveryCode(flipped)).toThrow('bad_recovery_code');
    expect(() => parseRecoveryCode('short')).toThrow('bad_recovery_code');
  });

  it('易混淆字符容错', () => {
    expect(normalizeCode('o-i-l u')).toBe('011V');
  });

  it('同一恢复码派生固定的根，账户和本地库密钥互相独立', () => {
    const rc = newRecoveryCode();
    expect(rootKeysFrom(rc.bytes).sign.pub).toEqual(rootKeysFrom(rc.bytes).sign.pub);
    expect(rootKeysFrom(rc.bytes).box.pub).not.toEqual(vaultRecoveryBox(rc.bytes).pub);
    expect(formatRecoveryCode(rc.bytes)).toBe(rc.text);
  });

  it('配对码往返', () => {
    const p = newPairCode();
    const q = parsePairCode(p.text.toLowerCase());
    expect(q.pairId).toBe(p.pairId);
    expect(q.secret).toBe(p.secret);
    expect(p.secret).toHaveLength(18);
  });
});

describe('口令派生', () => {
  it('拒绝被改低的参数（防降级）', () => {
    const salt = b64e(randomBytes(16));
    expect(() => assertKdfParams({ salt, ops: 1, mem: KDF_FLOOR.mem })).toThrow();
    expect(() => assertKdfParams({ salt, ops: 3, mem: 1024 })).toThrow();
    expect(() => assertKdfParams({ salt, ops: 3, mem: 2 ** 40 })).toThrow();
    expect(() => assertKdfParams({ salt, ops: 3, mem: KDF_FLOOR.mem })).not.toThrow();
  });

  it('Unicode 等价写法得到相同密钥', () => {
    const p = { salt: b64e(randomBytes(16)), ops: 3, mem: TEST_MEM };
    expect(argon2id('ﬁ密码', p)).toEqual(argon2id('fi密码', p));
  });
});

describe('设备密钥库', () => {
  it('口令错误无法解锁；正确时得到相同身份', async () => {
    const { store, session } = await makeDevice('pw-1');
    await expect(store.unlock('wrong')).rejects.toThrow('wrong_passphrase');
    const s2 = await store.unlock('pw-1');
    expect(s2.sign.pub).toEqual(session.sign.pub);
    expect(s2.box.pub).toEqual(session.box.pub);
  });

  it('把数据目录复制到别的设备：知道口令也解不开', async () => {
    const { kv } = await makeDevice('pw-1');
    const otherHw = new SoftwareKeys(new MemoryKV());
    const copied = (await DeviceStore.load(kv, otherHw))!;
    await expect(copied.unlock('pw-1')).rejects.toThrow('device_binding_failed');
  });

  it('硬件密钥销毁后本地数据永久打不开', async () => {
    const { kv, hw, store } = await makeDevice('pw-1');
    await hw.destroy(store.installId);
    const again = (await DeviceStore.load(kv, hw))!;
    await expect(again.unlock('pw-1')).rejects.toThrow('device_binding_failed');
  });

  it('改口令后旧口令失效，身份不变', async () => {
    const { store, session } = await makeDevice('old');
    await store.changePassphrase(session, 'old', 'new');
    await expect(store.unlock('old')).rejects.toThrow('wrong_passphrase');
    expect((await store.unlock('new')).deviceId).toBe(session.deviceId);
  });

  it('改口令时旧口令错误被拒绝', async () => {
    const { store, session } = await makeDevice('old');
    await expect(store.changePassphrase(session, 'bad', 'new')).rejects.toThrow('wrong_passphrase');
  });

  it('每次安装都是新身份', async () => {
    const a = await makeDevice();
    const b = await makeDevice();
    expect(a.session.deviceId).not.toBe(b.session.deviceId);
  });

  it('设备秘密和解锁密钥不落盘为明文', async () => {
    const { kv, session } = await makeDevice('pw');
    const stored = Buffer.concat(kv.dump().map((b) => Buffer.from(b))).toString('latin1');
    expect(stored).not.toContain(Buffer.from(session.unlockKey).toString('latin1'));
  });
});

describe('Pack', () => {
  const snap = (): Snapshot => ({
    vaultId: 'v1',
    name: '重要',
    policy: 'local',
    exportedAt: 1,
    versions: [
      {
        id: 'x',
        parents: [],
        ts: 1,
        device: 'd',
        kind: 'item',
        obj: 'o',
        del: false,
        data: { title: 'PACK-SECRET' },
      },
    ],
  });

  it('密封给指定公钥，其他密钥打不开，文件里没有明文', () => {
    const k = keys();
    const bytes = createPack('backup', 1, snap(), [{ t: 'seal', to: k.box.pub }]);
    expect(Buffer.from(bytes).toString('latin1')).not.toContain('PACK-SECRET');
    expect(Buffer.from(bytes).toString('latin1')).not.toContain('重要');
    expect(openPackWithBox(bytes, k.box).versions[0]!.data).toEqual({ title: 'PACK-SECRET' });
    expect(() => openPackWithBox(bytes, keys().box)).toThrow('pack_wrong_key');
    expect(readPackHeader(bytes).count).toBe(1);
  });

  it('篡改头部或密文都被发现', () => {
    const k = keys();
    const bytes = createPack('backup', 1, snap(), [{ t: 'seal', to: k.box.pub }]);
    const body = bytes.slice();
    body[body.length - 1]! ^= 1;
    expect(() => openPackWithBox(body, k.box)).toThrow('pack_corrupt');
    const s = Buffer.from(bytes).toString('latin1').replace('"gen":1', '"gen":2');
    expect(() => openPackWithBox(Uint8Array.from(Buffer.from(s, 'latin1')), k.box)).toThrow('pack_corrupt');
  });

  it('冷库必须口令和恢复码都对', () => {
    const rc = newRecoveryCode();
    const bytes = createPack('cold', 1, snap(), [
      { t: 'pw', passphrase: 'cold-pass', code: rc.bytes, mem: TEST_MEM },
    ]);
    expect(openPackWithCold(bytes, 'cold-pass', rc.bytes).name).toBe('重要');
    expect(() => openPackWithCold(bytes, 'wrong', rc.bytes)).toThrow('pack_wrong_key');
    expect(() => openPackWithCold(bytes, 'cold-pass', newRecoveryCode().bytes)).toThrow('pack_wrong_key');
  });

  it('不是 Pack 的文件给出清楚错误', () => {
    expect(() => readPackHeader(utf8e('hello world, not a pack'))).toThrow('not_a_pack');
  });

  it('空库也能打包和打开', () => {
    const k = keys();
    const bytes = createPack('backup', 1, { ...snap(), versions: [] }, [{ t: 'seal', to: k.box.pub }]);
    expect(openPackWithBox(bytes, k.box).versions).toEqual([]);
  });
});

describe('AEAD', () => {
  it('关联数据不符解密失败', () => {
    const k = randomBytes(32);
    const { n, c } = aeadSeal(k, utf8e('x'), utf8e('a'));
    expect(() => aeadOpen(k, n, c, utf8e('b'))).toThrow();
  });
});

describe('密码生成', () => {
  it('长度和字符集符合要求，每类至少一个', () => {
    for (let i = 0; i < 50; i++) {
      const p = generatePassword({ length: 16, lower: true, upper: true, digits: true, symbols: true, unambiguous: false });
      expect(p).toHaveLength(16);
      expect(p).toMatch(/[a-z]/);
      expect(p).toMatch(/[A-Z]/);
      expect(p).toMatch(/[0-9]/);
      expect(p).toMatch(/[^a-zA-Z0-9]/);
    }
  });

  it('去除易混淆字符', () => {
    for (let i = 0; i < 50; i++) {
      const p = generatePassword({ length: 32, lower: true, upper: true, digits: true, symbols: false, unambiguous: true });
      expect(p).not.toMatch(/[0O1lI]/);
    }
  });

  it('不重复，口令短语词数正确', () => {
    expect(new Set(Array.from({ length: 100 }, () => generatePassword())).size).toBe(100);
    expect(generatePassphrase(5).split('-')).toHaveLength(5);
  });

  it('字符集均匀，没有明显的取模偏差', () => {
    const counts = new Map<string, number>();
    for (let i = 0; i < 4000; i++) {
      for (const ch of generatePassword({ length: 10, lower: false, upper: false, digits: true, symbols: false, unambiguous: false })) {
        counts.set(ch, (counts.get(ch) ?? 0) + 1);
      }
    }
    const vals = [...counts.values()];
    expect(vals).toHaveLength(10);
    expect(Math.max(...vals) / Math.min(...vals)).toBeLessThan(1.15);
  });
});

describe('强度', () => {
  it('常见弱密码低分，随机长密码高分', () => {
    expect(strength('123456').score).toBe(0);
    expect(strength('password').score).toBeLessThanOrEqual(1);
    expect(strength('aaaaaaaaaaaaaaaa').score).toBe(0);
    expect(strength(generatePassword()).score).toBeGreaterThanOrEqual(3);
    expect(strength('').score).toBe(0);
  });
});

describe('TOTP', () => {
  // RFC 6238 附录 B 测试向量
  const sha1Secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  it.each([
    [59, '94287082'],
    [1111111109, '07081804'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
  ])('RFC 6238 SHA1 t=%i', (t, code) => {
    const cfg = { ...parseTotp(sha1Secret), digits: 8 };
    expect(totpCode(cfg, t * 1000).code).toBe(code);
  });

  it('解析 otpauth URI', () => {
    const c = parseTotp(`otpauth://totp/x?secret=${sha1Secret}&digits=8&period=60&algorithm=SHA256`);
    expect(c).toMatchObject({ digits: 8, period: 60, algo: 'SHA256' });
  });

  it('非法种子报错', () => {
    expect(() => parseTotp('!!!')).toThrow('bad_totp');
  });
});

const view = (data: Partial<ItemView['data']>, vaultId = 'v'): ItemView => ({
  vaultId,
  id: Math.random().toString(),
  data: { ...newItem('login', 'T'), ...data },
  conflict: false,
  heads: [],
});

describe('搜索', () => {
  const items = [
    view({ title: '公司邮箱', username: 'wang', tags: ['生产'], env: 'production', urls: ['https://mail.example.com'] }),
    view({ title: 'GitHub', username: 'me', tags: ['开发'], favorite: true }),
    view({ title: '服务器', type: 'server', fields: [{ name: '主机', value: '10.0.0.1' }, { name: 'SSH 私钥', value: 'TOPSECRET', secret: true }] }),
  ];

  it('全文、标签、类型、环境、收藏组合', () => {
    expect(search(items, '邮箱')).toHaveLength(1);
    expect(search(items, 'MAIL.example')).toHaveLength(1);
    expect(search(items, 'tag:生产 env:production')).toHaveLength(1);
    expect(search(items, 'type:server')).toHaveLength(1);
    expect(search(items, 'is:fav')).toHaveLength(1);
    expect(search(items, '10.0.0.1')).toHaveLength(1);
    expect(search(items, '')).toHaveLength(3);
    expect(parseQuery('tag:"a b" x').tag).toEqual(['a b']);
  });

  it('不搜索机密字段和密码内容', () => {
    expect(search(items, 'TOPSECRET')).toHaveLength(0);
    expect(search([view({ title: 'x', password: 'hunter2' })], 'hunter2')).toHaveLength(0);
  });

  it('一万条数据在 300 毫秒内', () => {
    const many = Array.from({ length: 10000 }, (_, i) =>
      view({ title: `站点${i}`, username: `user${i}`, urls: [`https://s${i}.example.com`], notes: 'x'.repeat(200), tags: ['a', 'b'] }),
    );
    const t0 = performance.now();
    const r = search(many, 'user9999 tag:a');
    const ms = performance.now() - t0;
    expect(r).toHaveLength(1);
    expect(ms).toBeLessThan(300);
  });
});

describe('安全检查', () => {
  it('找出弱密码、重复、过期、曾上云', () => {
    const old = Date.now() - 400 * 86_400_000;
    const r = securityReport([
      view({ title: 'a', password: '123456' }),
      view({ title: 'b', password: 'Same-Str0ng-Passw0rd-XYZ!' }),
      view({ title: 'c', password: 'Same-Str0ng-Passw0rd-XYZ!', passwordChangedAt: old }),
      view({ title: 'd', cloudExposed: true }),
      view({ title: 'e', env: 'production' }),
    ]);
    expect(r.weak.map((i) => i.data.title)).toEqual(['a']);
    expect(r.reused).toHaveLength(1);
    expect(r.stale.map((i) => i.data.title)).toEqual(['c']);
    expect(r.exposed.map((i) => i.data.title)).toEqual(['d']);
    expect(r.noTotp.map((i) => i.data.title)).toEqual(['e']);
  });
});

describe('导入导出', () => {
  it('CSV 解析：引号、转义、换行、BOM', () => {
    expect(parseCsv('﻿a,"b,1","c""d"\r\n1,"line1\nline2",3\n')).toEqual([
      ['a', 'b,1', 'c"d'],
      ['1', 'line1\nline2', '3'],
    ]);
    expect(parseCsv('')).toEqual([]);
  });

  it('Chrome 导出格式', () => {
    const p = importCsv('name,url,username,password,note\nGitHub,https://github.com,me,pw,hello\n');
    expect(p.rows).toHaveLength(1);
    expect(p.rows[0]!.data).toMatchObject({
      title: 'GitHub',
      username: 'me',
      password: 'pw',
      urls: ['https://github.com'],
      notes: 'hello',
    });
  });

  it('KeePassXC 分组路径和未知列保留', () => {
    const p = importCsv('"Group","Title","Username","Password","URL","Notes","Custom"\n"Root/项目A/生产","X","u","p","","","kept"\n');
    expect(p.rows[0]!.folderPath).toBe('Root/项目A/生产');
    expect(p.rows[0]!.data.fields).toEqual([{ name: 'Custom', value: 'kept', secret: false }]);
  });

  it('中文表头', () => {
    const p = importCsv('名称,用户名,密码,网址,备注,分类\n公司,a,b,c.com,d,项目/系统\n');
    expect(p.rows[0]!.data.title).toBe('公司');
    expect(p.rows[0]!.folderPath).toBe('项目/系统');
  });

  it('零条、一条、多条', () => {
    expect(importCsv('name,password\n').rows).toEqual([]);
    expect(importCsv('name,password\na,b\n').rows).toHaveLength(1);
    expect(importCsv('name,password\na,b\nc,d\ne,f\n').rows).toHaveLength(3);
  });

  it('密码首尾空格保留，无法识别的文件报错', () => {
    expect(importCsv('name,password\na,"  pw  "\n').rows[0]!.data.password).toBe('  pw  ');
    expect(() => importCsv('foo,bar\n1,2\n')).toThrow('csv_unrecognized');
  });

  it('Bitwarden JSON', () => {
    const doc = {
      encrypted: false,
      folders: [{ id: 'f1', name: '工作' }],
      items: [
        {
          type: 1,
          name: 'A',
          folderId: 'f1',
          favorite: true,
          notes: 'n',
          login: { username: 'u', password: 'p', totp: 't', uris: [{ uri: 'https://a.com' }] },
          fields: [{ name: 'k', value: 'v', type: 1 }],
        },
        { type: 2, name: 'N', notes: 'note' },
        { type: 3, name: 'C', card: { number: '4111', code: '123', expMonth: '1', expYear: '30' } },
        { type: 4, name: 'identity-unsupported' },
      ],
    };
    const p = importBitwardenJson(JSON.stringify(doc));
    expect(p.rows).toHaveLength(3);
    expect(p.skipped).toBe(1);
    expect(p.rows[0]!.folderPath).toBe('工作');
    expect(p.rows[0]!.data.fields).toEqual([{ name: 'k', value: 'v', secret: true }]);
    expect(p.rows[2]!.data.fields!.find((f) => f.name === '卡号')!.secret).toBe(true);
    expect(() => importBitwardenJson('{"encrypted":true}')).toThrow('bitwarden_encrypted');
  });

  it('按内容自动识别格式', () => {
    expect(detectAndImport('x.txt', '{"items":[]}').format).toBe('Bitwarden JSON');
    expect(detectAndImport('x.csv', 'name,password\n').format).toBe('CSV');
  });

  it('去重不改动原数据', () => {
    const rows = importCsv('name,username,password\na,b,c\na,b,c\nd,e,f\n').rows;
    const existing = [view({ title: 'd', username: 'e', password: 'f' })];
    const { fresh, dupes } = markDuplicates(rows, existing);
    expect(fresh).toHaveLength(1);
    expect(dupes).toHaveLength(2);
    expect(dedupeKey(rows[0]!.data)).toBe(dedupeKey(rows[1]!.data));
  });

  it('导出后再导入，字段不丢', () => {
    const it0 = view({ title: 'T,"x"', username: 'u', password: 'p,1', urls: ['https://a.com'], notes: '多行\n备注', tags: ['a', 'b'] });
    const csv = exportCsv([it0], () => 'F/G');
    const back = importCsv(csv).rows[0]!;
    expect(back.data).toMatchObject({ title: 'T,"x"', username: 'u', password: 'p,1', notes: '多行\n备注', tags: ['a', 'b'] });
    expect(back.folderPath).toBe('F/G');
    const j = JSON.parse(exportJson([it0], () => 'V'));
    expect(j.items[0].password).toBe('p,1');
    expect(JSON.parse(exportJson([], () => 'V')).items).toEqual([]);
  });
});

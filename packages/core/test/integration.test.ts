/**
 * 真实 Go 服务端上的端到端验收，对应研究报告 15.1。
 * 中间夹一层可编程的代理，模拟被控制的服务器。不依赖任何真实数据。
 */
import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { createHash, randomBytes as nodeRandom } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { ApiError, ServerApi, type HttpRequest, type HttpResponse } from '../src/api';
import { newRecoveryCode, rootKeysFrom } from '../src/codes';
import { b64d, b64e, boxSeal, initCrypto, randomBytes, utf8d, utf8e } from '../src/crypto';
import { SoftwareKeys } from '../src/device';
import { IntegrityAlarm, MixiaError } from '../src/errors';
import { nextBody, replay, signEntry } from '../src/ledger';
import { Mixia, type PlatformEnv } from '../src/mixia';
import { getItem, listItems, newItem, purgeItem, saveFolder, saveItem } from '../src/model';
import { MemoryKV } from '../src/store';
import { parseBlob, sealChange, type ChangeRecord, type Vault, type Version } from '../src/vault';
import { deviceFingerprint } from '../src/sync';
import { TEST_MEM, keys } from './helpers';

const BIN = resolve(__dirname, '../../../server/dist/mixia-server-test.exe');
const hasServer = existsSync(BIN);

type Tap = (req: HttpRequest, next: () => Promise<HttpResponse>) => Promise<HttpResponse>;

class Harness {
  proc!: ChildProcess;
  url = '';
  dir = '';
  token = '';
  port = 0;
  /** 被控制的服务器：拦截并篡改响应。 */
  tap: Tap | undefined;
  /** 记录所有发往服务器的字节，用来证明本地库内容从未离开。 */
  wire: { url: string; headers: string; body: Uint8Array }[] = [];

  async start() {
    await initCrypto();
    const port = await new Promise<number>((ok) => {
      const s = createServer();
      s.listen(0, '127.0.0.1', () => {
        const p = (s.address() as { port: number }).port;
        s.close(() => ok(p));
      });
    });
    this.port = port;
    this.dir = mkdtempSync(join(tmpdir(), 'mixia-it-'));
    this.url = `http://127.0.0.1:${port}`;
    this.token = nodeRandom(24).toString('hex');
    await this.launch();
  }

  async restart() {
    await new Promise<void>((ok) => {
      this.proc.once('exit', () => ok());
      this.proc.kill();
    });
    // 服务端拒绝启动时间之前的时间戳，给时钟留一点余量
    await new Promise((r) => setTimeout(r, 50));
    await this.launch();
  }

  private async launch() {
    this.proc = spawn(BIN, ['serve'], {
      env: {
        ...process.env,
        MIXIA_ADDR: `127.0.0.1:${this.port}`,
        MIXIA_DATA: this.dir,
        MIXIA_BOOTSTRAP_TOKEN_SHA256: createHash('sha256').update(this.token).digest('hex'),
        MIXIA_RATE_RPS: '100000',
        MIXIA_RATE_BURST: '100000',
      },
      stdio: 'ignore',
    });
    for (let i = 0; i < 100; i++) {
      try {
        if ((await fetch(`${this.url}/healthz`)).ok) return;
      } catch {
        /* 还没起来 */
      }
      await new Promise((r) => setTimeout(r, 50));
    }
    throw new Error('server did not start');
  }

  stop() {
    this.proc?.kill();
    rmSync(this.dir, { recursive: true, force: true, maxRetries: 5 });
  }

  raw = async (r: HttpRequest): Promise<HttpResponse> => {
    const res = await fetch(r.url, {
      method: r.method,
      headers: r.headers,
      ...(r.body ? { body: r.body as BodyInit } : {}),
    });
    return { status: res.status, body: new Uint8Array(await res.arrayBuffer()) };
  };

  http = async (r: HttpRequest): Promise<HttpResponse> => {
    this.wire.push({ url: r.url, headers: JSON.stringify(r.headers), body: r.body ?? new Uint8Array() });
    return this.tap ? this.tap(r, () => this.raw(r)) : this.raw(r);
  };

  /** 每台“设备”有自己独立的存储和密钥。 */
  env(name: string, opts: { level?: 'hardware' | 'software' } = {}): PlatformEnv {
    const stores = new Map<string, MemoryKV>();
    const hwKv = new MemoryKV();
    const hw = new SoftwareKeys(hwKv);
    Object.defineProperty(hw, 'level', { value: opts.level ?? 'hardware' });
    return {
      hw,
      http: this.http,
      openKV: (n) => {
        let kv = stores.get(n);
        if (!kv) stores.set(n, (kv = new MemoryKV()));
        return kv;
      },
      info: { platform: 'test', defaultName: name, kdfMem: TEST_MEM },
    };
  }
}

const PASS = 'correct-horse-battery';
const h = new Harness();

async function owner(name = '电脑') {
  const m = await Mixia.boot(h.env(name));
  const { recoveryCode } = await m.createOwner({ serverUrl: h.url, token: h.token, passphrase: PASS });
  await m.syncNow();
  return { m, recoveryCode, vault: m.openVaults()[0]! };
}

async function join2(admin: Mixia, name = '手机', opts: { role?: 'admin' | 'member'; vaults?: string[] } = {}) {
  const m = await Mixia.boot(h.env(name));
  const p = await admin.startPairing();
  const j = await m.beginJoin(h.url, p.code);
  await m.submitJoin(j, PASS, name);
  const pending = await admin.pollPairing(p.pairId, p.secret);
  await admin.approvePairing(p.pairId, p.secret, pending!, {
    role: opts.role ?? 'member',
    vaults: opts.vaults ?? admin.vaults().filter((v) => v.policy === 'cloud').map((v) => v.id),
  });
  expect(await m.finishJoin(j)).toBe(true);
  return m;
}

const add = (v: Vault, title: string, password = 'pw') =>
  saveItem(v, undefined, { ...newItem('login', title), username: 'u', password });

async function bothSync(...ms: Mixia[]) {
  for (const m of ms) await m.syncNow();
  for (const m of ms) await m.syncNow();
}

describe.skipIf(!hasServer)('端到端（真实服务端）', () => {
  beforeAll(() => initCrypto());

  beforeEach(async () => {
    await h.start();
    h.tap = undefined;
    h.wire = [];
  });

  afterEach(() => h.stop());

  it('创建、配对、同步：第二台设备读到内容，服务器和线路上只有密文', async () => {
    const { m, vault } = await owner();
    const id = await saveItem(vault, undefined, {
      ...newItem('login', 'WIRE-TITLE-MARKER'),
      username: 'WIRE-USER-MARKER',
      password: 'WIRE-PASSWORD-MARKER',
    });
    await m.syncNow();
    const phone = await join2(m);
    const pv = phone.openVaults()[0]!;
    expect(getItem(pv, id)!.data.password).toBe('WIRE-PASSWORD-MARKER');
    const allBytes = Buffer.concat(h.wire.map((w) => Buffer.from(w.body))).toString('latin1');
    expect(allBytes).not.toContain('WIRE-');
    expect(allBytes).not.toContain(PASS);
    // 服务器落盘文件同样没有
    const { readdirSync, readFileSync } = await import('node:fs');
    for (const f of readdirSync(h.dir)) {
      if (f.endsWith('.db') || f.endsWith('-wal')) {
        expect(readFileSync(join(h.dir, f)).toString('latin1')).not.toContain('WIRE-');
      }
    }
  });

  it('密钥条目跨设备同步：新字段和换下的旧值都不丢，线路上只有密文', async () => {
    const { m, vault } = await owner();
    const phone = await join2(m);
    const pv = phone.openVaults()[0]!;
    const field = (value: string) => ({ name: 'API Key', value, secret: true, envName: 'ENV_NAME_MARKER' });
    const id = await saveItem(vault, undefined, {
      ...newItem('api', 'TITLE-MARKER'),
      provider: 'PROVIDER-MARKER',
      expiresAt: 1_900_000_000_000,
      rotateDays: 90,
      usedBy: ['USEDBY-MARKER'],
      fields: [field('VALUE-ONE-MARKER')],
    });
    await saveItem(vault, id, { ...getItem(vault, id)!.data, fields: [field('VALUE-TWO-MARKER')] });
    await bothSync(m, phone);
    const got = getItem(pv, id)!.data;
    expect(got).toMatchObject({
      type: 'api',
      provider: 'PROVIDER-MARKER',
      expiresAt: 1_900_000_000_000,
      rotateDays: 90,
      usedBy: ['USEDBY-MARKER'],
    });
    expect(got.fields).toEqual([field('VALUE-TWO-MARKER')]);
    expect(got.passwordHistory?.[0]).toMatchObject({ value: 'VALUE-ONE-MARKER', field: 'API Key' });

    // 手机上换密钥，电脑能看到新值和完整历史
    await saveItem(pv, id, { ...got, fields: [field('VALUE-THREE-MARKER')] });
    await bothSync(phone, m);
    const back = getItem(vault, id)!.data;
    expect(back.fields).toEqual([field('VALUE-THREE-MARKER')]);
    expect(back.passwordHistory?.map((p) => p.value)).toEqual(['VALUE-TWO-MARKER', 'VALUE-ONE-MARKER']);

    expect(Buffer.concat(h.wire.map((w) => Buffer.from(w.body))).toString('latin1')).not.toContain('MARKER');
  });

  it('双向同步，幂等：重复推送不产生重复条目', async () => {
    const { m, vault } = await owner();
    const phone = await join2(m);
    await add(phone.openVaults()[0]!, 'from-phone');
    await add(vault, 'from-pc');
    await bothSync(m, phone);
    expect(listItems(vault)).toHaveLength(2);
    expect(listItems(phone.openVaults()[0]!)).toHaveLength(2);
    expect(m.syncStatus.state).toBe('idle');
  });

  it('只有密码或账号：没有任何入口。未签名请求全部被拒', async () => {
    await owner();
    const anon = new ServerApi(h.url, h.raw);
    await expect(anon.getLedger(0)).rejects.toThrow(MixiaError);
    const r = await h.raw({ method: 'GET', url: `${h.url}/v1/ledger?from=0`, headers: {} });
    expect(r.status).toBe(401);
    const login = await h.raw({
      method: 'POST',
      url: `${h.url}/v1/login`,
      headers: {},
      body: utf8e(JSON.stringify({ password: PASS })),
    });
    expect(login.status).toBe(404);
  });

  it('陌生设备自己生成密钥来请求：不在账本上一律 401', async () => {
    await owner();
    const stranger = await Mixia.boot(h.env('陌生人'));
    const hw = new SoftwareKeys(new MemoryKV());
    await hw.create('x');
    const api = new ServerApi(h.url, h.raw, { id: 'AAAAAAAAAAAAAAAAAAAAAA', sign: (m) => hw.sign('x', m) });
    await api.info();
    await expect(api.getLedger(0)).rejects.toMatchObject({ status: 401 });
    expect(stranger.phase).toBe('fresh');
  });

  it('服务器伪造新设备：客户端拒绝并告警，不接受这台设备', async () => {
    const { m } = await owner();
    const attacker = rootKeysFrom(newRecoveryCode().bytes);
    h.tap = async (req, next) => {
      const res = await next();
      if (!req.url.includes('/v1/ledger')) return res;
      const j = JSON.parse(utf8d(res.body));
      const st = replay(m.book.entries);
      const evil = signEntry(
        nextBody(
          st,
          'device_add',
          {
            deviceId: 'AAAA',
            name: 'evil',
            platform: 'x',
            level: 'hardware',
            role: 'admin',
            authPub: b64e(randomBytes(65)),
            signPub: b64e(attacker.sign.pub),
            boxPub: b64e(attacker.box.pub),
            vaults: [],
          },
          'root',
        ),
        attacker.sign,
      );
      j.entries.push(evil);
      j.head += 1;
      return { status: 200, body: utf8e(JSON.stringify(j)) };
    };
    await m.syncNow();
    expect(m.syncStatus.state).toBe('alarm');
    expect(m.devices().map((d) => d.name)).not.toContain('evil');
  });

  it('服务器回滚账本：客户端发现回退并停止写入', async () => {
    const { m, vault } = await owner();
    const phone = await join2(m);
    await bothSync(m, phone);
    h.tap = async (req, next) => {
      if (req.url.includes('/v1/ledger')) {
        return { status: 200, body: utf8e(JSON.stringify({ entries: [], head: 0 })) };
      }
      return next();
    };
    await add(vault, 'after-rollback');
    await m.syncNow();
    expect(m.syncStatus).toMatchObject({ state: 'alarm', alarm: { code: 'ledger_rollback' } });
    expect(await m.pendingCount()).toBe(1);
    // 告警期间不再尝试写入
    h.wire = [];
    h.tap = undefined;
    await m.syncNow();
    expect(h.wire).toHaveLength(0);
    // 用户确认后恢复
    await m.acknowledgeAlarm();
    await m.syncNow();
    expect(m.syncStatus.state).toBe('idle');
    expect(await m.pendingCount()).toBe(0);
  });

  /** 只改账本响应里的某一部分，让每层检查单独起作用，互相不掩盖。 */
  const ledgerTap =
    (edit: (j: { entries: unknown[]; head: number }) => void): Tap =>
    async (req, next) => {
      const res = await next();
      if (!req.url.includes('/v1/ledger')) return res;
      const j = JSON.parse(utf8d(res.body));
      edit(j);
      return { status: 200, body: utf8e(JSON.stringify(j)) };
    };

  it('服务器谎报更小的 head，条目却是对的：单独发现回退', async () => {
    const { m } = await owner();
    h.tap = ledgerTap((j) => {
      j.head = 0;
    });
    await m.syncNow();
    expect(m.syncStatus).toMatchObject({ state: 'alarm', alarm: { code: 'ledger_rollback' } });
  });

  it('服务器 head 不变但不返回本机已确认的条目：单独发现', async () => {
    const { m } = await owner();
    h.tap = ledgerTap((j) => {
      j.entries = [];
    });
    await m.syncNow();
    expect(m.syncStatus).toMatchObject({ state: 'alarm', alarm: { code: 'ledger_rollback' } });
  });

  it('账本分叉：同一序号换成另一条，被发现', async () => {
    const { m } = await owner();
    const other = m.book.entries[0]!;
    h.tap = ledgerTap((j) => {
      j.entries[0] = other;
    });
    await m.syncNow();
    expect(m.syncStatus).toMatchObject({ state: 'alarm', alarm: { code: 'ledger_fork' } });
  });

  it('变更签名被破坏：拒绝，内容不进入本机', async () => {
    const { m, vault } = await owner();
    const phone = await join2(m);
    await add(vault, 'signed');
    await m.syncNow();
    h.tap = async (req, next) => {
      const res = await next();
      if (!req.url.includes('/changes?')) return res;
      const j = JSON.parse(utf8d(res.body));
      for (const c of j.changes) {
        const o = JSON.parse(utf8d(b64d(c.blob)));
        const sig = b64d(o.s);
        sig[0]! ^= 1;
        o.s = b64e(sig);
        c.blob = b64e(utf8e(JSON.stringify(o)));
      }
      return { status: 200, body: utf8e(JSON.stringify(j)) };
    };
    await phone.syncNow();
    expect(phone.syncStatus).toMatchObject({ state: 'alarm', alarm: { code: 'change_bad_signature' } });
    expect(listItems(phone.openVaults()[0]!)).toHaveLength(0);
  });

  it('持有库密钥的人冒充别的设备写入：签名对不上', async () => {
    const { m, vault } = await owner();
    const phone = await join2(m);
    const forge = (deviceId: string) => {
      const v: Version = { id: 'FORGED', parents: [], ts: 1, device: deviceId, kind: 'item', obj: 'o', del: false, data: { title: 'forged' } };
      const author = { deviceId, sign: keys().sign };
      return sealChange(vault.vaultKey, { vaultId: vault.id, gen: 1, counter: 1, ledgerSeq: 0 }, author, v);
    };
    const serve = (rec: ChangeRecord, device: string): Tap => async (req, next) => {
      const res = await next();
      if (!req.url.includes('/changes?')) return res;
      const j = JSON.parse(utf8d(res.body));
      j.changes = [{ ...rec, device, seq: j.head + 1 }];
      j.head += 1;
      return { status: 200, body: utf8e(JSON.stringify(j)) };
    };
    h.tap = serve(forge(m.deviceId!), m.deviceId!);
    await phone.syncNow();
    expect(phone.syncStatus).toMatchObject({ state: 'alarm', alarm: { code: 'change_bad_signature' } });

    await phone.acknowledgeAlarm();
    h.tap = serve(forge('ROGUE'), 'ROGUE');
    await phone.syncNow();
    expect(phone.syncStatus).toMatchObject({ state: 'alarm', alarm: { code: 'change_unknown_author' } });
    expect(listItems(phone.openVaults()[0]!)).toHaveLength(0);
  });

  it('服务器谎报更旧的库代数：停止', async () => {
    const { m, vault } = await owner();
    h.tap = async (req, next) => {
      const res = await next();
      if (!req.url.includes('/changes?')) return res;
      const j = JSON.parse(utf8d(res.body));
      j.gen = 0;
      return { status: 200, body: utf8e(JSON.stringify(j)) };
    };
    await m.syncNow();
    expect(m.syncStatus).toMatchObject({ state: 'alarm', alarm: { code: 'gen_rollback' } });
    expect(vault.gen).toBe(1);
  });

  it('本地状态比账本新（异常）：停止而不是降级', async () => {
    const { m, vault } = await owner();
    m.ledger.vaults.get(vault.id)!.gen = 0;
    await m.syncNow();
    expect(m.syncStatus).toMatchObject({ state: 'alarm', alarm: { code: 'gen_rollback' } });
  });

  it('服务器隐瞒中间一条变更：跳号被发现', async () => {
    const { m, vault } = await owner();
    const phone = await join2(m);
    await add(vault, 'a');
    await add(vault, 'b');
    await add(vault, 'c');
    await m.syncNow();
    h.tap = async (req, next) => {
      const res = await next();
      if (!req.url.includes('/changes?')) return res;
      const j = JSON.parse(utf8d(res.body));
      if (j.changes.length >= 3) j.changes.splice(1, 1);
      return { status: 200, body: utf8e(JSON.stringify(j)) };
    };
    await phone.syncNow();
    expect(phone.syncStatus).toMatchObject({ state: 'alarm', alarm: { code: 'change_withheld' } });
  });

  it('服务器替换库密钥封装：keyCommit 校验失败，不使用攻击者的密钥', async () => {
    const { m } = await owner();
    const phone = await Mixia.boot(h.env('手机'));
    const p = await m.startPairing();
    const j = await phone.beginJoin(h.url, p.code);
    await phone.submitJoin(j, PASS);
    const dev = await m.pollPairing(p.pairId, p.secret);
    await m.approvePairing(p.pairId, p.secret, dev!, {
      role: 'member',
      vaults: m.openVaults().map((v) => v.id),
    });
    const evilKey = randomBytes(32);
    h.tap = async (req, next) => {
      const res = await next();
      if (!req.url.endsWith('/keys') || req.method !== 'GET') return res;
      const body = JSON.parse(utf8d(res.body));
      for (const k of body.keys) k.wrapped = b64e(boxSeal(b64d(dev!.raw.boxPub), evilKey));
      return { status: 200, body: utf8e(JSON.stringify(body)) };
    };
    await phone.finishJoin(j);
    expect(phone.syncStatus).toMatchObject({ state: 'alarm', alarm: { code: 'key_commit_mismatch' } });
    expect(phone.openVaults()).toHaveLength(0);
  });

  it('配对：服务器换掉 offer 被发现；错误配对码打不开', async () => {
    const { m } = await owner();
    const p = await m.startPairing();
    const n = await Mixia.boot(h.env('新设备'));
    const flipped = (p.code[0] === 'A' ? 'B' : 'A') + p.code.slice(1);
    await expect(n.beginJoin(h.url, flipped)).rejects.toBeInstanceOf(ApiError);
    const wrongSecret = p.code.slice(0, -1) + (p.code.endsWith('0') ? '1' : '0');
    await expect(n.beginJoin(h.url, wrongSecret)).rejects.toMatchObject({ status: 401 });
    h.tap = async (req, next) => {
      const res = await next();
      if (!req.url.includes('/v1/pair/')) return res;
      const j = JSON.parse(utf8d(res.body));
      j.offer = b64e(randomBytes(120));
      return { status: 200, body: utf8e(JSON.stringify(j)) };
    };
    await expect(n.beginJoin(h.url, p.code)).rejects.toThrow('pair_tampered');
  });

  it('新设备钉住的信任根和服务器不一致：拒绝加入', async () => {
    const { m } = await owner();
    const n = await Mixia.boot(h.env('手机'));
    const p = await m.startPairing();
    const j = await n.beginJoin(h.url, p.code);
    await n.submitJoin(j, PASS);
    const dev = await m.pollPairing(p.pairId, p.secret);
    await m.approvePairing(p.pairId, p.secret, dev!, { role: 'member', vaults: [] });
    await expect(n.finishJoin({ ...j, genesisHash: 'AAAA' })).rejects.toThrow('genesis_mismatch');
    // 失败的加入不能留下错误的钉住值
    expect(await n.book.pinned()).toBeUndefined();
  });

  it('撤销：旧设备立刻被拒，换钥后读不到新内容，剩余设备无感继续', async () => {
    const { m, vault } = await owner();
    const lost = await join2(m, '丢失的手机');
    const tablet = await join2(m, '平板');
    await add(vault, 'before-revoke');
    await bothSync(m, lost, tablet);
    const oldKey = lost.openVaults()[0]!.vaultKey.slice();

    await m.revokeDevice(lost.deviceId!, '丢了');
    expect(vault.gen).toBe(2);
    expect(m.ledger.vaultsNeedingRotation()).toEqual([]);
    await add(vault, 'after-revoke-SECRET');
    await m.syncNow();

    await lost.syncNow();
    expect(lost.syncStatus).toMatchObject({ state: 'error', error: 'unauthorized' });

    await tablet.syncNow();
    const tv = tablet.openVaults()[0]!;
    expect(tv.gen).toBe(2);
    expect(listItems(tv).map((i) => i.data.title).sort()).toEqual(['after-revoke-SECRET', 'before-revoke']);

    // 即使旧设备偷到新密文，旧密钥也解不开
    const api = m.api!;
    const { changes } = await api.getChanges(vault.id, 0);
    const { decryptBlob } = await import('../src/vault');
    for (const c of changes) {
      expect(() => decryptBlob(parseBlob(c.blob), oldKey)).toThrow();
    }
  });

  it('离线设备的修改在别的设备换钥后不丢', async () => {
    const { m, vault } = await owner();
    const phone = await join2(m);
    const other = await join2(m, '要撤销的设备');
    const id = await add(vault, 'base');
    await bothSync(m, phone);
    const pv = phone.openVaults()[0]!;
    await saveItem(pv, id, { ...getItem(pv, id)!.data, password: 'offline-edit' });
    await m.revokeDevice(other.deviceId!);
    await phone.syncNow();
    expect(pv.gen).toBe(2);
    await bothSync(m, phone);
    expect(getItem(vault, id)!.data.password).toBe('offline-edit');
    expect(phone.syncStatus.state).toBe('idle');
  });

  it('换钥快照被篡改：校验失败', async () => {
    const { m, vault } = await owner();
    const phone = await join2(m);
    const other = await join2(m, 'x');
    await add(vault, 'a');
    await bothSync(m, phone);
    await m.revokeDevice(other.deviceId!);
    h.tap = async (req, next) => {
      const res = await next();
      if (!req.url.includes('/changes?')) return res;
      const j = JSON.parse(utf8d(res.body));
      j.changes = j.changes.slice(1);
      return { status: 200, body: utf8e(JSON.stringify(j)) };
    };
    await phone.syncNow();
    expect(phone.syncStatus.state).toBe('alarm');
  });

  it('换钥快照数量对但内容被调换：哈希校验失败', async () => {
    const { m, vault } = await owner();
    const phone = await join2(m);
    const other = await join2(m, 'x');
    await add(vault, 'a');
    await add(vault, 'b');
    await bothSync(m, phone);
    await m.revokeDevice(other.deviceId!);
    h.tap = async (req, next) => {
      const res = await next();
      if (!req.url.includes('/changes?')) return res;
      const j = JSON.parse(utf8d(res.body));
      if (j.changes.length >= 2) [j.changes[0], j.changes[1]] = [j.changes[1], j.changes[0]];
      return { status: 200, body: utf8e(JSON.stringify(j)) };
    };
    await phone.syncNow();
    expect(phone.syncStatus).toMatchObject({ state: 'alarm', alarm: { code: 'snapshot_tampered' } });
    expect(phone.openVaults()[0]!.gen).toBe(1);
  });

  it('离线并发修改与删除：通过服务器后依然保留冲突', async () => {
    const { m, vault } = await owner();
    const phone = await join2(m);
    const id = await add(vault, 'x');
    await bothSync(m, phone);
    const pv = phone.openVaults()[0]!;
    await saveItem(vault, id, { ...getItem(vault, id)!.data, password: 'pc' });
    await purgeItem(pv, id);
    await bothSync(m, phone);
    for (const v of [vault, pv]) {
      expect(getItem(v, id)!.conflict).toBe(true);
      expect(getItem(v, id)!.data.password).toBe('pc');
    }
  });

  it('重要本地库全路径：名称、条目、ID 都不离开设备', async () => {
    const { m, vault } = await owner();
    h.wire = [];
    const { vaultId } = await m.createLocalVault('LOCAL-VAULT-NAME', PASS);
    const lv = m.vault(vaultId);
    const fid = await saveFolder(lv, undefined, 'LOCAL-FOLDER', null);
    const id = await saveItem(lv, undefined, {
      ...newItem('login', 'LOCAL-TITLE'),
      username: 'LOCAL-USER',
      password: 'LOCAL-PASSWORD',
      folder: fid,
    });
    const ref = await lv.putAttachment(utf8e('LOCAL-ATTACHMENT'), 'LOCAL-FILE.txt', 'text/plain');
    await saveItem(lv, id, { ...getItem(lv, id)!.data, attachments: [ref] });
    await add(vault, 'cloud-item');
    await m.syncNow();
    await m.syncNow();

    const bytes = Buffer.concat(h.wire.map((w) => Buffer.concat([Buffer.from(w.url), Buffer.from(w.headers), Buffer.from(w.body)]))).toString('latin1');
    expect(bytes).not.toContain('LOCAL-');
    expect(bytes).not.toContain(vaultId);
    expect(bytes).not.toContain(id);
    expect(bytes).not.toContain(fid);
    expect(m.ledger.vaults.has(vaultId)).toBe(false);
    expect(h.wire.some((w) => w.url.includes(vaultId))).toBe(false);

    // 代码错误地把本地库传给上传接口：第二道闸拦下
    expect(() => m.api!.pushChanges(lv, [])).toThrow('policy_blocks_upload');
    expect(() => m.api!.putBlob(lv, 'x', new Uint8Array(1))).toThrow('policy_blocks_upload');
    expect(() => m.api!.getBlob(lv, 'x')).toThrow('policy_blocks_upload');
  });

  it('本地库独立口令：主口令打不开；重新解锁后数据还在；软件级设备不允许创建', async () => {
    const { m } = await owner();
    const { vaultId } = await m.createLocalVault('重要', 'local-vault-passphrase');
    const id = await add(m.vault(vaultId), 'top-secret');
    m.lockLocalVault(vaultId);
    expect(() => m.vault(vaultId)).toThrow('vault_locked');
    await expect(m.unlockLocalVault(vaultId, PASS)).rejects.toThrow('wrong_passphrase');
    await m.unlockLocalVault(vaultId, 'local-vault-passphrase');
    expect(getItem(m.vault(vaultId), id)!.data.title).toBe('top-secret');

    const weak = await Mixia.boot(h.env('软件设备', { level: 'software' }));
    const p = await m.startPairing();
    const j = await weak.beginJoin(h.url, p.code);
    await weak.submitJoin(j, PASS);
    const dev = await m.pollPairing(p.pairId, p.secret);
    await m.approvePairing(p.pairId, p.secret, dev!, { role: 'member', vaults: [] });
    await weak.finishJoin(j);
    await expect(weak.createLocalVault('x', PASS)).rejects.toThrow('hardware_required');
  });

  it('本地库备份与设备传输：只有恢复码或目标设备能开；快照只读', async () => {
    const { m } = await owner();
    const phone = await join2(m);
    const { vaultId, recoveryCode } = await m.createLocalVault('重要', PASS);
    await add(m.vault(vaultId), 'root-password', 'R00T');

    const backup = await m.exportBackup(vaultId);
    expect(m.verifyBackup(backup, recoveryCode)).toMatchObject({ name: '重要', count: 1 });
    expect(() => m.verifyBackup(backup, newRecoveryCode().text)).toThrow('pack_wrong_key');
    expect(m.vaults().find((v) => v.id === vaultId)!.lastBackupAt).toBeGreaterThan(0);

    const pack = await m.exportTransfer(vaultId, phone.deviceId!);
    const r = await phone.importTransfer(pack, PASS);
    expect(r).toMatchObject({ count: 1, name: '重要' });
    const snap = phone.vault(r.vaultId);
    expect(snap.readOnly).toBe(true);
    await expect(add(snap, 'nope')).rejects.toThrow('vault_read_only');
    await expect(m.importTransfer(pack, PASS)).rejects.toThrow('pack_wrong_key');

    const fresh = await owner2();
    const restored = await fresh.restoreBackup(backup, recoveryCode, PASS);
    expect(restored.count).toBe(1);
    expect(listItems(fresh.vault(restored.vaultId))[0]!.data.password).toBe('R00T');
  });

  /** 另一个独立账户上的设备：证明备份恢复不依赖原账户和原服务器。 */
  async function owner2() {
    const other = new Harness();
    await other.start();
    const m = await Mixia.boot(other.env('另一台'));
    await m.createOwner({ serverUrl: other.url, token: other.token, passphrase: PASS });
    other.stop();
    return m;
  }

  it('冷库：只在内存中，口令加恢复码两样都要，保存后再打开内容一致', async () => {
    const { m } = await owner();
    const c = await m.createColdVault('根材料', 'cold-passphrase-1');
    await add(m.vault(c.handle), 'root-ca-key', 'COLD-SECRET');
    const bytes = await m.saveColdVault(c.handle);
    expect(Buffer.from(bytes).toString('latin1')).not.toContain('COLD-SECRET');
    m.closeColdVault(c.handle);
    expect(() => m.vault(c.handle)).toThrow('vault_locked');
    await expect(m.openColdVault(bytes, 'bad', c.recoveryCode)).rejects.toThrow('pack_wrong_key');
    const h2 = await m.openColdVault(bytes, 'cold-passphrase-1', c.recoveryCode);
    expect(listItems(m.vault(h2))[0]!.data.password).toBe('COLD-SECRET');
    expect(m.vaults().find((v) => v.id === h2)!.policy).toBe('cold');
  });

  it('跨库移动：本地到云必须确认，云到本地标记曾上云，目标确认后才删源', async () => {
    const { m, vault } = await owner();
    const { vaultId } = await m.createLocalVault('重要', PASS);
    const lv = m.vault(vaultId);
    const a = await add(lv, 'local-item');
    await expect(m.moveItem(vaultId, a, vault.id)).rejects.toThrow('upload_needs_confirmation');
    expect(getItem(lv, a)).toBeDefined();
    const moved = await m.moveItem(vaultId, a, vault.id, { confirmUpload: true });
    expect(getItem(lv, a)).toBeUndefined();
    expect(getItem(vault, moved)!.data.cloudExposed).toBeUndefined();

    const back = await m.moveItem(vault.id, moved, vaultId);
    expect(getItem(lv, back)!.data.cloudExposed).toBe(true);
  });

  it('普通设备不能批准或撤销；服务端也拒绝', async () => {
    const { m } = await owner();
    const phone = await join2(m, '手机', { role: 'member' });
    await expect(phone.startPairing()).rejects.toThrow('admin_required');
    await expect(phone.revokeDevice(m.deviceId!)).rejects.toThrow('admin_required');
    const st = replay(phone.book.entries);
    const e = signEntry(
      nextBody(st, 'device_revoke', { deviceId: m.deviceId }, phone.deviceId!),
      phone.session!.sign,
    );
    await expect(phone.api!.postLedger([e])).rejects.toMatchObject({ status: 403 });
  });

  it('按库授权：没被授权的库，设备拿不到密钥也读不到日志', async () => {
    const { m, vault } = await owner();
    const second = await m.createCloudVault('工作');
    await add(m.vault(second), 'work-secret');
    await m.syncNow();
    const phone = await join2(m, '手机', { vaults: [vault.id] });
    expect(phone.vaults().map((v) => v.id)).toEqual([vault.id]);
    await expect(phone.api!.getChanges(second, 0)).rejects.toMatchObject({ status: 403 });
    await expect(phone.api!.getKeys(second)).rejects.toMatchObject({ status: 403 });
  });

  it('所有设备丢失：用恢复码在新设备重建，撤销旧设备，旧设备出局', async () => {
    const { m, vault, recoveryCode } = await owner();
    const second = await m.createCloudVault('工作');
    const id = await add(vault, 'survives', 'P@ss');
    await add(m.vault(second), 'work');
    await m.syncNow();

    const fresh = await Mixia.boot(h.env('新电脑'));
    await fresh.recoverAccount({ serverUrl: h.url, recoveryCode, passphrase: 'new-passphrase-123' });
    expect(fresh.phase).toBe('unlocked');
    expect(fresh.isAdmin).toBe(true);
    await fresh.syncNow();
    expect(fresh.openVaults()).toHaveLength(2);
    expect(getItem(fresh.vault(vault.id), id)!.data.password).toBe('P@ss');

    await fresh.revokeDevice(m.deviceId!, '丢失');
    await m.syncNow();
    expect(m.syncStatus).toMatchObject({ state: 'error', error: 'unauthorized' });
  });

  it('恢复码错误：拒绝；只有恢复码没有服务器时无法伪造', async () => {
    await owner();
    const fresh = await Mixia.boot(h.env('x'));
    await expect(
      fresh.recoverAccount({ serverUrl: h.url, recoveryCode: newRecoveryCode().text, passphrase: PASS }),
    ).rejects.toThrow('recovery_rejected');
    expect(fresh.phase).toBe('fresh');
  });

  it('服务器放行恢复却给出别人的账本：根不一致，拒绝', async () => {
    const { recoveryCode } = await owner();
    const fake = rootKeysFrom(newRecoveryCode().bytes);
    const st = replay([]);
    const genesis = signEntry(
      nextBody(st, 'genesis', { ownerId: 'x', rootPub: b64e(fake.sign.pub), recoveryBoxPub: b64e(fake.box.pub) }, 'root'),
      fake.sign,
    );
    h.tap = async (req, next) => {
      if (req.url.includes('/v1/ledger')) {
        return { status: 200, body: utf8e(JSON.stringify({ entries: [genesis], head: 0 })) };
      }
      return next();
    };
    const fresh = await Mixia.boot(h.env('x'));
    await expect(fresh.recoverAccount({ serverUrl: h.url, recoveryCode, passphrase: PASS })).rejects.toThrow('root_mismatch');
  });

  it('换恢复码：旧码失效，新码可恢复', async () => {
    const { m, vault, recoveryCode } = await owner();
    const id = await add(vault, 'keep');
    await m.syncNow();
    const { recoveryCode: fresh } = await m.rotateRecoveryCode(recoveryCode);
    const a = await Mixia.boot(h.env('a'));
    await expect(a.recoverAccount({ serverUrl: h.url, recoveryCode, passphrase: PASS })).rejects.toThrow('recovery_rejected');
    const b = await Mixia.boot(h.env('b'));
    await b.recoverAccount({ serverUrl: h.url, recoveryCode: fresh, passphrase: PASS });
    await b.syncNow();
    expect(getItem(b.vault(vault.id), id)).toBeDefined();
  });

  it('附件：跨设备读取，服务器篡改被发现', async () => {
    const { m, vault } = await owner();
    const phone = await join2(m);
    const ref = await vault.putAttachment(utf8e('ATTACHMENT-BYTES'), 'a.txt', 'text/plain');
    const id = await saveItem(vault, undefined, { ...newItem('note', 'n'), attachments: [ref] });
    await bothSync(m, phone);
    await m.flushUploads();
    const pv = phone.openVaults()[0]!;
    const att = getItem(pv, id)!.data.attachments![0]!;
    const got = await pv.readAttachment(att, (b) => phone.api!.getBlob(pv, b));
    expect(utf8d(got)).toBe('ATTACHMENT-BYTES');

    const third = await join2(m, '第三台');
    await third.syncNow();
    const tv = third.openVaults()[0]!;
    h.tap = async (req, next) => {
      const res = await next();
      if (!req.url.includes('/blobs/')) return res;
      const b = res.body.slice();
      b[30]! ^= 1;
      return { status: 200, body: b };
    };
    await expect(tv.readAttachment(att, (b) => third.api!.getBlob(tv, b))).rejects.toBeInstanceOf(IntegrityAlarm);
    // 被篡改的内容不留在本机：恢复正常后能读
    h.tap = undefined;
    expect(utf8d(await tv.readAttachment(att, (b) => third.api!.getBlob(tv, b)))).toBe('ATTACHMENT-BYTES');
  });

  it('分页：1200 条跨多页同步完整，换钥后全部可读', async () => {
    const { m, vault } = await owner();
    const rows = Array.from({ length: 1200 }, (_, i) => ({
      data: { ...newItem('login', `site-${i}`), password: `p${i}` },
      folderPath: i % 2 ? '项目/系统' : '',
    }));
    await m.importRows(vault.id, rows);
    await m.syncNow();
    const phone = await join2(m);
    expect(listItems(phone.openVaults()[0]!)).toHaveLength(1200);
    await m.rotateVault(vault.id);
    await phone.syncNow();
    expect(phone.openVaults()[0]!.gen).toBe(2);
    expect(listItems(phone.openVaults()[0]!)).toHaveLength(1200);
  }, 60000);

  it('附件上传卡住时，密码条目照常同步', async () => {
    const { m, vault } = await owner();
    const phone = await join2(m);
    const ref = await vault.putAttachment(utf8e('big'), 'a.bin', 'application/octet-stream');
    await saveItem(vault, undefined, { ...newItem('note', '带附件'), attachments: [ref] });
    const id = await add(vault, '紧急改的密码');
    h.tap = async (req, next) => {
      if (req.url.includes('/blobs/')) throw new Error('uplink stalled');
      return next();
    };
    await m.syncNow();
    expect(m.syncStatus.state).toBe('idle');
    await phone.syncNow();
    expect(getItem(phone.openVaults()[0]!, id)).toBeDefined();
    // 附件没丢，恢复后补传
    h.tap = undefined;
    await m.syncNow();
    await m.flushUploads();
    expect(await vault.pendingAttachments()).toEqual([]);
  });

  it('同步进行中发起的修改不用等下一个周期', async () => {
    const { m, vault } = await owner();
    const phone = await join2(m);
    let later: Promise<unknown> | undefined;
    h.tap = async (req, next) => {
      if (!later && req.url.includes('/changes?')) {
        later = add(vault, 'during-sync').then(() => m.syncNow());
      }
      return next();
    };
    await m.syncNow();
    await later;
    h.tap = undefined;
    expect(await m.pendingCount()).toBe(0);
    await phone.syncNow();
    expect(listItems(phone.openVaults()[0]!)).toHaveLength(1);
  });

  it('网络中断：本地修改留在队列，恢复后上传且不重复', async () => {
    const { m, vault } = await owner();
    const id = await add(vault, 'offline');
    h.tap = async () => {
      throw new Error('net down');
    };
    await m.syncNow();
    expect(m.syncStatus.state).toBe('offline');
    expect(await m.pendingCount()).toBe(1);
    expect(getItem(vault, id)).toBeDefined();
    h.tap = undefined;
    await m.syncNow();
    expect(m.syncStatus.state).toBe('idle');
    expect(await m.pendingCount()).toBe(0);
  });

  it('响应丢失后重试：服务器已写入但客户端没收到确认，不产生重复', async () => {
    const { m, vault } = await owner();
    const phone = await join2(m);
    await add(vault, 'once');
    let dropped = false;
    h.tap = async (req, next) => {
      const res = await next();
      if (!dropped && req.method === 'POST' && req.url.endsWith('/changes')) {
        dropped = true;
        throw new Error('connection reset');
      }
      return res;
    };
    await m.syncNow();
    h.tap = undefined;
    await m.syncNow();
    await bothSync(m, phone);
    expect(listItems(phone.openVaults()[0]!)).toHaveLength(1);
    expect(m.syncStatus.state).toBe('idle');
  });

  it('锁定清除内存中的库，解锁后离线也能读', async () => {
    const { m, vault } = await owner();
    const id = await add(vault, 'persist');
    await m.syncNow();
    m.lock();
    expect(m.phase).toBe('locked');
    expect(m.openVaults()).toHaveLength(0);
    h.tap = async () => {
      throw new Error('offline');
    };
    await expect(m.unlock('wrong-pass')).rejects.toThrow('wrong_passphrase');
    await m.unlock(PASS);
    expect(getItem(m.openVaults()[0]!, id)!.data.title).toBe('persist');
  });

  it('同步途中锁定：不产生误报告警，解锁后正常', async () => {
    const { m, vault } = await owner();
    const phone = await join2(m);
    await add(vault, 'x');
    await m.syncNow();
    let hit = false;
    h.tap = async (req, next) => {
      const res = await next();
      if (!hit && req.url.includes('/changes?')) {
        hit = true;
        phone.lock();
      }
      return res;
    };
    await phone.syncNow();
    h.tap = undefined;
    // 不留下告警，也不留下错误状态：解锁时不该看到一条吓人的提示
    expect(phone.syncStatus.state).toBe('idle');
    await phone.unlock(PASS);
    await phone.syncNow();
    expect(phone.syncStatus.state).toBe('idle');
    expect(listItems(phone.openVaults()[0]!)).toHaveLength(1);
  });

  it('换钥和并发上传竞争：刚上传成功的修改不会被吞掉', async () => {
    const { m, vault } = await owner();
    const phone = await join2(m);
    const other = await join2(m, '要撤销的设备');
    const id = await add(vault, 'site', 'old');
    await bothSync(m, phone, other);
    const pv = phone.openVaults()[0]!;

    // 管理设备刚同步完、提交换钥之前，手机上传了改密码
    let raced = false;
    h.tap = async (req, next) => {
      if (!raced && req.url.endsWith('/rotate')) {
        raced = true;
        await saveItem(pv, id, { ...getItem(pv, id)!.data, password: 'NEW-after-site-change' });
        h.tap = undefined;
        await phone.syncNow();
        expect(await phone.pendingCount()).toBe(0);
      }
      return next();
    };
    await m.revokeDevice(other.deviceId!);
    h.tap = undefined;
    await bothSync(m, phone);
    await bothSync(m, phone);
    expect(getItem(vault, id)!.data.password).toBe('NEW-after-site-change');
    expect(getItem(pv, id)!.data.password).toBe('NEW-after-site-change');
  });

  it('服务器对上传回 200 却不存：下一次换钥后本机内容依然在，并重新发出', async () => {
    const { m, vault } = await owner();
    const phone = await join2(m);
    const other = await join2(m, 'x');
    const id = await add(vault, 'site', 'old');
    await bothSync(m, phone);
    const pv = phone.openVaults()[0]!;
    await saveItem(pv, id, { ...getItem(pv, id)!.data, password: 'swallowed' });
    h.tap = async (req, next) => {
      if (req.method === 'POST' && req.url.endsWith('/changes')) {
        const ids = JSON.parse(utf8d(req.body!)).changes.map((c: { id: string }) => ({ id: c.id, seq: 999 }));
        return { status: 200, body: utf8e(JSON.stringify({ accepted: ids, head: 999 })) };
      }
      return next();
    };
    await phone.syncNow();
    expect(await phone.pendingCount()).toBe(0);
    h.tap = undefined;
    await m.revokeDevice(other.deviceId!);
    await bothSync(phone, m);
    await bothSync(phone, m);
    expect(getItem(pv, id)!.data.password).toBe('swallowed');
    expect(getItem(vault, id)!.data.password).toBe('swallowed');
  });

  it('服务器没真正接受上传：不能当成已发送', async () => {
    const { m, vault } = await owner();
    await add(vault, 'x');
    h.tap = async (req, next) => {
      if (req.method === 'POST' && req.url.endsWith('/changes')) {
        return { status: 200, body: utf8e(JSON.stringify({ accepted: [], head: 0 })) };
      }
      return next();
    };
    await m.syncNow();
    expect(m.syncStatus).toMatchObject({ state: 'alarm', alarm: { code: 'push_not_accepted' } });
    expect(await m.pendingCount()).toBe(1);
  });

  it('服务器隐瞒账本尾部：其他设备的变更头暴露了更新的序号', async () => {
    const { m, vault } = await owner();
    const phone = await join2(m);
    const other = await join2(m, 'x');
    await bothSync(m, phone);
    await m.revokeDevice(other.deviceId!);
    // 服务器只给手机旧账本，但手机能从变更头看到别人已经到了更高的序号
    const frozen = phone.ledger.seq;
    await add(vault, 'after');
    await m.syncNow();
    h.tap = async (req, next) => {
      const res = await next();
      if (!req.url.includes('/v1/ledger')) return res;
      const j = JSON.parse(utf8d(res.body));
      j.entries = j.entries.slice(0, 1);
      j.head = frozen;
      return { status: 200, body: utf8e(JSON.stringify(j)) };
    };
    // 变更日志也停在旧代，只放出一条高序号的变更
    const real = await m.api!.getChanges(vault.id, 0);
    const tail = real.changes.at(-1)!;
    const inner = h.tap;
    h.tap = async (req, next) => {
      if (req.url.includes('/changes?')) {
        const j = { changes: [tail], head: tail.seq, base: 1, gen: 1 };
        return { status: 200, body: utf8e(JSON.stringify(j)) };
      }
      return inner(req, next);
    };
    await phone.syncNow();
    expect(phone.syncStatus.state).toBe('alarm');
    expect(phone.syncStatus.alarm?.code).toBe('ledger_withheld');
  });

  it('新设备被放进缺记录的旧账本：批准时的账本位置对不上', async () => {
    const { m } = await owner();
    const n = await Mixia.boot(h.env('手机'));
    const p = await m.startPairing();
    const j = await n.beginJoin(h.url, p.code);
    await n.submitJoin(j, PASS);
    const dev = await m.pollPairing(p.pairId, p.secret);
    await m.approvePairing(p.pairId, p.secret, dev!, { role: 'member', vaults: [] });
    // 批准之后管理设备的账本又往前走了，服务器只给新设备看到批准之前
    h.tap = async (req, next) => {
      const res = await next();
      if (!req.url.includes('/v1/ledger')) return res;
      const body = JSON.parse(utf8d(res.body));
      body.entries = body.entries.slice(0, -1);
      return { status: 200, body: utf8e(JSON.stringify(body)) };
    };
    await expect(n.finishJoin(j)).rejects.toThrow(/ledger_withheld|device_not_in_ledger/);
  });

  it('被撤销的管理设备在分叉上替新设备签 device_add：账本位置对不上', async () => {
    const { m } = await owner();
    const x = await join2(m, '被撤销的管理设备', { role: 'admin' });
    const xSign = { pub: x.session!.sign.pub, priv: x.session!.sign.priv.slice() };
    const xId = x.deviceId!;
    await m.revokeDevice(xId);
    const forkAt = m.ledger.devices.get(xId)!.revokedSeq!;

    const n = await Mixia.boot(h.env('手机'));
    const p = await m.startPairing();
    const j = await n.beginJoin(h.url, p.code);
    await n.submitJoin(j, PASS);
    const dev = (await m.pollPairing(p.pairId, p.secret))!;
    await m.approvePairing(p.pairId, p.secret, dev, { role: 'member', vaults: [] });

    // 服务器给新设备看的分支里，撤销那一条不存在，同一个位置上是被撤销设备签的批准
    const base = m.book.entries.slice(0, forkAt);
    const st = replay(base);
    const forged = signEntry(
      nextBody(
        st,
        'device_add',
        {
          deviceId: dev.deviceId,
          name: dev.raw.name,
          platform: dev.raw.platform,
          level: dev.raw.level,
          role: 'member',
          authPub: dev.raw.authPub,
          signPub: dev.raw.signPub,
          boxPub: dev.raw.boxPub,
          vaults: [],
        },
        xId,
      ),
      xSign,
    );
    h.tap = async (req, next) => {
      if (req.url.includes('/v1/ledger')) {
        const entries = [...base, forged];
        return { status: 200, body: utf8e(JSON.stringify({ entries, head: entries.length - 1 })) };
      }
      return next();
    };
    await expect(n.finishJoin(j)).rejects.toThrow('ledger_withheld');
  });

  it('批准管理设备时不管选了什么，都授予全部云库', async () => {
    const { m } = await owner();
    const second = await m.createCloudVault('工作');
    const admin2 = await join2(m, '第二管理设备', { role: 'admin', vaults: [] });
    await admin2.syncNow();
    expect(admin2.vaults().map((v) => v.id).sort()).toEqual(m.vaults().map((v) => v.id).sort());
    expect(admin2.vaults().map((v) => v.id)).toContain(second);
  });

  it('批准时公钥被换：指纹变化，新设备也会发现', async () => {
    const { m } = await owner();
    const n = await Mixia.boot(h.env('手机'));
    const p = await m.startPairing();
    const j = await n.beginJoin(h.url, p.code);
    const { fingerprint: shown } = await n.submitJoin(j, PASS);
    const dev = (await m.pollPairing(p.pairId, p.secret))!;
    expect(dev.fingerprint).toBe(shown);
    const evil = keys();
    const swapped = { ...dev, raw: { ...dev.raw, boxPub: b64e(evil.box.pub) } };
    expect(deviceFingerprint(swapped.raw)).not.toBe(shown);
    await m.approvePairing(p.pairId, p.secret, swapped, { role: 'member', vaults: [] });
    await expect(n.finishJoin(j)).rejects.toThrow('device_keys_swapped');
  });

  it('管理设备总是持有全部云库，换钥不会被跳过', async () => {
    const { m } = await owner();
    const admin2 = await join2(m, '第二管理设备', { role: 'admin' });
    const second = await admin2.createCloudVault('后建的库');
    await add(admin2.vault(second), 'in-second');
    await admin2.syncNow();
    await m.syncNow();
    expect(m.vaults().map((v) => v.id)).toContain(second);
    expect(listItems(m.vault(second))).toHaveLength(1);
    await m.revokeDevice(admin2.deviceId!);
    expect(m.vault(second).gen).toBe(2);
    expect(m.ledger.vaultsNeedingRotation()).toEqual([]);
  });

  it('有库换不了钥时必须报错，不能显示成功', async () => {
    const { m, vault } = await owner();
    const other = await join2(m, 'x');
    (m as unknown as { cloud: Map<string, Vault> }).cloud.delete(vault.id);
    await expect(m.revokeDevice(other.deviceId!)).rejects.toThrow('rotation_incomplete');
  });

  it('告警期间不能批准新设备', async () => {
    const { m } = await owner();
    h.tap = async (req, next) => {
      if (req.url.includes('/v1/ledger')) {
        return { status: 200, body: utf8e(JSON.stringify({ entries: [], head: 0 })) };
      }
      return next();
    };
    await m.syncNow();
    h.tap = undefined;
    await expect(m.startPairing()).rejects.toThrow('alarm_active');
  });

  it('坏数据卡住同步：管理设备用本机内容重建，所有设备恢复', async () => {
    const { m, vault } = await owner();
    const phone = await join2(m);
    const id = await add(vault, 'keep');
    await bothSync(m, phone);
    await phone.api!.pushChanges(phone.openVaults()[0]!, [{ id: 'POISON', gen: 1, blob: b64e(utf8e('garbage')) }]);
    await m.syncNow();
    expect(m.syncStatus).toMatchObject({ state: 'alarm', alarm: { code: 'malformed_change', vaultId: vault.id } });
    await m.rebuildVault(vault.id);
    await m.syncNow();
    expect(m.syncStatus.state).toBe('idle');
    expect(vault.gen).toBe(2);
    await phone.acknowledgeAlarm();
    await phone.syncNow();
    expect(phone.syncStatus.state).toBe('idle');
    expect(getItem(phone.openVaults()[0]!, id)).toBeDefined();
  });

  it('本机被撤销：云库清除，本地库还能打开和备份', async () => {
    const { m } = await owner();
    const phone = await join2(m, '手机', { role: 'admin' });
    const { vaultId, recoveryCode } = await phone.createLocalVault('重要', PASS);
    await add(phone.vault(vaultId), 'still-mine');
    await m.revokeDevice(phone.deviceId!);
    // 正常情况服务器直接 401；这里让它把真实账本给被撤销设备，走客户端处理路径
    const entries = m.book.entries;
    h.tap = async (req, next) => {
      if (req.url.includes('/v1/ledger')) {
        const from = Number(new URL(req.url).searchParams.get('from'));
        return { status: 200, body: utf8e(JSON.stringify({ entries: entries.slice(from), head: entries.length - 1 })) };
      }
      return next();
    };
    await phone.syncNow();
    h.tap = undefined;
    expect(phone.revoked).toBe(true);
    expect(phone.phase).toBe('unlocked');
    expect(phone.vaults().map((v) => v.policy)).toEqual(['local']);
    phone.lock();
    await phone.unlock(PASS);
    await phone.unlockLocalVault(vaultId, PASS);
    const bytes = await phone.exportBackup(vaultId);
    expect(phone.verifyBackup(bytes, recoveryCode).count).toBe(1);
  });

  it('备份带上附件：设备没了也能从备份恢复附件', async () => {
    const { m } = await owner();
    const { vaultId, recoveryCode } = await m.createLocalVault('重要', PASS);
    const lv = m.vault(vaultId);
    const ref = await lv.putAttachment(utf8e('PRIVATE-KEY-FILE'), 'key.pem', 'text/plain');
    const id = await saveItem(lv, undefined, { ...newItem('note', 'cert'), attachments: [ref] });
    const backup = await m.exportBackup(vaultId);
    const fresh = await owner2();
    const r = await fresh.restoreBackup(backup, recoveryCode, PASS);
    const v = fresh.vault(r.vaultId);
    const att = listItems(v)[0]!.data.attachments![0]!;
    expect(utf8d(await v.readAttachment(att))).toBe('PRIVATE-KEY-FILE');
    expect(id).toBeTruthy();
  });

  it('离线恢复工具：没有服务器和客户端时读出备份和冷库', async () => {
    const { m } = await owner();
    const { vaultId, recoveryCode } = await m.createLocalVault('重要', PASS);
    await saveItem(m.vault(vaultId), undefined, { ...newItem('login', 'CLI-ITEM'), password: 'CLI-PW' });
    await saveItem(m.vault(vaultId), undefined, {
      ...newItem('api', 'CLI-KEY'),
      provider: 'CLI-PROVIDER',
      fields: [{ name: 'API Key', value: 'CLI-SECRET', secret: true, envName: 'CLI_ENV' }],
    });
    const dir = mkdtempSync(join(tmpdir(), 'mixia-cli-'));
    const pack = join(dir, 'b.mxpack');
    const out = join(dir, 'o.json');
    writeFileSync(pack, await m.exportBackup(vaultId));
    const cli = resolve(__dirname, '../../../apps/cli/dist/mixia-recover.cjs');
    const run = (args: string[], input: string) => execFileSync('node', [cli, ...args], { input, encoding: 'utf8', stdio: 'pipe' });
    expect(JSON.parse(run(['info', pack], '')).kind).toBe('backup');
    expect(run(['verify', pack], `${recoveryCode}
`)).toContain('2 条');
    run(['export', pack, out], `${recoveryCode}
`);
    const plain = JSON.parse(readFileSync(out, 'utf8'));
    const byTitle = (t: string) => plain.items.find((i: { title: string }) => i.title === t);
    expect(byTitle('CLI-ITEM')).toMatchObject({ password: 'CLI-PW' });
    expect(byTitle('CLI-KEY')).toMatchObject({
      type: 'api',
      provider: 'CLI-PROVIDER',
      fields: [{ name: 'API Key', value: 'CLI-SECRET', secret: true, envName: 'CLI_ENV' }],
    });
    expect(() => run(['verify', pack], `${newRecoveryCode().text}
`)).toThrow();

    const c = await m.createColdVault('根材料', 'cold-passphrase-1');
    await saveItem(m.vault(c.handle), undefined, { ...newItem('note', 'COLD-ITEM') });
    const cold = join(dir, 'c.mxcold');
    writeFileSync(cold, await m.saveColdVault(c.handle));
    expect(run(['verify', cold], `${c.recoveryCode}
cold-passphrase-1
`)).toContain('1 条');
    rmSync(dir, { recursive: true, force: true });
  });

  it('新设备在换钥之后加入，也能完整读取', async () => {
    const { m, vault } = await owner();
    const other = await join2(m, 'x');
    await add(vault, 'a');
    await m.syncNow();
    await m.revokeDevice(other.deviceId!);
    await add(vault, 'b');
    await m.syncNow();
    const late = await join2(m, '后来的手机');
    await late.syncNow();
    expect(late.syncStatus.state).toBe('idle');
    expect(listItems(late.openVaults()[0]!)).toHaveLength(2);
  });

  it('换恢复码失败是原子的：旧码继续有效', async () => {
    const { m, vault, recoveryCode } = await owner();
    await add(vault, 'keep');
    await m.syncNow();
    const r = m.beginRecoveryRotation(recoveryCode);
    h.tap = async (req, next) => {
      if (req.url.endsWith('/v1/root/rotate')) throw new Error('net down');
      return next();
    };
    await expect(r.commit()).rejects.toThrow();
    h.tap = undefined;
    const a = await Mixia.boot(h.env('a'));
    await a.recoverAccount({ serverUrl: h.url, recoveryCode, passphrase: PASS });
    await a.syncNow();
    expect(listItems(a.vault(vault.id))).toHaveLength(1);
  });

  it('改主口令：旧口令失效，云库和本地库都还能打开', async () => {
    const { m } = await owner();
    const { vaultId } = await m.createLocalVault('重要', 'local-passphrase');
    await add(m.vault(vaultId), 'k');
    await m.changePassphrase(PASS, 'brand-new-passphrase');
    expect(m.phase).toBe('locked');
    await expect(m.unlock(PASS)).rejects.toThrow('wrong_passphrase');
    await m.unlock('brand-new-passphrase');
    expect(m.openVaults()).toHaveLength(1);
    expect(m.vaults().find((v) => v.id === vaultId)!.name).toBe('重要');
    await m.unlockLocalVault(vaultId, 'local-passphrase');
    expect(listItems(m.vault(vaultId))).toHaveLength(1);
  });

  it('服务器重启：账本和数据不丢，客户端继续同步', async () => {
    const { m, vault } = await owner();
    await add(vault, 'before-restart');
    await m.syncNow();
    await h.restart();
    await add(vault, 'after-restart');
    await m.syncNow();
    expect(m.syncStatus.state).toBe('idle');
    const phone = await join2(m);
    expect(listItems(phone.openVaults()[0]!)).toHaveLength(2);
  });
});

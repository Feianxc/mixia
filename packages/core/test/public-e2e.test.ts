/**
 * 公网全链路：真实经过 Cloudflare → 隧道 → 线上服务端。
 * 只在设置 MIXIA_E2E_URL 和 MIXIA_E2E_TOKEN 时运行；初始化只能一次，跑完要重置服务端数据。
 * 全部是虚构数据。
 */
import { describe, expect, it } from 'vitest';
import type { HttpRequest, HttpResponse } from '../src/api';
import { SoftwareKeys } from '../src/device';
import { Mixia, type PlatformEnv } from '../src/mixia';
import { getItem, listItems, newItem, saveItem } from '../src/model';
import { MemoryKV } from '../src/store';
import { TEST_MEM } from './helpers';

const URL_ = process.env.MIXIA_E2E_URL ?? '';
const TOKEN = process.env.MIXIA_E2E_TOKEN ?? '';
const PASS = 'public-e2e-passphrase';

const http = async (r: HttpRequest): Promise<HttpResponse> => {
  const res = await fetch(r.url, {
    method: r.method,
    headers: r.headers,
    ...(r.body ? { body: r.body as BodyInit } : {}),
  });
  return { status: res.status, body: new Uint8Array(await res.arrayBuffer()) };
};

function env(name: string): PlatformEnv {
  const stores = new Map<string, MemoryKV>();
  const hw = new SoftwareKeys(new MemoryKV());
  Object.defineProperty(hw, 'level', { value: 'hardware' });
  return {
    hw,
    http,
    openKV: (n) => {
      let kv = stores.get(n);
      if (!kv) stores.set(n, (kv = new MemoryKV()));
      return kv;
    },
    info: { platform: 'e2e', defaultName: name, kdfMem: TEST_MEM },
  };
}

async function pair(admin: Mixia, name: string) {
  const m = await Mixia.boot(env(name));
  const p = await admin.startPairing();
  const j = await m.beginJoin(URL_, p.code);
  await m.submitJoin(j, PASS, name);
  const dev = await admin.pollPairing(p.pairId, p.secret);
  await admin.approvePairing(p.pairId, p.secret, dev!, {
    role: 'member',
    vaults: admin.vaults().filter((v) => v.policy === 'cloud').map((v) => v.id),
  });
  expect(await m.finishJoin(j)).toBe(true);
  return m;
}

const ms = async (fn: () => Promise<unknown>) => {
  const t = performance.now();
  await fn();
  const d = Math.round(performance.now() - t);
  return d;
};

describe.skipIf(!URL_ || !TOKEN)('公网全链路', () => {
  it('初始化、配对、同步、附件、撤销、恢复全部经过隧道', { timeout: 420000 }, async () => {
    const report: Record<string, unknown> = {};

    const pc = await Mixia.boot(env('公网电脑'));
    report.bootstrapMs = await ms(async () => {
      const r = await pc.createOwner({ serverUrl: URL_, token: TOKEN, passphrase: PASS });
      (globalThis as { rc?: string }).rc = r.recoveryCode;
    });
    const rc = (globalThis as { rc?: string }).rc!;
    await pc.syncNow();
    expect(pc.syncStatus.state).toBe('idle');
    const vault = pc.openVaults()[0]!;

    // 第二次初始化必须被拒
    const again = await Mixia.boot(env('抢占者'));
    await expect(again.createOwner({ serverUrl: URL_, token: TOKEN, passphrase: PASS })).rejects.toThrow('gone');

    // 匿名访问被拒，请求头经过 Cloudflare 后签名依然成立
    const anon = await http({ method: 'GET', url: `${URL_}/v1/ledger?from=0`, headers: {} });
    expect(anon.status).toBe(401);

    const phone = await pair(pc, '公网手机');
    const pv = phone.openVaults()[0]!;

    // 小变更跨设备可见耗时，目标 5 秒内
    const id = await saveItem(vault, undefined, { ...newItem('login', '延迟探针'), password: 'p1' });
    report.crossDeviceMs = await ms(async () => {
      await pc.syncNow();
      await phone.syncNow();
    });
    expect(getItem(pv, id)!.data.password).toBe('p1');

    // 附件穿过隧道。这条路入站很慢，用 300 KB 测通路和速度
    const big = new Uint8Array(300 * 1024).fill(7);
    const ref = await vault.putAttachment(big, 'big.bin', 'application/octet-stream');
    const aid = await saveItem(vault, undefined, { ...newItem('note', '附件'), attachments: [ref] });
    await pc.syncNow();
    report.attachment300kbMs = await ms(() => pc.flushUploads());
    await phone.syncNow();
    const att = getItem(pv, aid)!.data.attachments![0]!;
    const got = await pv.readAttachment(att, (b) => phone.api!.getBlob(pv, b));
    expect(got.length).toBe(big.length);

    // 500 条导入后走分页和换钥
    await pc.importRows(
      vault.id,
      Array.from({ length: 500 }, (_, i) => ({ data: { ...newItem('login', `站点${i}`), password: `x${i}` }, folderPath: '' })),
    );
    report.push500Ms = await ms(() => pc.syncNow());
    report.pull500Ms = await ms(() => phone.syncNow());
    expect(listItems(pv).length).toBe(listItems(vault).length);

    // 撤销：第三台被拒，其余无感
    const lost = await pair(pc, '公网丢失设备');
    report.revokeRotateMs = await ms(() => pc.revokeDevice(lost.deviceId!, 'e2e'));
    await lost.syncNow();
    expect(lost.syncStatus).toMatchObject({ state: 'error', error: 'unauthorized' });
    await phone.syncNow();
    expect(pv.gen).toBe(2);
    expect(listItems(pv).length).toBe(listItems(vault).length);

    // 所有设备丢失后用恢复码重建
    const fresh = await Mixia.boot(env('公网新电脑'));
    report.recoverMs = await ms(() => fresh.recoverAccount({ serverUrl: URL_, recoveryCode: rc, passphrase: PASS }));
    await fresh.syncNow();
    expect(listItems(fresh.vault(vault.id)).length).toBe(listItems(vault).length);

    // 限流：同一 IP 连续错误配对请求会被限制，而不是无限尝试
    const burst = await Promise.all(
      Array.from({ length: 80 }, () =>
        http({ method: 'GET', url: `${URL_}/v1/pair/ZZZZZZ`, headers: { 'X-Mx-Pair-Token': 'bad' } }),
      ),
    );
    const codes = new Set(burst.map((r) => r.status));
    report.pairProbeStatuses = [...codes];
    expect(codes.has(429)).toBe(true);

    console.log('PUBLIC_E2E', JSON.stringify(report));
  });
});

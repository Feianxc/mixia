import { describe, expect, it } from 'vitest';
import { b64d, b64e, randomBytes, sha256, utf8e } from '../src/crypto';
import {
  LedgerState,
  deviceIdFromAuthPub,
  entryHash,
  nextBody,
  replay,
  signEntry,
  type EntryType,
  type LedgerEntry,
} from '../src/ledger';
import { keys, ready } from './helpers';

ready();

function setup() {
  const root = keys();
  const st = new LedgerState();
  const entries: LedgerEntry[] = [];
  const push = (type: EntryType, data: Record<string, unknown>, signer = 'root', k = root.sign) => {
    const e = signEntry(nextBody(st, type, data, signer), k);
    st.apply(e);
    entries.push(e);
    return e;
  };
  push('genesis', {
    ownerId: 'owner',
    rootPub: b64e(root.sign.pub),
    recoveryBoxPub: b64e(root.box.pub),
  });
  return { root, st, entries, push };
}

function deviceData(role: 'admin' | 'member', vaults: string[] = []) {
  const k = keys();
  const authPub = randomBytes(65);
  const deviceId = deviceIdFromAuthPub(authPub);
  return {
    k,
    deviceId,
    data: {
      deviceId,
      name: 'd',
      platform: 'test',
      level: 'hardware',
      role,
      authPub: b64e(authPub),
      signPub: b64e(k.sign.pub),
      boxPub: b64e(k.box.pub),
      vaults,
    },
  };
}

describe('信任账本', () => {
  it('创世条目定义根，重放得到相同状态', () => {
    const { entries, st, push } = setup();
    const a = deviceData('admin');
    push('device_add', a.data);
    const again = replay(entries);
    expect(again.headHash).toBe(st.headHash);
    expect(again.genesisHash).toBe(entryHash(entries[0]!));
    expect(again.activeAdmins.map((d) => d.deviceId)).toEqual([a.deviceId]);
  });

  it('服务器伪造新设备：攻击者自己的密钥签名被拒绝', () => {
    const { st } = setup();
    const attacker = keys();
    const evil = deviceData('admin');
    const forged = signEntry(nextBody(st, 'device_add', evil.data, 'root'), attacker.sign);
    expect(() => st.apply(forged)).toThrow(/bad_root_signature/);
    expect(st.devices.size).toBe(0);
  });

  it('冒用管理设备身份：密钥不对被拒绝', () => {
    const { st, push } = setup();
    const a = deviceData('admin');
    push('device_add', a.data);
    const evil = deviceData('admin');
    const forged = signEntry(nextBody(st, 'device_add', evil.data, a.deviceId), keys().sign);
    expect(() => st.apply(forged)).toThrow(/bad_signature/);
    expect(st.devices.has(evil.deviceId)).toBe(false);
  });

  it('篡改已签名条目的内容被拒绝', () => {
    const { st, root } = setup();
    const a = deviceData('member');
    const e = signEntry(nextBody(st, 'device_add', a.data, 'root'), root.sign);
    const body = JSON.parse(new TextDecoder().decode(b64d(e.body)));
    body.data.role = 'admin';
    const tampered = { ...e, body: b64e(utf8e(JSON.stringify(body))) };
    expect(() => st.apply(tampered)).toThrow(/bad_root_signature/);
  });

  it('member 设备不能批准别的设备或扩大自己的权限', () => {
    const { st, push } = setup();
    const m = deviceData('member');
    push('device_add', m.data);
    const other = deviceData('admin');
    expect(() =>
      st.apply(signEntry(nextBody(st, 'device_add', other.data, m.deviceId), m.k.sign)),
    ).toThrow(/signer_not_admin/);
    expect(() =>
      st.apply(
        signEntry(
          nextBody(st, 'grant', { deviceId: m.deviceId, role: 'admin', vaults: [] }, m.deviceId),
          m.k.sign,
        ),
      ),
    ).toThrow(/signer_not_admin/);
  });

  it('被撤销的管理设备不能再签任何条目，且不能复活', () => {
    const { st, push } = setup();
    const a = deviceData('admin');
    const b = deviceData('admin');
    push('device_add', a.data);
    push('device_add', b.data);
    push('device_revoke', { deviceId: a.deviceId, reason: 'lost' }, b.deviceId, b.k.sign);
    const c = deviceData('member');
    expect(() =>
      st.apply(signEntry(nextBody(st, 'device_add', c.data, a.deviceId), a.k.sign)),
    ).toThrow(/signer_revoked/);
    expect(() => push('device_add', a.data)).toThrow(/device_exists/);
  });

  it('不能撤销最后一个管理设备，除非根签名', () => {
    const { st, push } = setup();
    const a = deviceData('admin');
    push('device_add', a.data);
    expect(() =>
      st.apply(
        signEntry(nextBody(st, 'device_revoke', { deviceId: a.deviceId }, a.deviceId), a.k.sign),
      ),
    ).toThrow(/last_admin/);
    push('device_revoke', { deviceId: a.deviceId });
    expect(st.activeAdmins).toHaveLength(0);
  });

  it('序号跳号、前序哈希不符、创世重放都被拒绝', () => {
    const { st, root, entries } = setup();
    const a = deviceData('member');
    const skip = signEntry({ ...nextBody(st, 'device_add', a.data, 'root'), seq: 5 }, root.sign);
    expect(() => st.apply(skip)).toThrow(/bad_seq/);
    const bad = signEntry({ ...nextBody(st, 'device_add', a.data, 'root'), prev: 'AAAA' }, root.sign);
    expect(() => st.apply(bad)).toThrow(/bad_prev/);
    expect(() => st.apply(entries[0]!)).toThrow(/bad_seq/);
  });

  it('deviceId 必须由认证公钥派生，防止顶替', () => {
    const { st, root } = setup();
    const a = deviceData('admin');
    const e = signEntry(
      nextBody(st, 'device_add', { ...a.data, deviceId: b64e(sha256(utf8e('other')).slice(0, 16)) }, 'root'),
      root.sign,
    );
    expect(() => st.apply(e)).toThrow(/device_id_mismatch/);
  });

  it('库的代数只能逐一递增，撤销后标记需要换钥，换钥后清除', () => {
    const { st, push } = setup();
    push('vault_add', { vaultId: 'v1', gen: 1, keyCommit: 'c' });
    const a = deviceData('admin', ['v1']);
    const b = deviceData('member', ['v1']);
    push('device_add', a.data);
    push('device_add', b.data);
    expect(st.vaultsNeedingRotation()).toEqual([]);
    push('device_revoke', { deviceId: b.deviceId }, a.deviceId, a.k.sign);
    expect(st.vaultsNeedingRotation()).toEqual(['v1']);
    expect(() =>
      push('vault_rotate', { vaultId: 'v1', gen: 3, keyCommit: 'x', snapshotCount: 0, snapshotHash: '' }),
    ).toThrow(/bad_gen/);
    push('vault_rotate', { vaultId: 'v1', gen: 2, keyCommit: 'x', snapshotCount: 0, snapshotHash: '' });
    expect(st.vaultsNeedingRotation()).toEqual([]);
  });

  it('收窄授权也要求换钥', () => {
    const { st, push } = setup();
    push('vault_add', { vaultId: 'v1', gen: 1, keyCommit: 'c' });
    const a = deviceData('admin', ['v1']);
    push('device_add', a.data);
    push('grant', { deviceId: a.deviceId, role: 'admin', vaults: [] });
    expect(st.vaultsNeedingRotation()).toEqual(['v1']);
  });

  it('授权未知的库被拒绝', () => {
    const { push } = setup();
    expect(() => push('device_add', deviceData('member', ['ghost']).data)).toThrow(/unknown_vault/);
  });

  it('只有根能换根，换根后旧根失效', () => {
    const { st, push, root } = setup();
    const a = deviceData('admin');
    push('device_add', a.data);
    const fresh = keys();
    expect(() =>
      st.apply(
        signEntry(
          nextBody(st, 'root_rotate', { rootPub: 'x', recoveryBoxPub: 'y' }, a.deviceId),
          a.k.sign,
        ),
      ),
    ).toThrow(/root_only/);
    push('root_rotate', { rootPub: b64e(fresh.sign.pub), recoveryBoxPub: b64e(fresh.box.pub) });
    const evil = deviceData('admin');
    expect(() =>
      st.apply(signEntry(nextBody(st, 'device_add', evil.data, 'root'), root.sign)),
    ).toThrow(/bad_root_signature/);
    push('device_add', evil.data, 'root', fresh.sign);
    expect(st.devices.has(evil.deviceId)).toBe(true);
  });
});

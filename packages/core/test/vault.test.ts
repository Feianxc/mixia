import { describe, expect, it } from 'vitest';
import { randomBytes } from '../src/crypto';
import { IntegrityAlarm } from '../src/errors';
import {
  deleteFolder,
  flattenFolders,
  folderTree,
  getItem,
  listItems,
  newItem,
  purgeItem,
  restoreItem,
  restoreVersion,
  saveFolder,
  saveItem,
  trashItem,
} from '../src/model';
import { MemoryKV, type KV, type KVOp } from '../src/store';
import { Vault, decryptBlob, parseBlob, verifyBlob, type ChangeRecord } from '../src/vault';
import { keys, makeVault, ready } from './helpers';

ready();

/** 把 a 的待发送变更交给 b，模拟服务器转发。 */
async function deliver(a: Vault, b: Vault, startSeq = b.meta.lastSeq + 1): Promise<number> {
  const pending = await a.pending();
  const recs: ChangeRecord[] = pending.map((p, i) => ({
    id: p.id,
    gen: p.gen,
    blob: p.blob,
    device: parseBlob(p.blob).header.device,
    seq: startSeq + i,
  }));
  const n = await b.ingest(recs, () => undefined);
  await a.markUploaded(pending.map((p) => p.counter));
  return n;
}

async function pair() {
  const key = randomBytes(32);
  const mk = (deviceId: string) =>
    Vault.create(new MemoryKV(), { vaultId: 'v', policy: 'cloud' }, key, { deviceId, sign: keys().sign }, () => 1);
  return { a: await mk('dev-a'), b: await mk('dev-b') };
}

describe('条目与版本', () => {
  it('保存后可重新打开并读回，未知字段保留', async () => {
    const { v, kv, key, author } = await makeVault();
    const data = { ...newItem('login', 'GitHub'), username: 'me', password: 'pw1', futureField: { x: 1 } };
    const id = await saveItem(v, undefined, data);
    const reopened = await Vault.open(kv, key, author, () => 7);
    const it = getItem(reopened, id)!;
    expect(it.data.title).toBe('GitHub');
    expect(it.data.futureField).toEqual({ x: 1 });
  });

  it('存储中没有任何明文', async () => {
    const { v, kv } = await makeVault();
    await saveItem(v, undefined, {
      ...newItem('login', 'SECRET-TITLE-MARKER'),
      username: 'SECRET-USER-MARKER',
      password: 'SECRET-PW-MARKER',
      urls: ['https://secret-url-marker.example'],
    });
    const all = new TextDecoder('latin1').decode(
      Uint8Array.from(kv.dump().flatMap((b) => [...b])),
    );
    expect(all).not.toMatch(/SECRET|marker/i);
  });

  it('修改密码保留历史，可恢复旧版本', async () => {
    const { v } = await makeVault();
    const id = await saveItem(v, undefined, { ...newItem('login', 'A'), password: 'old' });
    await saveItem(v, id, { ...getItem(v, id)!.data, password: 'new' });
    expect(getItem(v, id)!.data.passwordHistory?.[0]?.value).toBe('old');
    const first = v.graph.history('item', id).at(-1)!;
    await restoreVersion(v, id, first.id);
    expect(getItem(v, id)!.data.password).toBe('old');
    expect(v.graph.history('item', id)).toHaveLength(3);
  });

  it('回收站与永久删除', async () => {
    const { v } = await makeVault();
    const id = await saveItem(v, undefined, newItem('note', 'N'));
    await trashItem(v, id);
    expect(listItems(v)).toHaveLength(0);
    expect(listItems(v, { trash: true })).toHaveLength(1);
    await restoreItem(v, id);
    expect(listItems(v)).toHaveLength(1);
    await purgeItem(v, id);
    expect(listItems(v)).toHaveLength(0);
    expect(listItems(v, { trash: true })).toHaveLength(0);
  });

  it('集合零条、一条、多条形态一致', async () => {
    const { v } = await makeVault();
    expect(listItems(v)).toEqual([]);
    await saveItem(v, undefined, newItem('note', '1'));
    expect(listItems(v)).toHaveLength(1);
    await saveItem(v, undefined, newItem('note', '2'));
    await saveItem(v, undefined, newItem('note', '3'));
    expect(listItems(v)).toHaveLength(3);
  });
});

describe('离线并发与冲突', () => {
  it('两台设备离线修改同一条目：保留双方，不静默覆盖', async () => {
    const { a, b } = await pair();
    const id = await saveItem(a, undefined, { ...newItem('login', 'X'), username: 'u0', password: 'p0' });
    await deliver(a, b);

    await saveItem(a, id, { ...getItem(a, id)!.data, password: 'from-a' });
    await saveItem(b, id, { ...getItem(b, id)!.data, username: 'from-b' });
    await deliver(a, b, 2);
    await deliver(b, a, 2);

    for (const v of [a, b]) {
      const it = getItem(v, id)!;
      expect(it.conflict).toBe(true);
      expect(it.heads).toHaveLength(2);
      const combos = it.heads.map((h) => [h.data!.username, h.data!.password]);
      // 绝不出现“新账号配旧密码”以外的字段混搭：每个头都是完整的一版
      expect(combos).toContainEqual(['u0', 'from-a']);
      expect(combos).toContainEqual(['from-b', 'p0']);
    }
    // 两端挑选结果一致
    expect(getItem(a, id)!.data.password).toBe(getItem(b, id)!.data.password);
  });

  it('用户裁决后冲突消失，并传播给对端', async () => {
    const { a, b } = await pair();
    const id = await saveItem(a, undefined, newItem('login', 'X'));
    await deliver(a, b);
    await saveItem(a, id, { ...getItem(a, id)!.data, password: 'A' });
    await saveItem(b, id, { ...getItem(b, id)!.data, password: 'B' });
    await deliver(a, b, 2);
    await deliver(b, a, 2);
    await saveItem(a, id, { ...getItem(a, id)!.data, password: 'merged' });
    expect(getItem(a, id)!.conflict).toBe(false);
    await deliver(a, b, 3);
    expect(getItem(b, id)!.conflict).toBe(false);
    expect(getItem(b, id)!.data.password).toBe('merged');
  });

  it('一方删除一方编辑：显示冲突，不让删除静默获胜', async () => {
    const { a, b } = await pair();
    const id = await saveItem(a, undefined, newItem('login', 'X'));
    await deliver(a, b);
    await purgeItem(a, id);
    await saveItem(b, id, { ...getItem(b, id)!.data, password: 'edited' });
    await deliver(a, b, 2);
    await deliver(b, a, 2);
    for (const v of [a, b]) {
      const it = getItem(v, id)!;
      expect(it.conflict).toBe(true);
      expect(it.data.password).toBe('edited');
    }
  });

  it('两边改成完全相同内容不算冲突', async () => {
    const { a, b } = await pair();
    const id = await saveItem(a, undefined, newItem('note', 'X'));
    await deliver(a, b);
    const same = { ...getItem(a, id)!.data, notes: 'same', updatedAt: 1 };
    await a.commit('item', id, same);
    await b.commit('item', id, same);
    await deliver(a, b, 2);
    expect(getItem(b, id)!.conflict).toBe(false);
  });

  it('乱序到达时头计算依然正确', async () => {
    const { a, b } = await pair();
    const id = await saveItem(a, undefined, newItem('note', 'v1'));
    await saveItem(a, id, { ...getItem(a, id)!.data, title: 'v2' });
    const versions = a.graph.history('item', id);
    const v1 = versions.find((x) => x.data!.title === 'v1')!;
    const v2 = versions.find((x) => x.data!.title === 'v2')!;
    b.graph.add(v2);
    b.graph.add(v1);
    expect(b.graph.headsOf('item', id).map((h) => h.id)).toEqual([v2.id]);
  });
});

describe('服务器作恶', () => {
  it('跳号（隐瞒变更）触发告警且不写入', async () => {
    const { a, b } = await pair();
    await saveItem(a, undefined, newItem('note', '1'));
    await saveItem(a, undefined, newItem('note', '2'));
    const [, second] = await a.pending();
    const rec = { id: second!.id, gen: 1, blob: second!.blob, device: 'dev-a', seq: 2 };
    await expect(b.ingest([rec], () => undefined)).rejects.toThrow('change_withheld');
    expect(listItems(b)).toHaveLength(0);
  });

  it('重放旧变更触发告警', async () => {
    const { a, b } = await pair();
    await saveItem(a, undefined, newItem('note', '1'));
    const [p] = await a.pending();
    const rec = { id: p!.id, gen: 1, blob: p!.blob, device: 'dev-a', seq: 1 };
    await b.ingest([rec], () => undefined);
    await expect(b.ingest([{ ...rec, seq: 2 }], () => undefined)).rejects.toThrow('change_replayed');
  });

  it('外层字段与签名头不一致触发告警（服务器改作者）', async () => {
    const { a, b } = await pair();
    await saveItem(a, undefined, newItem('note', '1'));
    const [p] = await a.pending();
    const rec = { id: p!.id, gen: 1, blob: p!.blob, device: 'dev-EVIL', seq: 1 };
    await expect(b.ingest([rec], () => undefined)).rejects.toBeInstanceOf(IntegrityAlarm);
  });

  it('用错密钥加密的变更无法解密，触发告警', async () => {
    const { a } = await pair();
    const { v: other } = await makeVault('cloud', 'dev-a');
    await saveItem(other, undefined, newItem('note', 'x'));
    const [p] = await other.pending();
    const header = parseBlob(p!.blob).header;
    const rec = { id: p!.id, gen: 1, blob: p!.blob, device: header.device, seq: 1 };
    await expect(a.ingest([rec], () => undefined)).rejects.toBeInstanceOf(IntegrityAlarm);
  });

  it('变更签名绑定作者，换个公钥验不过', async () => {
    const { v, author } = await makeVault();
    await saveItem(v, undefined, newItem('note', 'x'));
    const [p] = await v.pending();
    const o = parseBlob(p!.blob);
    expect(verifyBlob(o, author.sign.pub)).toBe(true);
    expect(verifyBlob(o, keys().sign.pub)).toBe(false);
  });
});

describe('原子性', () => {
  class FailingKV extends MemoryKV {
    fail = false;
    override async batch(ops: KVOp[]) {
      if (this.fail) throw new Error('disk full');
      return super.batch(ops);
    }
  }

  it('磁盘写入失败时内存和存储都保持旧的完整状态', async () => {
    const kv = new FailingKV();
    const key = randomBytes(32);
    const author = { deviceId: 'd', sign: keys().sign };
    const v = await Vault.create(kv, { vaultId: 'v', policy: 'cloud' }, key, author, () => 1);
    const id = await saveItem(v, undefined, { ...newItem('login', 'A'), password: 'good' });
    kv.fail = true;
    await expect(saveItem(v, id, { ...getItem(v, id)!.data, password: 'bad' })).rejects.toThrow('disk full');
    expect(getItem(v, id)!.data.password).toBe('good');
    expect(v.meta.counter).toBe(1);
    kv.fail = false;
    const reopened = await Vault.open(kv as KV, key, author, () => 1);
    expect(getItem(reopened, id)!.data.password).toBe('good');
    await saveItem(v, id, { ...getItem(v, id)!.data, password: 'after' });
    expect(v.meta.counter).toBe(2);
  });

  it('本地库不产生待发送队列', async () => {
    const { v } = await makeVault('local');
    await saveItem(v, undefined, newItem('note', 'x'));
    expect(await v.pending()).toEqual([]);
  });
});

describe('锁定', () => {
  it('锁定后持有旧引用也写不进去，绝不用全零密钥加密', async () => {
    const { v, kv, key, author } = await makeVault();
    const id = await saveItem(v, undefined, newItem('note', 'keep'));
    const copy = key.slice();
    v.close();
    expect(key.every((b) => b === 0)).toBe(true);
    await expect(saveItem(v, id, newItem('note', 'late'))).rejects.toThrow('vault_locked');
    await expect(v.ingest([], () => undefined)).rejects.toThrow('vault_locked');
    await expect(v.putAttachment(new Uint8Array(1), 'a', 'b')).rejects.toThrow('vault_locked');
    expect(() => v.prepareRotation(randomBytes(32), 2)).toThrow('vault_locked');
    const reopened = await Vault.open(kv, copy, author, () => 7);
    expect(getItem(reopened, id)!.data.title).toBe('keep');
  });
});

describe('换代', () => {
  it('压缩保留所有头和有限历史，待发送的修改用新密钥重新封装', async () => {
    const { v, kv, author } = await makeVault();
    const id = await saveItem(v, undefined, newItem('note', 'v0'));
    for (let i = 1; i <= 30; i++) await saveItem(v, id, { ...getItem(v, id)!.data, title: `v${i}` });
    await v.markUploaded((await v.pending()).map((p) => p.counter));
    await saveItem(v, id, { ...getItem(v, id)!.data, title: 'pending-edit' });

    const newKey = randomBytes(32);
    const { changes } = v.prepareRotation(newKey, 2, 5);
    expect(changes.length).toBeLessThanOrEqual(6);
    await v.enterGeneration(newKey, 2, changes);
    expect(v.gen).toBe(2);
    expect(getItem(v, id)!.data.title).toBe('pending-edit');
    // 该修改已包含在快照里，不必再发
    expect(await v.pending()).toEqual([]);
    const reopened = await Vault.open(kv, newKey, author, () => 1);
    expect(getItem(reopened, id)!.data.title).toBe('pending-edit');
  });

  it('永久删除后，历史内容不再进入快照', async () => {
    const { v } = await makeVault();
    const id = await saveItem(v, undefined, { ...newItem('login', 'gone'), password: 'SHOULD-VANISH' });
    await saveItem(v, id, { ...getItem(v, id)!.data, password: 'SHOULD-VANISH-2' });
    await purgeItem(v, id);
    const kept = v.graph.compacted(20).filter((x) => x.obj === id);
    expect(kept).toHaveLength(1);
    expect(kept[0]!.del).toBe(true);
    expect(JSON.stringify(kept)).not.toContain('VANISH');
  });

  it('本机有而快照没有的头版本不丢，改由本设备重新发出', async () => {
    const { a, b } = await pair();
    const id = await saveItem(a, undefined, newItem('note', 'base'));
    await deliver(a, b);
    await saveItem(b, id, { ...getItem(b, id)!.data, title: 'uploaded-but-missing' });
    // 上传已经确认，待发送队列是空的
    await b.markUploaded((await b.pending()).map((p) => p.counter));
    const newKey = randomBytes(32);
    const { changes } = a.prepareRotation(newKey, 2);
    await b.enterGeneration(newKey, 2, changes);
    expect(getItem(b, id)!.data.title).toBe('uploaded-but-missing');
    const pending = await b.pending();
    expect(pending).toHaveLength(1);
    const o = parseBlob(pending[0]!.blob);
    expect(decryptBlob(o, newKey).device).toBe(o.header.device);
  });

  it('转发别的设备写的版本时，作者改成本设备，和签名一致', async () => {
    const { a, b } = await pair();
    const id = await saveItem(a, undefined, newItem('note', 'from-a'));
    await deliver(a, b);
    const newKey = randomBytes(32);
    await b.enterGeneration(newKey, 2, []);
    expect(getItem(b, id)!.data.title).toBe('from-a');
    const [p] = await b.pending();
    const o = parseBlob(p!.blob);
    expect(o.header.device).toBe('dev-b');
    expect(decryptBlob(o, newKey).device).toBe('dev-b');
  });

  it('本设备尚未进入快照的离线修改被带入新一代', async () => {
    const { a, b } = await pair();
    const id = await saveItem(a, undefined, newItem('note', 'base'));
    await deliver(a, b);
    await saveItem(b, id, { ...getItem(b, id)!.data, title: 'offline-edit' });
    const newKey = randomBytes(32);
    const { changes } = a.prepareRotation(newKey, 2);
    await b.enterGeneration(newKey, 2, changes);
    const pending = await b.pending();
    expect(pending).toHaveLength(1);
    expect(pending[0]!.gen).toBe(2);
    expect(getItem(b, id)!.data.title).toBe('offline-edit');
  });
});

describe('文件夹', () => {
  it('多级树、路径、防环', async () => {
    const { v } = await makeVault();
    const a = await saveFolder(v, undefined, '项目A', null);
    const b = await saveFolder(v, undefined, '系统B', a);
    const c = await saveFolder(v, undefined, '生产环境', b);
    const flat = flattenFolders(folderTree(v));
    expect(flat.map((n) => n.path.join('/'))).toEqual(['项目A', '项目A/系统B', '项目A/系统B/生产环境']);
    await expect(saveFolder(v, a, '项目A', c)).rejects.toThrow('folder_cycle');
  });

  it('并发移动形成的环被确定性打破，不丢节点', async () => {
    const { a, b } = await pair();
    const x = await saveFolder(a, undefined, 'X', null);
    const y = await saveFolder(a, undefined, 'Y', null);
    await deliver(a, b);
    await saveFolder(a, x, 'X', y);
    await saveFolder(b, y, 'Y', x);
    await deliver(a, b, 3);
    await deliver(b, a, 3);
    const ta = flattenFolders(folderTree(a)).map((n) => n.path.join('/'));
    const tb = flattenFolders(folderTree(b)).map((n) => n.path.join('/'));
    expect(ta).toHaveLength(2);
    expect(ta).toEqual(tb);
  });

  it('删除文件夹不删条目，子项上移', async () => {
    const { v } = await makeVault();
    const root = await saveFolder(v, undefined, 'R', null);
    const mid = await saveFolder(v, undefined, 'M', root);
    const leaf = await saveFolder(v, undefined, 'L', mid);
    const id = await saveItem(v, undefined, { ...newItem('note', 'keep'), folder: mid });
    await deleteFolder(v, mid);
    expect(getItem(v, id)!.data.folder).toBe(root);
    const flat = flattenFolders(folderTree(v));
    expect(flat.map((n) => n.id).sort()).toEqual([root, leaf].sort());
    expect(flat.find((n) => n.id === leaf)!.parent).toBe(root);
  });
});

describe('附件', () => {
  it('独立加密，篡改被发现', async () => {
    const { v, kv } = await makeVault();
    const bytes = new TextEncoder().encode('ATTACHMENT-PLAINTEXT');
    const ref = await v.putAttachment(bytes, 'a.txt', 'text/plain');
    expect(await v.readAttachment(ref)).toEqual(bytes);
    const raw = (await kv.get(`b/${ref.id}`))!;
    expect(new TextDecoder('latin1').decode(raw)).not.toContain('ATTACHMENT');
    raw[40]! ^= 1;
    await kv.batch([{ t: 'put', k: `b/${ref.id}`, v: raw }]);
    await expect(v.readAttachment(ref)).rejects.toBeInstanceOf(IntegrityAlarm);
  });
});

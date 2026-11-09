/**
 * 库引擎。三类保险库共用这一套实现，差别只在 policy（数据能走哪条路）。
 *
 * 所有写入都是不可变版本，组成一张 DAG。一个对象有多个头就是冲突，
 * 由用户裁决；绝不按时钟静默覆盖，也不做字段级合并（避免新账号配旧密码）。
 */
import {
  aeadOpen,
  aeadSeal,
  b64d,
  b64e,
  concat,
  edSign,
  edVerify,
  randomBytes,
  randomId,
  sha256,
  utf8d,
  utf8e,
  type SignKeys,
} from './crypto';
import { IntegrityAlarm, MixiaError } from './errors';
import { fromJson, jsonBytes, type KV, type KVOp } from './store';

export type Policy = 'cloud' | 'local' | 'cold';
export type ObjKind = 'item' | 'folder' | 'view' | 'meta';

export interface Version {
  id: string;
  parents: string[];
  ts: number;
  device: string;
  kind: ObjKind;
  obj: string;
  del: boolean;
  data: Record<string, unknown> | null;
}

/** 线上变更记录。服务器只看外层字段。 */
export interface ChangeRecord {
  id: string;
  gen: number;
  blob: string;
  device?: string;
  seq?: number;
}

export interface ChangeHeader {
  v: 1;
  vaultId: string;
  gen: number;
  changeId: string;
  device: string;
  counter: number;
  ledgerSeq: number;
}

export interface Author {
  deviceId: string;
  sign: SignKeys;
}

const CHANGE_PREFIX = 'mixia/change/v1\n';

export function sealChange(
  vk: Uint8Array,
  head: Omit<ChangeHeader, 'v' | 'changeId' | 'device'>,
  author: Author,
  v: Version,
): ChangeRecord {
  const header: ChangeHeader = { v: 1, ...head, changeId: v.id, device: author.deviceId };
  const h = utf8e(JSON.stringify(header));
  const payload = jsonBytes({
    kind: v.kind,
    obj: v.obj,
    ver: { id: v.id, parents: v.parents, ts: v.ts, device: v.device },
    del: v.del,
    data: v.data,
  });
  const { n, c } = aeadSeal(vk, payload, h);
  const s = edSign(author.sign.priv, concat(utf8e(CHANGE_PREFIX), h, n, c));
  const blob = b64e(jsonBytes({ h: b64e(h), n: b64e(n), c: b64e(c), s: b64e(s) }));
  return { id: v.id, gen: head.gen, blob };
}

interface OpenedBlob {
  header: ChangeHeader;
  h: Uint8Array;
  n: Uint8Array;
  c: Uint8Array;
  s: Uint8Array;
}

export function parseBlob(blob: string): OpenedBlob {
  try {
    const o = fromJson<{ h: string; n: string; c: string; s: string }>(b64d(blob));
    const h = b64d(o.h);
    return {
      header: JSON.parse(utf8d(h)) as ChangeHeader,
      h,
      n: b64d(o.n),
      c: b64d(o.c),
      s: b64d(o.s),
    };
  } catch {
    throw new IntegrityAlarm('malformed_change');
  }
}

export function verifyBlob(o: OpenedBlob, signPub: Uint8Array): boolean {
  return edVerify(signPub, concat(utf8e(CHANGE_PREFIX), o.h, o.n, o.c), o.s);
}

export function decryptBlob(o: OpenedBlob, vk: Uint8Array): Version {
  const plain = aeadOpen(vk, o.n, o.c, o.h);
  const p = fromJson<{
    kind: ObjKind;
    obj: string;
    ver: { id: string; parents: string[]; ts: number; device: string };
    del: boolean;
    data: Record<string, unknown> | null;
  }>(plain);
  return {
    id: p.ver.id,
    parents: p.ver.parents,
    ts: p.ver.ts,
    device: p.ver.device,
    kind: p.kind,
    obj: p.obj,
    del: p.del,
    data: p.data,
  };
}

const objKey = (kind: ObjKind, obj: string) => `${kind}:${obj}`;

export interface Resolved {
  current: Version | undefined;
  heads: Version[];
  conflict: boolean;
  deleted: boolean;
}

/** 内存中的版本图。纯数据结构，不碰存储。 */
export class VersionGraph {
  versions = new Map<string, Version>();
  private heads = new Map<string, Set<string>>();
  /** 已被其他版本引用为父版本的 id；乱序到达时用来判定新版本不是头。 */
  private referenced = new Set<string>();

  has(id: string): boolean {
    return this.versions.has(id);
  }

  /** 用另一张图整体替换本图内容，保持外部持有的引用有效。 */
  adopt(other: VersionGraph): void {
    this.versions = other.versions;
    this.heads = other.heads;
    this.referenced = other.referenced;
  }

  add(v: Version): void {
    if (this.versions.has(v.id)) return;
    this.versions.set(v.id, v);
    const key = objKey(v.kind, v.obj);
    let hs = this.heads.get(key);
    if (!hs) this.heads.set(key, (hs = new Set()));
    for (const p of v.parents) {
      this.referenced.add(p);
      hs.delete(p);
    }
    if (!this.referenced.has(v.id)) hs.add(v.id);
  }

  allHeads(): Version[] {
    const out: Version[] = [];
    for (const hs of this.heads.values()) for (const id of hs) out.push(this.versions.get(id)!);
    return out;
  }

  headsOf(kind: ObjKind, obj: string): Version[] {
    const hs = this.heads.get(objKey(kind, obj));
    if (!hs) return [];
    return [...hs].map((id) => this.versions.get(id)!);
  }

  objects(kind: ObjKind): string[] {
    const prefix = `${kind}:`;
    const out: string[] = [];
    for (const k of this.heads.keys()) if (k.startsWith(prefix)) out.push(k.slice(prefix.length));
    return out;
  }

  /** 同一输入在所有设备上得到同一结果，排序不依赖到达顺序。 */
  resolve(kind: ObjKind, obj: string): Resolved {
    const heads = this.headsOf(kind, obj).sort(
      (a, b) => b.ts - a.ts || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
    );
    const live = heads.filter((h) => !h.del);
    if (live.length === 0) {
      return { current: heads[0], heads, conflict: false, deleted: true };
    }
    const distinct = new Set(heads.map((h) => (h.del ? '\0del' : JSON.stringify(h.data))));
    return { current: live[0], heads, conflict: distinct.size > 1, deleted: false };
  }

  /** 按时间倒序的该对象全部已知版本。 */
  history(kind: ObjKind, obj: string): Version[] {
    return [...this.versions.values()]
      .filter((v) => v.kind === kind && v.obj === obj)
      .sort((a, b) => b.ts - a.ts);
  }

  /** 换钥和导出用：保留所有头和每个对象最近 keep 个历史版本。 */
  compacted(keep: number): Version[] {
    const out: Version[] = [];
    const byObj = new Map<string, Version[]>();
    for (const v of this.versions.values()) {
      const k = objKey(v.kind, v.obj);
      const list = byObj.get(k);
      if (list) list.push(v);
      else byObj.set(k, [v]);
    }
    for (const [key, list] of byObj) {
      const heads = this.heads.get(key) ?? new Set<string>();
      list.sort((a, b) => b.ts - a.ts);
      // 永久删除的对象只留墓碑：历史内容不再进入快照和备份
      const purged = [...heads].every((id) => this.versions.get(id)?.del);
      let kept = 0;
      for (const v of list) {
        if (heads.has(v.id)) out.push(v);
        else if (!purged && kept < keep) {
          out.push(v);
          kept++;
        }
      }
    }
    return out.sort((a, b) => a.ts - b.ts || (a.id < b.id ? -1 : 1));
  }
}

export interface VaultMeta {
  vaultId: string;
  policy: Policy;
  gen: number;
  readOnly: boolean;
  /** 服务器日志已处理到的序号，云库专用。 */
  lastSeq: number;
  nextLocal: number;
  /** 本设备下一个 counter - 1。 */
  counter: number;
  /** `device:gen` → 已见到的最大 counter，发现跳号或重放用。 */
  peers: Record<string, number>;
  createdAt: number;
  /** 上次成功导出备份的时间；为 0 时界面提示未备份。 */
  lastBackupAt: number;
}

const META_KEY = 'meta';
const pad = (n: number) => n.toString().padStart(12, '0');

export interface PendingChange {
  id: string;
  gen: number;
  blob: string;
  counter: number;
}

export class Vault {
  readonly graph = new VersionGraph();
  private listeners = new Set<() => void>();
  private closed = false;

  private constructor(
    private kv: KV,
    public meta: VaultMeta,
    private key: Uint8Array,
    private author: Author,
    private ledgerSeq: () => number,
  ) {}

  get id() {
    return this.meta.vaultId;
  }
  get policy() {
    return this.meta.policy;
  }
  get readOnly() {
    return this.meta.readOnly;
  }
  get gen() {
    return this.meta.gen;
  }
  /** 只给换钥和 Pack 使用。 */
  get vaultKey() {
    return this.key;
  }

  onChange(fn: () => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  /**
   * 锁定：清零密钥并拒绝后续操作。必须走这里而不是直接清零，
   * 否则还持有引用的代码（比如进行中的同步）会用全零密钥写入数据。
   */
  close(): void {
    this.closed = true;
    this.key.fill(0);
  }

  private assertOpen(): void {
    if (this.closed) throw new MixiaError('vault_locked');
  }

  private emit() {
    for (const l of this.listeners) l();
  }

  static async create(
    kv: KV,
    init: { vaultId: string; policy: Policy; gen?: number; readOnly?: boolean },
    key: Uint8Array,
    author: Author,
    ledgerSeq: () => number,
  ): Promise<Vault> {
    const meta: VaultMeta = {
      vaultId: init.vaultId,
      policy: init.policy,
      gen: init.gen ?? 1,
      readOnly: init.readOnly ?? false,
      lastSeq: 0,
      nextLocal: 1,
      counter: 0,
      peers: {},
      createdAt: Date.now(),
      lastBackupAt: 0,
    };
    await kv.batch([{ t: 'put', k: META_KEY, v: jsonBytes(meta) }]);
    return new Vault(kv, meta, key, author, ledgerSeq);
  }

  static async open(
    kv: KV,
    key: Uint8Array,
    author: Author,
    ledgerSeq: () => number,
  ): Promise<Vault> {
    const raw = await kv.get(META_KEY);
    if (!raw) throw new MixiaError('vault_missing');
    const v = new Vault(kv, fromJson<VaultMeta>(raw), key, author, ledgerSeq);
    for (const [, blob] of await kv.scan('c/')) {
      // 本地已验证过签名；AEAD 仍然保证磁盘上的内容没被改动
      v.graph.add(decryptBlob(parseBlob(utf8d(blob)), key));
    }
    return v;
  }

  static async metaOf(kv: KV): Promise<VaultMeta | undefined> {
    const raw = await kv.get(META_KEY);
    return raw ? fromJson<VaultMeta>(raw) : undefined;
  }

  private metaOp(m: VaultMeta): KVOp {
    return { t: 'put', k: META_KEY, v: jsonBytes(m) };
  }

  /** 写入一个新版本。批量写失败时内存状态不变，不会出现半写。 */
  async commit(
    kind: ObjKind,
    obj: string,
    data: Record<string, unknown> | null,
    opts: { del?: boolean; parents?: string[] } = {},
  ): Promise<Version> {
    const parents = opts.parents ?? this.graph.headsOf(kind, obj).map((h) => h.id);
    const v: Version = {
      id: randomId(),
      parents,
      ts: Date.now(),
      device: this.author.deviceId,
      kind,
      obj,
      del: opts.del ?? false,
      data,
    };
    await this.commitVersions([v]);
    return v;
  }

  /** 批量写入本设备创作的版本，作者字段统一填本设备。 */
  async commitAuthored(versions: Version[]): Promise<void> {
    await this.commitVersions(versions.map((v) => ({ ...v, device: this.author.deviceId })));
  }

  /** 批量写入，一次事务；保留版本原作者，导入时用。 */
  async commitVersions(versions: Version[]): Promise<void> {
    this.assertOpen();
    if (versions.length === 0) return;
    if (this.meta.readOnly) throw new MixiaError('vault_read_only');
    const next: VaultMeta = { ...this.meta, peers: { ...this.meta.peers } };
    const ops: KVOp[] = [];
    for (const v of versions) {
      next.counter += 1;
      const rec = sealChange(
        this.key,
        {
          vaultId: this.id,
          gen: this.meta.gen,
          counter: next.counter,
          ledgerSeq: this.ledgerSeq(),
        },
        this.author,
        v,
      );
      ops.push({ t: 'put', k: `c/${pad(next.nextLocal)}`, v: utf8e(rec.blob) });
      next.nextLocal += 1;
      if (this.policy === 'cloud') {
        const pending: PendingChange = { ...rec, counter: next.counter };
        ops.push({ t: 'put', k: `o/${pad(next.counter)}`, v: jsonBytes(pending) });
      }
    }
    ops.push(this.metaOp(next));
    await this.kv.batch(ops);
    this.meta = next;
    for (const v of versions) this.graph.add(v);
    this.emit();
  }

  async pending(): Promise<PendingChange[]> {
    const rows = await this.kv.scan('o/');
    return rows.map(([, v]) => fromJson<PendingChange>(v));
  }

  async pendingCount(): Promise<number> {
    return (await this.kv.scan('o/')).length;
  }

  async markUploaded(counters: number[]): Promise<void> {
    await this.kv.batch(counters.map((c) => ({ t: 'del', k: `o/${pad(c)}` }) as KVOp));
  }

  /**
   * 接收服务器变更。verifySigner 由同步层注入，负责用账本校验作者身份和签名。
   * 任一条校验失败都不写入本批内容。
   */
  async ingest(
    changes: ChangeRecord[],
    verifySigner: (o: OpenedBlob, c: ChangeRecord) => void,
  ): Promise<number> {
    this.assertOpen();
    const next: VaultMeta = { ...this.meta, peers: { ...this.meta.peers } };
    const ops: KVOp[] = [];
    const added: Version[] = [];
    for (const c of changes) {
      const o = parseBlob(c.blob);
      const h = o.header;
      if (
        h.vaultId !== this.id ||
        h.changeId !== c.id ||
        h.device !== c.device ||
        h.gen !== c.gen ||
        h.v !== 1
      ) {
        throw new IntegrityAlarm('change_header_mismatch');
      }
      if (h.gen !== this.meta.gen) throw new IntegrityAlarm('change_wrong_gen');
      verifySigner(o, c);
      const peer = `${h.device}:${h.gen}`;
      const last = next.peers[peer] ?? 0;
      if (h.counter <= last) throw new IntegrityAlarm('change_replayed');
      if (h.counter !== last + 1) throw new IntegrityAlarm('change_withheld');
      next.peers[peer] = h.counter;
      let v: Version;
      try {
        v = decryptBlob(o, this.key);
      } catch {
        throw new IntegrityAlarm('change_undecryptable');
      }
      if (v.id !== c.id || v.device !== h.device) throw new IntegrityAlarm('change_payload_mismatch');
      if (!this.graph.has(v.id) && !added.some((a) => a.id === v.id)) {
        ops.push({ t: 'put', k: `c/${pad(next.nextLocal)}`, v: utf8e(c.blob) });
        next.nextLocal += 1;
        added.push(v);
      }
      if (c.seq !== undefined && c.seq > next.lastSeq) next.lastSeq = c.seq;
    }
    ops.push(this.metaOp(next));
    await this.kv.batch(ops);
    this.meta = next;
    for (const v of added) this.graph.add(v);
    if (added.length) this.emit();
    return added.length;
  }

  /**
   * 换钥第一步：用新密钥封装快照，不改动本地状态。
   * 快照的 counter 从 1 开始，属于执行换钥的设备。
   */
  prepareRotation(
    newKey: Uint8Array,
    newGen: number,
    keep = 20,
  ): { changes: ChangeRecord[]; snapshotHash: string } {
    this.assertOpen();
    const versions = this.graph.compacted(keep);
    const changes = versions.map((v, i) =>
      sealChange(
        newKey,
        { vaultId: this.id, gen: newGen, counter: i + 1, ledgerSeq: this.ledgerSeq() },
        this.author,
        v,
      ),
    );
    return { changes, snapshotHash: snapshotHash(changes) };
  }

  /**
   * 进入新一代：清空日志，换密钥。
   * 待发送的修改和本机所有不在快照里的头版本都用新密钥重新封装发出去。
   * 后者是防丢数据的关键：换钥快照可能没包含刚上传成功的修改，
   * 本机绝不因为一份快照就丢弃用户写过的内容。
   */
  async enterGeneration(newKey: Uint8Array, newGen: number, snapshot: ChangeRecord[]): Promise<void> {
    this.assertOpen();
    const oldPending = await this.pending();
    const pendingVersions: Version[] = [];
    for (const p of oldPending) {
      pendingVersions.push(decryptBlob(parseBlob(p.blob), this.key));
    }
    const ops: KVOp[] = [];
    for (const [k] of await this.kv.scan('c/')) ops.push({ t: 'del', k });
    for (const [k] of await this.kv.scan('o/')) ops.push({ t: 'del', k });

    const next: VaultMeta = {
      ...this.meta,
      gen: newGen,
      lastSeq: 0,
      nextLocal: 1,
      counter: 0,
      peers: {},
    };
    const fresh = new VersionGraph();
    for (const c of snapshot) {
      const o = parseBlob(c.blob);
      const v = decryptBlob(o, newKey);
      fresh.add(v);
      ops.push({ t: 'put', k: `c/${pad(next.nextLocal)}`, v: utf8e(c.blob) });
      next.nextLocal += 1;
      const peer = `${o.header.device}:${newGen}`;
      next.peers[peer] = Math.max(next.peers[peer] ?? 0, o.header.counter);
      if (o.header.device === this.author.deviceId) next.counter = Math.max(next.counter, o.header.counter);
      if (c.seq !== undefined && c.seq > next.lastSeq) next.lastSeq = c.seq;
    }
    const carry = new Map<string, Version>();
    for (const v of pendingVersions) if (!fresh.has(v.id)) carry.set(v.id, v);
    for (const v of this.graph.allHeads()) if (!fresh.has(v.id)) carry.set(v.id, v);
    for (const original of carry.values()) {
      // 由本设备转发，作者字段要和签名一致
      const v: Version = { ...original, device: this.author.deviceId };
      next.counter += 1;
      const rec = sealChange(
        newKey,
        { vaultId: this.id, gen: newGen, counter: next.counter, ledgerSeq: this.ledgerSeq() },
        this.author,
        v,
      );
      ops.push({ t: 'put', k: `c/${pad(next.nextLocal)}`, v: utf8e(rec.blob) });
      next.nextLocal += 1;
      const pending: PendingChange = { ...rec, counter: next.counter };
      ops.push({ t: 'put', k: `o/${pad(next.counter)}`, v: jsonBytes(pending) });
      fresh.add(v);
    }
    ops.push(this.metaOp(next));
    await this.kv.batch(ops);
    this.meta = next;
    this.key = newKey;
    this.graph.adopt(fresh);
    this.emit();
  }

  /** 把 Pack 中的版本写入本库。用于导入快照，保留原版本 id 和 DAG。 */
  async importVersions(versions: Version[], opts: { readOnly: boolean }): Promise<void> {
    const wasRO = this.meta.readOnly;
    this.meta = { ...this.meta, readOnly: false };
    try {
      await this.commitVersions(versions.filter((v) => !this.graph.has(v.id)));
    } finally {
      this.meta = { ...this.meta, readOnly: opts.readOnly || wasRO };
      await this.kv.batch([this.metaOp(this.meta)]);
    }
  }

  async markBackedUp(at = Date.now()): Promise<void> {
    const next = { ...this.meta, lastBackupAt: at };
    await this.kv.batch([this.metaOp(next)]);
    this.meta = next;
  }

  /** 附件：独立随机密钥加密，密钥存在条目内。 */
  async putAttachment(bytes: Uint8Array, name: string, type: string): Promise<AttachmentRef> {
    this.assertOpen();
    const id = randomId();
    const key = randomBytes(32);
    const { n, c } = aeadSeal(key, bytes, utf8e(`mixia/att/v1\n${id}`));
    const packed = concat(n, c);
    const ops: KVOp[] = [{ t: 'put', k: `b/${id}`, v: packed }];
    if (this.policy === 'cloud') ops.push({ t: 'put', k: `ob/${id}`, v: new Uint8Array(1) });
    await this.kv.batch(ops);
    return { id, name, type, size: bytes.length, key: b64e(key) };
  }

  async readAttachment(
    ref: AttachmentRef,
    fetchRemote?: (id: string) => Promise<Uint8Array>,
  ): Promise<Uint8Array> {
    const local = await this.kv.get(`b/${ref.id}`);
    if (!local && !fetchRemote) throw new MixiaError('attachment_unavailable');
    const packed = local ?? (await fetchRemote!(ref.id));
    let plain: Uint8Array;
    try {
      plain = aeadOpen(b64d(ref.key), packed.slice(0, 24), packed.slice(24), utf8e(`mixia/att/v1\n${ref.id}`));
    } catch {
      throw new IntegrityAlarm('attachment_corrupt');
    }
    // 校验通过才缓存，被篡改的内容不留在本机
    if (!local) await this.kv.batch([{ t: 'put', k: `b/${ref.id}`, v: packed }]);
    return plain;
  }

  /** 备份用：本机持有的附件密文，附件密钥随条目一起在快照里。 */
  async attachmentBlobs(): Promise<Record<string, string>> {
    const out: Record<string, string> = {};
    for (const [k, v] of await this.kv.scan('b/')) out[k.slice(2)] = b64e(v);
    return out;
  }

  async importAttachmentBlobs(blobs: Record<string, string>): Promise<void> {
    const ops = Object.entries(blobs).map(([id, b]) => ({ t: 'put', k: `b/${id}`, v: b64d(b) }) as KVOp);
    if (ops.length) await this.kv.batch(ops);
  }

  async pendingAttachments(): Promise<string[]> {
    return (await this.kv.scan('ob/')).map(([k]) => k.slice(3));
  }

  async attachmentBytes(id: string): Promise<Uint8Array | undefined> {
    return this.kv.get(`b/${id}`);
  }

  async attachmentUploaded(id: string): Promise<void> {
    await this.kv.batch([{ t: 'del', k: `ob/${id}` }]);
  }

  async destroyStorage(): Promise<void> {
    await this.kv.destroy();
  }
}

export interface AttachmentRef {
  id: string;
  name: string;
  type: string;
  size: number;
  key: string;
}

export function snapshotHash(changes: ChangeRecord[]): string {
  const parts: Uint8Array[] = [];
  for (const c of changes) parts.push(utf8e(c.id), b64d(c.blob));
  return b64e(sha256(concat(...parts)));
}

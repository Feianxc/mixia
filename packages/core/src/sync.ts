/**
 * 同步。只处理云库；本地库和冷库的对象根本不进入这个模块。
 * 服务器提供的一切都当作不可信输入：账本从创世重新校验，变更逐条验签，
 * 发现回滚、分叉、隐瞒时抛 IntegrityAlarm 并停止写入，不做自动修复。
 */
import { ApiError, type ServerApi } from './api';
import { b64d, b64e, boxOpen, concat, kdf, type BoxKeys } from './crypto';
import { IntegrityAlarm, MixiaError } from './errors';
import { entryHash, LedgerState, replay, type LedgerEntry, type VaultInfo } from './ledger';
import { fromJson, jsonBytes, type KV, type KVOp } from './store';
import { snapshotHash, parseBlob, verifyBlob, type ChangeRecord, type Vault } from './vault';

export function keyCommit(vk: Uint8Array, vaultId: string, gen: number): string {
  return b64e(kdf(vk, `mixia/vk-commit/v1\n${vaultId}\n${gen}`));
}

/** 持久化的账本。写入前先完整重放校验，失败不落盘。 */
export class LedgerBook {
  state = new LedgerState();
  entries: LedgerEntry[] = [];

  private constructor(private kv: KV) {}

  static async load(kv: KV): Promise<LedgerBook> {
    const b = new LedgerBook(kv);
    const rows = await kv.scan('ledger/e/');
    b.entries = rows.map(([, v]) => fromJson<LedgerEntry>(v));
    b.state = replay(b.entries);
    const pin = await kv.get('ledger/pin');
    if (pin && b.entries.length > 0) {
      if (fromJson<string>(pin) !== b.state.genesisHash) throw new IntegrityAlarm('genesis_changed');
    }
    return b;
  }

  /** 钉住创世哈希。此后任何不同根的账本都被拒绝。 */
  async pin(genesisHash: string): Promise<void> {
    await this.kv.batch([{ t: 'put', k: 'ledger/pin', v: jsonBytes(genesisHash) }]);
  }

  async pinned(): Promise<string | undefined> {
    const p = await this.kv.get('ledger/pin');
    return p ? fromJson<string>(p) : undefined;
  }

  async accept(entries: LedgerEntry[]): Promise<void> {
    if (entries.length === 0) return;
    const next = replay([...this.entries, ...entries]);
    const pin = await this.pinned();
    if (pin && pin !== next.genesisHash) throw new IntegrityAlarm('genesis_mismatch');
    const ops: KVOp[] = entries.map((e, i) => ({
      t: 'put',
      k: `ledger/e/${(this.entries.length + i).toString().padStart(10, '0')}`,
      v: jsonBytes(e),
    }));
    await this.kv.batch(ops);
    this.entries.push(...entries);
    this.state = next;
  }

  /** 拉取并校验。检测服务器回退或分叉。 */
  async pull(api: ServerApi): Promise<number> {
    const from = this.state.seq;
    const res = await api.getLedger(from);
    if (typeof res.head !== 'number' || !Array.isArray(res.entries)) {
      throw new IntegrityAlarm('malformed_response');
    }
    if (res.head < from) throw new IntegrityAlarm('ledger_rollback');
    const first = res.entries[0];
    if (!first) throw new IntegrityAlarm('ledger_rollback');
    if (entryHash(first) !== this.state.headHash) throw new IntegrityAlarm('ledger_fork');
    const rest = res.entries.slice(1);
    try {
      await this.accept(rest);
    } catch (e) {
      if (e instanceof MixiaError && !(e instanceof IntegrityAlarm)) {
        throw new IntegrityAlarm('ledger_tampered', e.message);
      }
      throw e;
    }
    return rest.length;
  }
}

export interface VaultKeyring {
  get(vaultId: string, gen: number): Promise<Uint8Array | undefined>;
  put(vaultId: string, gen: number, key: Uint8Array): Promise<void>;
}

export class SyncEngine {
  constructor(
    private api: ServerApi,
    private book: LedgerBook,
    private box: BoxKeys,
    private keyring: VaultKeyring,
  ) {}

  /** 取库密钥。服务器给的封装必须能通过账本里已签名的 keyCommit 校验。 */
  async keyFor(info: VaultInfo): Promise<Uint8Array> {
    const cached = await this.keyring.get(info.vaultId, info.gen);
    if (cached) return cached;
    const { keys } = await this.api.getKeys(info.vaultId);
    const w = keys.find((k) => k.gen === info.gen);
    if (!w) throw new MixiaError('key_not_granted');
    let vk: Uint8Array;
    try {
      vk = boxOpen(this.box, b64d(w.wrapped));
    } catch {
      throw new IntegrityAlarm('key_unwrap_failed');
    }
    if (keyCommit(vk, info.vaultId, info.gen) !== info.keyCommit) {
      throw new IntegrityAlarm('key_commit_mismatch');
    }
    await this.keyring.put(info.vaultId, info.gen, vk);
    return vk;
  }

  private verifier() {
    const st = this.book.state;
    return (o: ReturnType<typeof parseBlob>) => {
      const dev = st.devices.get(o.header.device);
      if (!dev) throw new IntegrityAlarm('change_unknown_author');
      if (!verifyBlob(o, b64d(dev.signPub))) throw new IntegrityAlarm('change_bad_signature');
      // 被撤销设备不能在撤销之后写入：头部声明的账本序号不得晚于撤销序号。
      // 伪造旧序号的情况由换钥兜底（旧代变更不被接受）。
      if (dev.revokedSeq !== undefined && o.header.ledgerSeq >= dev.revokedSeq) {
        throw new IntegrityAlarm('change_from_revoked');
      }
    };
  }

  /**
   * 设备互证：变更头里写着作者当时看到的账本序号。比本机新，说明账本有尾部没给我。
   * 这是发现“服务器对我隐瞒撤销记录”的主要手段。先重新拉一次，排除正常的时序差。
   */
  private async checkLedgerNotWithheld(changes: ChangeRecord[]): Promise<void> {
    let highest = -1;
    for (const c of changes) highest = Math.max(highest, parseBlob(c.blob).header.ledgerSeq);
    if (highest <= this.book.state.seq) return;
    await this.book.pull(this.api);
    if (highest > this.book.state.seq) throw new IntegrityAlarm('ledger_withheld');
  }

  private async fetchAll(vaultId: string, after: number): Promise<{ all: ChangeRecord[]; gen: number; base: number; head: number }> {
    const all: ChangeRecord[] = [];
    let cursor = after;
    for (;;) {
      const page = await this.api.getChanges(vaultId, cursor, 500);
      all.push(...page.changes);
      const last = page.changes[page.changes.length - 1];
      if (!last || page.changes.length < 500) {
        return { all, gen: page.gen, base: page.base, head: page.head };
      }
      cursor = last.seq!;
    }
  }

  /** 进入账本记录的新一代：全量拉取并校验快照。 */
  private async resync(v: Vault, info: VaultInfo): Promise<void> {
    const key = await this.keyFor(info);
    const { all, gen } = await this.fetchAll(v.id, 0);
    if (gen !== info.gen) throw new IntegrityAlarm('gen_mismatch');
    if (all.length < info.snapshotCount) throw new IntegrityAlarm('snapshot_incomplete');
    const snapshot = all.slice(0, info.snapshotCount);
    if (snapshotHash(snapshot) !== info.snapshotHash) throw new IntegrityAlarm('snapshot_tampered');
    await this.checkLedgerNotWithheld(all);
    const check = this.verifier();
    for (const c of snapshot) {
      const o = parseBlob(c.blob);
      if (o.header.gen !== info.gen || o.header.vaultId !== v.id) {
        throw new IntegrityAlarm('snapshot_tampered');
      }
      check(o);
    }
    await v.enterGeneration(key, info.gen, snapshot);
    const rest = all.slice(info.snapshotCount);
    if (rest.length) await v.ingest(rest, check);
  }

  async pullVault(v: Vault): Promise<number> {
    const info = this.book.state.vaults.get(v.id);
    if (!info) throw new MixiaError('vault_gone');
    if (info.gen < v.gen) throw new IntegrityAlarm('gen_rollback');
    if (info.gen > v.gen) await this.resync(v, info);

    let total = 0;
    for (;;) {
      const after = v.meta.lastSeq;
      const page = await this.api.getChanges(v.id, after, 500);
      if (
        typeof page.head !== 'number' ||
        typeof page.base !== 'number' ||
        typeof page.gen !== 'number' ||
        !Array.isArray(page.changes)
      ) {
        throw new IntegrityAlarm('malformed_response');
      }
      if (page.gen < v.gen) throw new IntegrityAlarm('gen_rollback');
      if (page.head < after) throw new IntegrityAlarm('log_rollback');
      if (page.gen > v.gen) {
        // 账本比变更日志旧：先刷新账本，下一轮同步再处理
        await this.book.pull(this.api);
        const fresh = this.book.state.vaults.get(v.id);
        if (!fresh || fresh.gen !== page.gen) throw new IntegrityAlarm('gen_mismatch');
        await this.resync(v, fresh);
        continue;
      }
      if (page.base - 1 > after) throw new IntegrityAlarm('log_truncated');
      if (page.changes.length === 0) break;
      await this.checkLedgerNotWithheld(page.changes);
      total += await v.ingest(page.changes, this.verifier());
      if (page.changes.length < 500) break;
    }
    return total;
  }

  /**
   * 附件单独上传，不走同步主路径。经隧道进入国内的上行可能只有几十 KB/s，
   * 一个大附件不能挡住小而关键的密码条目。
   */
  async pushAttachments(v: Vault): Promise<void> {
    for (const id of await v.pendingAttachments()) {
      const bytes = await v.attachmentBytes(id);
      if (bytes) await this.api.putBlob(v, id, bytes);
      await v.attachmentUploaded(id);
    }
  }

  async pushVault(v: Vault): Promise<number> {
    const pending = await v.pending();
    let sent = 0;
    for (let i = 0; i < pending.length; i += 100) {
      const batch = pending.slice(i, i + 100);
      const res = await this.api.pushChanges(
        v,
        batch.map(({ id, gen, blob }) => ({ id, gen, blob })),
      );
      // 服务器说收到了才算数，只回 200 不算
      const got = new Set((res.accepted ?? []).map((a) => a.id));
      if (!batch.every((p) => got.has(p.id))) throw new IntegrityAlarm('push_not_accepted');
      await v.markUploaded(batch.map((p) => p.counter));
      sent += batch.length;
    }
    return sent;
  }

  /** 一轮完整同步：先拉后推。推送遇到换钥时刷新后重试一次。 */
  async syncVault(v: Vault): Promise<{ pulled: number; pushed: number }> {
    const pulled = await this.pullVault(v);
    if (v.readOnly) return { pulled, pushed: 0 };
    try {
      return { pulled, pushed: await this.pushVault(v) };
    } catch (e) {
      if (e instanceof ApiError && e.code === 'stale_gen') {
        await this.book.pull(this.api);
        const again = await this.pullVault(v);
        return { pulled: pulled + again, pushed: await this.pushVault(v) };
      }
      throw e;
    }
  }
}

/** 设备指纹覆盖全部三把公钥，换掉任何一把用户都能在批准时看出来。 */
export const deviceFingerprint = (d: { authPub: string; signPub: string; boxPub: string }): string =>
  fingerprint(concat(b64d(d.authPub), b64d(d.signPub), b64d(d.boxPub)));

export const fingerprint = (bytes: Uint8Array): string => {
  const h = b64e(kdf(new Uint8Array(32).fill(7), bytes)).toUpperCase().replace(/[^0-9A-Z]/g, '');
  return (h.slice(0, 16).match(/.{4}/g) ?? []).join(' ');
};


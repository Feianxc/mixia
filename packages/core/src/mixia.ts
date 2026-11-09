/**
 * 应用门面：界面只和这个类打交道。
 * 所有流程（初始化、配对、恢复、撤销换钥、本地库、冷库）在这里编排，便于用真实服务端集成测试。
 */
import { ApiError, ServerApi, type RequestSigner, type Transport, type WrappedKey } from './api';
import {
  newRecoveryCode,
  newPairCode,
  parsePairCode,
  parseRecoveryCode,
  rootKeysFrom,
  vaultRecoveryBox,
  type PairCode,
  type RootKeys,
} from './codes';
import {
  aeadOpen,
  aeadSeal,
  argon2id,
  b64d,
  b64e,
  boxOpen,
  boxSeal,
  concat,
  edSign,
  initCrypto,
  kdf,
  newKdfParams,
  randomBytes,
  randomId,
  sha256,
  utf8d,
  utf8e,
  type KdfParams,
} from './crypto';
import { DeviceStore, type DeviceSession, type HardwareKeys } from './device';
import { IntegrityAlarm, MixiaError } from './errors';
import {
  LedgerState,
  entryHash,
  nextBody,
  replay,
  signEntry,
  type DeviceInfo,
  type EntryType,
  type LedgerEntry,
  type Level,
  type Role,
} from './ledger';
import {
  flattenFolders,
  folderTree,
  getItem,
  listItems,
  newItem,
  saveFolder,
  saveItem,
  setVaultName,
  vaultName,
  type ItemData,
  type ItemView,
} from './model';
import {
  createPack,
  openPackWithBox,
  openPackWithCold,
  readPackHeader,
  type PackHeader,
  type Snapshot,
} from './pack';
import { MemoryKV, fromJson, jsonBytes, type KV } from './store';
import { LedgerBook, SyncEngine, deviceFingerprint, keyCommit, type VaultKeyring } from './sync';
import type { ImportRow } from './transfer';
import { Vault, VersionGraph, type Policy, type Version } from './vault';

export interface PlatformEnv {
  hw: HardwareKeys;
  http: Transport;
  /** 打开一个独立命名空间的存储。本地库和云库各有自己的实例。 */
  openKV(name: string): KV;
  info: { platform: string; defaultName: string; kdfMem?: number };
  /** 钉住服务器来源：外壳此后拒绝连接其他主机。擦除设备时解除。 */
  pinServer?(url: string): Promise<void>;
  unpinServer?(): Promise<void>;
  /** 这个实例不同步。手机自动填充窗口和主窗口是两个实例，共用存储，只能有一个写。 */
  noSync?: boolean;
}

export type Phase = 'fresh' | 'locked' | 'unlocked';

interface Settings {
  serverUrl: string;
}

export interface Prefs {
  autoLockMinutes: number;
  localLockMinutes: number;
  clipboardSeconds: number;
  quickUnlock: boolean;
}

export const DEFAULT_PREFS: Prefs = {
  autoLockMinutes: 5,
  localLockMinutes: 2,
  clipboardSeconds: 30,
  quickUnlock: false,
};

interface LocalRecord {
  vaultId: string;
  kdf: KdfParams;
  n: string;
  c: string;
  /** 名称用解锁密钥加密，不留明文。 */
  nameN: string;
  nameC: string;
  readOnly: boolean;
}

export interface VaultSummary {
  id: string;
  name: string;
  policy: Policy;
  locked: boolean;
  readOnly: boolean;
  count: number;
  pending: number;
  lastBackupAt: number;
  gen: number;
}

export interface SyncStatus {
  state: 'idle' | 'syncing' | 'offline' | 'error' | 'alarm' | 'none';
  lastSyncAt: number;
  error?: string;
  alarm?: { code: string; at: number; vaultId?: string };
}

export interface PendingDevice {
  name: string;
  platform: string;
  level: Level;
  fingerprint: string;
  deviceId: string;
  raw: PairRequest;
}

interface PairRequest {
  name: string;
  platform: string;
  level: Level;
  authPub: string;
  signPub: string;
  boxPub: string;
}

function pairKeys(secret: string) {
  const ikm = utf8e(secret);
  return { key: kdf(ikm, 'mixia/pair/key/v1'), token: b64e(kdf(ikm, 'mixia/pair/token/v1')) };
}

const PAIR_AAD = utf8e('mixia/pair/v1');
function pairSeal(key: Uint8Array, v: unknown): string {
  const { n, c } = aeadSeal(key, jsonBytes(v), PAIR_AAD);
  return b64e(concat(n, c));
}
function pairOpen<T>(key: Uint8Array, text: string): T {
  const b = b64d(text);
  try {
    return fromJson<T>(aeadOpen(key, b.slice(0, 24), b.slice(24), PAIR_AAD));
  } catch {
    throw new IntegrityAlarm('pair_tampered');
  }
}

function localSlotKey(secret: Uint8Array, passphrase: string, params: KdfParams): Uint8Array {
  return kdf(secret, concat(utf8e('mixia/local-slot/v1\n'), argon2id(passphrase, params)));
}

export interface JoinState {
  serverUrl: string;
  code: PairCode;
  genesisHash: string;
  adminName: string;
  api: ServerApi;
}

export class ColdVault {
  constructor(
    readonly vault: Vault,
    readonly name: string,
    private passphrase: string,
    private code: Uint8Array,
    private mem?: number,
  ) {}

  /** 冷库不落盘，保存就是生成新的 Pack 字节。写到哪里由用户决定。 */
  async save(): Promise<Uint8Array> {
    return createPack('cold', this.vault.gen, await snapshotOf(this.vault, this.name), [
      { t: 'pw', passphrase: this.passphrase, code: this.code, ...(this.mem ? { mem: this.mem } : {}) },
    ]);
  }
}

async function snapshotOf(v: Vault, name: string, keep = 50): Promise<Snapshot> {
  return {
    vaultId: v.id,
    name,
    policy: v.policy,
    versions: v.graph.compacted(keep),
    exportedAt: Date.now(),
    blobs: await v.attachmentBlobs(),
  };
}

export class Mixia {
  phase: Phase = 'fresh';
  session: DeviceSession | undefined;
  book!: LedgerBook;
  api: ServerApi | undefined;

  private kv: KV;
  private store: DeviceStore | undefined;
  private settings: Settings | undefined;
  private engine: SyncEngine | undefined;
  private listeners = new Set<() => void>();
  private cloud = new Map<string, Vault>();
  private local = new Map<string, Vault>();
  private localRecords = new Map<string, LocalRecord>();
  private localNames = new Map<string, string>();
  /** 本地库的恢复公钥，解锁时从加密槽里取出。放明文里会被一次写文件替换。 */
  private localPackPub = new Map<string, string>();
  private cold = new Map<string, ColdVault>();
  /** 账本显示本机已被撤销。云库已清除，本地库仍然可用，以便导出。 */
  revoked = false;
  private syncing: Promise<void> | undefined;
  private syncAgain = false;
  private uploading: Promise<void> | undefined;
  private calibratedAt = 0;
  private status: SyncStatus = { state: 'none', lastSyncAt: 0 };
  prefs: Prefs = { ...DEFAULT_PREFS };

  private constructor(private env: PlatformEnv) {
    this.kv = env.openKV('device');
  }

  static async boot(env: PlatformEnv): Promise<Mixia> {
    await initCrypto();
    const m = new Mixia(env);
    m.store = await DeviceStore.load(m.kv, env.hw);
    m.book = await LedgerBook.load(m.kv);
    const s = await m.kv.get('settings');
    if (s) m.settings = fromJson<Settings>(s);
    const p = await m.kv.get('prefs');
    if (p) m.prefs = { ...DEFAULT_PREFS, ...fromJson<Partial<Prefs>>(p) };
    m.revoked = (await m.kv.get('revoked')) !== undefined;
    m.phase = m.store ? 'locked' : 'fresh';
    if (m.settings) m.api = new ServerApi(m.settings.serverUrl, env.http);
    return m;
  }

  onChange(fn: () => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  private emit(): void {
    for (const l of this.listeners) l();
  }

  // ————— 通用 —————

  async setPrefs(next: Partial<Prefs>): Promise<void> {
    this.prefs = { ...this.prefs, ...next };
    await this.kv.batch([{ t: 'put', k: 'prefs', v: jsonBytes(this.prefs) }]);
    this.emit();
  }

  get deviceId(): string | undefined {
    return this.store?.deviceId;
  }

  get level(): Level {
    return this.store?.level ?? this.env.hw.level;
  }

  get serverUrl(): string | undefined {
    return this.settings?.serverUrl;
  }

  get syncStatus(): SyncStatus {
    return this.status;
  }

  get ledger(): LedgerState {
    return this.book.state;
  }

  get isAdmin(): boolean {
    const d = this.deviceId ? this.ledger.devices.get(this.deviceId) : undefined;
    return d?.role === 'admin' && d.revokedSeq === undefined;
  }

  private requireSession(): DeviceSession {
    if (!this.session) throw new MixiaError('locked');
    return this.session;
  }

  private author() {
    const s = this.requireSession();
    return { deviceId: s.deviceId, sign: s.sign };
  }

  private deviceSigner(s: DeviceSession): RequestSigner {
    return { id: s.deviceId, sign: (m) => s.authSign(m) };
  }

  private rootSigner(root: RootKeys): RequestSigner {
    return { id: 'root', sign: async (m) => edSign(root.sign.priv, m) };
  }

  private keyring(): VaultKeyring {
    const s = this.requireSession();
    const k = kdf(s.unlockKey, 'mixia/vk-cache/v1');
    const aad = (id: string, gen: number) => utf8e(`${id}\n${gen}`);
    return {
      get: async (id, gen) => {
        const raw = await this.kv.get(`vk/${id}/${gen}`);
        if (!raw) return undefined;
        return aeadOpen(k, raw.slice(0, 24), raw.slice(24), aad(id, gen));
      },
      put: async (id, gen, key) => {
        const { n, c } = aeadSeal(k, key, aad(id, gen));
        await this.kv.batch([{ t: 'put', k: `vk/${id}/${gen}`, v: concat(n, c) }]);
      },
    };
  }

  private async saveSettings(serverUrl: string) {
    this.settings = { serverUrl };
    await this.kv.batch([{ t: 'put', k: 'settings', v: jsonBytes(this.settings) }]);
    await this.env.pinServer?.(serverUrl);
  }

  private makeEngine(s: DeviceSession): void {
    if (!this.settings) return;
    this.api = new ServerApi(this.settings.serverUrl, this.env.http, this.deviceSigner(s));
    this.engine = new SyncEngine(this.api, this.book, s.box, this.keyring());
  }

  private ledgerSeq = () => this.book.state.seq;

  private async openCloudVault(vaultId: string, key: Uint8Array): Promise<Vault> {
    const kv = this.env.openKV(`v-${vaultId}`);
    const meta = await Vault.metaOf(kv);
    const v = meta
      ? await Vault.open(kv, key, this.author(), this.ledgerSeq)
      : await Vault.create(kv, { vaultId, policy: 'cloud' }, key, this.author(), this.ledgerSeq);
    this.cloud.set(vaultId, v);
    v.onChange(() => this.emit());
    return v;
  }

  // ————— 首次初始化 —————

  /** 创建所有者：生成恢复码（根）、第一台管理设备和第一个云库。服务器只接受一次。 */
  async createOwner(o: {
    serverUrl: string;
    token: string;
    passphrase: string;
    deviceName?: string;
  }): Promise<{ recoveryCode: string }> {
    const r = await this.createOwnerDeferred(o);
    r.activate();
    return { recoveryCode: r.recoveryCode };
  }

  /** 和 createOwner 相同，但等用户确认保管好恢复码之后才调用 activate 进入主界面。 */
  async createOwnerDeferred(o: {
    serverUrl: string;
    token: string;
    passphrase: string;
    deviceName?: string;
  }): Promise<{ recoveryCode: string; activate: () => void }> {
    if (this.phase !== 'fresh') throw new MixiaError('already_set_up');
    const api = new ServerApi(o.serverUrl, this.env.http);
    await api.info();
    const rc = newRecoveryCode();
    const root = rootKeysFrom(rc.bytes);
    const { store, session } = await DeviceStore.create(
      this.kv,
      this.env.hw,
      o.passphrase,
      this.env.info.kdfMem,
    );
    try {
      const st = new LedgerState();
      const entries: LedgerEntry[] = [];
      const add = (type: EntryType, data: Record<string, unknown>) => {
        const e = signEntry(nextBody(st, type, data, 'root'), root.sign);
        st.apply(e);
        entries.push(e);
      };
      add('genesis', {
        ownerId: randomId(),
        rootPub: b64e(root.sign.pub),
        recoveryBoxPub: b64e(root.box.pub),
      });
      const vaultId = randomId();
      const vk = randomBytes(32);
      add('vault_add', { vaultId, gen: 1, keyCommit: keyCommit(vk, vaultId, 1) });
      add('device_add', this.deviceAddData(session, o.deviceName, 'admin', [vaultId]));
      const keys = [
        { vaultId, deviceId: session.deviceId, gen: 1, wrapped: b64e(boxSeal(session.box.pub, vk)) },
        { vaultId, deviceId: 'recovery', gen: 1, wrapped: b64e(boxSeal(root.box.pub, vk)) },
      ];
      await api.bootstrap(o.token, entries, keys);

      await this.book.accept(entries);
      await this.book.pin(st.genesisHash);
      await this.saveSettings(o.serverUrl);
      this.store = store;
      this.session = session;
      await this.keyring().put(vaultId, 1, vk);
      this.makeEngine(session);
      const v = await this.openCloudVault(vaultId, vk);
      await setVaultName(v, '日常');
      await this.loadLocalRecords();
      return {
        recoveryCode: rc.text,
        activate: () => {
          this.phase = 'unlocked';
          this.emit();
          this.syncNow().catch(() => undefined);
        },
      };
    } catch (e) {
      await store.wipe().catch(() => undefined);
      this.session = undefined;
      this.phase = 'fresh';
      throw e;
    }
  }

  private deviceAddData(
    s: DeviceSession,
    name: string | undefined,
    role: Role,
    vaults: string[],
  ): Record<string, unknown> {
    return {
      deviceId: s.deviceId,
      name: name || this.env.info.defaultName,
      platform: this.env.info.platform,
      level: s.level,
      role,
      authPub: b64e(s.authPub),
      signPub: b64e(s.sign.pub),
      boxPub: b64e(s.box.pub),
      vaults,
    };
  }

  // ————— 解锁 —————

  async unlock(passphrase: string): Promise<void> {
    if (!this.store) throw new MixiaError('not_set_up');
    await this.afterUnlock(await this.store.unlock(passphrase));
  }

  /** 敏感操作前重新确认本人。 */
  async verifyPassphrase(passphrase: string): Promise<void> {
    if (!this.store) throw new MixiaError('not_set_up');
    (await this.store.unlock(passphrase)).close();
  }

  async quickUnlock(): Promise<void> {
    if (!this.store) throw new MixiaError('not_set_up');
    await this.afterUnlock(await this.store.quickUnlock());
  }

  async enableQuickUnlock(): Promise<void> {
    await this.store!.enableQuickUnlock(this.requireSession());
  }

  async disableQuickUnlock(): Promise<void> {
    await this.store?.disableQuickUnlock();
  }

  get quickAvailable(): boolean {
    return !!this.env.hw.quick;
  }

  private async afterUnlock(session: DeviceSession): Promise<void> {
    this.session = session;
    this.phase = 'unlocked';
    if (this.revoked) {
      await this.loadLocalRecords();
      this.emit();
      return;
    }
    this.makeEngine(session);
    const kr = this.keyring();
    const me = this.ledger.devices.get(session.deviceId);
    for (const vaultId of me?.vaults ?? []) {
      const info = this.ledger.vaults.get(vaultId);
      if (!info) continue;
      const kv = this.env.openKV(`v-${vaultId}`);
      const meta = await Vault.metaOf(kv);
      const gen = meta?.gen ?? info.gen;
      const key = await kr.get(vaultId, gen);
      if (key) await this.openCloudVault(vaultId, key);
    }
    await this.loadLocalRecords();
    this.emit();
  }

  private async loadLocalRecords(): Promise<void> {
    this.localRecords.clear();
    this.localNames.clear();
    const s = this.requireSession();
    const nk = kdf(s.unlockKey, 'mixia/local-name/v1');
    for (const [, raw] of await this.kv.scan('local/')) {
      const r = fromJson<LocalRecord>(raw);
      this.localRecords.set(r.vaultId, r);
      this.localNames.set(
        r.vaultId,
        utf8d(aeadOpen(nk, b64d(r.nameN), b64d(r.nameC), utf8e(r.vaultId))),
      );
    }
  }

  lock(): void {
    for (const v of this.openVaults()) v.close();
    this.cloud.clear();
    this.local.clear();
    this.cold.clear();
    this.localRecords.clear();
    this.localNames.clear();
    this.localPackPub.clear();
    this.session?.close();
    this.session = undefined;
    this.engine = undefined;
    if (this.phase === 'unlocked') this.phase = 'locked';
    this.emit();
  }

  async changePassphrase(oldPass: string, newPass: string): Promise<void> {
    const s = this.requireSession();
    await this.store!.changePassphrase(s, oldPass, newPass);
    // 解锁密钥变了，依赖它的本地缓存要重新加密：直接重新锁定，让用户用新口令解锁
    await this.rekeyLocalCaches(s, newPass);
    this.lock();
  }

  private async rekeyLocalCaches(old: DeviceSession, newPass: string): Promise<void> {
    const fresh = await this.store!.unlock(newPass);
    const oldVk = kdf(old.unlockKey, 'mixia/vk-cache/v1');
    const newVk = kdf(fresh.unlockKey, 'mixia/vk-cache/v1');
    const oldNk = kdf(old.unlockKey, 'mixia/local-name/v1');
    const newNk = kdf(fresh.unlockKey, 'mixia/local-name/v1');
    const ops: { t: 'put'; k: string; v: Uint8Array }[] = [];
    for (const [k, raw] of await this.kv.scan('vk/')) {
      const [, id, gen] = k.split('/');
      const aad = utf8e(`${id}\n${gen}`);
      const plain = aeadOpen(oldVk, raw.slice(0, 24), raw.slice(24), aad);
      const { n, c } = aeadSeal(newVk, plain, aad);
      ops.push({ t: 'put', k, v: concat(n, c) });
    }
    for (const r of this.localRecords.values()) {
      const name = aeadOpen(oldNk, b64d(r.nameN), b64d(r.nameC), utf8e(r.vaultId));
      const { n, c } = aeadSeal(newNk, name, utf8e(r.vaultId));
      const next: LocalRecord = { ...r, nameN: b64e(n), nameC: b64e(c) };
      ops.push({ t: 'put', k: `local/${r.vaultId}`, v: jsonBytes(next) });
    }
    await this.kv.batch(ops);
    fresh.close();
  }

  // ————— 同步 —————

  /** 同步进行中再次请求时排队补跑一轮，否则这期间的修改要等下一个周期才发出。 */
  async syncNow(): Promise<void> {
    if (this.env.noSync) return;
    if (this.syncing) {
      this.syncAgain = true;
      return this.syncing;
    }
    this.syncing = (async () => {
      do {
        this.syncAgain = false;
        await this.doSync();
      } while (this.syncAgain && this.session);
    })().finally(() => {
      this.syncing = undefined;
    });
    return this.syncing;
  }

  private kickUploads(): Promise<void> {
    this.uploading ??= (async () => {
      for (const v of [...this.cloud.values()]) {
        try {
          await this.engine?.pushAttachments(v);
        } catch {
          /* 下一轮再传。附件留在本机，不会丢。 */
        }
      }
    })().finally(() => {
      this.uploading = undefined;
    });
    return this.uploading;
  }

  /** 等后台附件上传告一段落。 */
  async flushUploads(): Promise<void> {
    await this.kickUploads();
  }

  private async doSync(): Promise<void> {
    const s = this.session;
    if (!s || !this.engine || !this.api || this.revoked) return;
    const alarmRaw = await this.kv.get('alarm');
    if (alarmRaw) {
      this.status = { ...this.status, state: 'alarm', alarm: fromJson(alarmRaw) };
      this.emit();
      return;
    }
    this.status = { ...this.status, state: 'syncing' };
    this.emit();
    let alarmVault: string | undefined;
    try {
      // 校准一次时钟就够用一阵，这条链路每次往返要 600ms 以上
      if (Date.now() - this.calibratedAt > 10 * 60_000) {
        await this.api.info();
        this.calibratedAt = Date.now();
      }
      await this.book.pull(this.api);
      if (!this.ledger.isActive(s.deviceId)) {
        await this.handleRevoked();
        return;
      }
      const me = this.ledger.devices.get(s.deviceId)!;
      for (const vaultId of me.vaults) {
        const info = this.ledger.vaults.get(vaultId);
        if (info && !this.cloud.has(vaultId)) {
          await this.openCloudVault(vaultId, await this.engine.keyFor(info));
        }
      }
      for (const [id, v] of [...this.cloud]) {
        if (!me.vaults.includes(id)) {
          await v.destroyStorage();
          this.cloud.delete(id);
          continue;
        }
        try {
          await this.engine.syncVault(v);
        } catch (e) {
          if (e instanceof IntegrityAlarm) alarmVault = id;
          throw e;
        }
      }
      this.status = { state: 'idle', lastSyncAt: Date.now() };
      void this.kickUploads();
    } catch (e) {
      // 同步途中被锁定：密钥已清零，这时的任何失败都不是服务器的问题
      if (this.session !== s) {
        this.status = { ...this.status, state: 'idle' };
        return;
      }
      // 认证失败也可能是时钟漂移，下一轮重新校准
      this.calibratedAt = 0;
      if (e instanceof IntegrityAlarm) {
        const alarm = { code: e.code, at: Date.now(), ...(alarmVault ? { vaultId: alarmVault } : {}) };
        await this.kv.batch([{ t: 'put', k: 'alarm', v: jsonBytes(alarm) }]);
        this.status = { ...this.status, state: 'alarm', alarm };
      } else if (e instanceof MixiaError && e.code === 'network') {
        this.status = { ...this.status, state: 'offline' };
      } else {
        this.status = {
          ...this.status,
          state: 'error',
          error: e instanceof MixiaError ? e.code : 'unknown',
        };
      }
    }
    this.emit();
  }

  /** 用户确认过告警后清除，下一轮重新校验。 */
  async acknowledgeAlarm(): Promise<void> {
    await this.kv.batch([{ t: 'del', k: 'alarm' }]);
    this.status = { ...this.status, state: 'idle' };
    delete this.status.alarm;
    this.emit();
  }

  /** 只清云库。本地库和云端无关，用户要能把它导出来。 */
  private async handleRevoked(): Promise<void> {
    for (const v of this.cloud.values()) {
      v.close();
      await v.destroyStorage();
    }
    this.cloud.clear();
    const ops = (await this.kv.scan('vk/')).map(([k]) => ({ t: 'del', k }) as const);
    await this.kv.batch([...ops, { t: 'put', k: 'revoked', v: new Uint8Array(1) }]);
    this.revoked = true;
    this.engine = undefined;
    this.status = { state: 'none', lastSyncAt: 0 };
    this.emit();
  }

  private async assertNoAlarm(): Promise<void> {
    if (await this.kv.get('alarm')) throw new MixiaError('alarm_active');
  }

  // ————— 保险库 —————

  vaults(): VaultSummary[] {
    const out: VaultSummary[] = [];
    for (const v of this.cloud.values()) out.push(this.summarize(v, vaultName(v)));
    for (const [id, r] of this.localRecords) {
      const v = this.local.get(id);
      const name = this.localNames.get(id) ?? '本地库';
      out.push(
        v
          ? this.summarize(v, name)
          : {
              id,
              name,
              policy: 'local',
              locked: true,
              readOnly: r.readOnly,
              count: 0,
              pending: 0,
              lastBackupAt: 0,
              gen: 1,
            },
      );
    }
    for (const [id, c] of this.cold) out.push(this.summarize(c.vault, c.name, id));
    return out;
  }

  private summarize(v: Vault, name: string, id = v.id): VaultSummary {
    return {
      id,
      name,
      policy: v.policy,
      locked: false,
      readOnly: v.readOnly,
      count: listItems(v).length,
      pending: 0,
      lastBackupAt: v.meta.lastBackupAt,
      gen: v.gen,
    };
  }

  vault(id: string): Vault {
    const v = this.cloud.get(id) ?? this.local.get(id) ?? this.cold.get(id)?.vault;
    if (!v) throw new MixiaError('vault_locked');
    return v;
  }

  openVaults(): Vault[] {
    return [...this.cloud.values(), ...this.local.values(), ...[...this.cold.values()].map((c) => c.vault)];
  }

  vaultDisplayName(id: string): string {
    return this.vaults().find((v) => v.id === id)?.name ?? '';
  }

  allItems(opts: { trash?: boolean } = {}): ItemView[] {
    return this.openVaults().flatMap((v) => listItems(v, opts));
  }

  async pendingCount(): Promise<number> {
    let n = 0;
    for (const v of this.cloud.values()) n += await v.pendingCount();
    return n;
  }

  async renameVault(id: string, name: string): Promise<void> {
    const v = this.vault(id);
    await setVaultName(v, name);
    const r = this.localRecords.get(id);
    if (r) {
      const s = this.requireSession();
      const box = aeadSeal(kdf(s.unlockKey, 'mixia/local-name/v1'), utf8e(name), utf8e(id));
      const next: LocalRecord = { ...r, nameN: b64e(box.n), nameC: b64e(box.c) };
      await this.kv.batch([{ t: 'put', k: `local/${id}`, v: jsonBytes(next) }]);
      this.localRecords.set(id, next);
      this.localNames.set(id, name);
    }
    this.emit();
  }

  async createCloudVault(name: string): Promise<string> {
    const s = this.requireSession();
    if (!this.isAdmin || !this.api) throw new MixiaError('admin_required');
    await this.book.pull(this.api);
    const st = replay(this.book.entries);
    const vaultId = randomId();
    const vk = randomBytes(32);
    const add = signEntry(
      nextBody(st, 'vault_add', { vaultId, gen: 1, keyCommit: keyCommit(vk, vaultId, 1) }, s.deviceId),
      s.sign,
    );
    st.apply(add);
    // 管理设备总是持有全部云库：撤销设备后任何一台管理设备都能完成换钥
    const entries = [add];
    for (const admin of st.activeAdmins) {
      const e = signEntry(
        nextBody(
          st,
          'grant',
          { deviceId: admin.deviceId, role: admin.role, vaults: [...admin.vaults, vaultId] },
          s.deviceId,
        ),
        s.sign,
      );
      st.apply(e);
      entries.push(e);
    }
    await this.api.postLedger(entries);
    await this.book.accept(entries);
    await this.api.putKeys(vaultId, [
      ...this.ledger.activeAdmins.map((a) => ({
        deviceId: a.deviceId,
        gen: 1,
        wrapped: b64e(boxSeal(b64d(a.boxPub), vk)),
      })),
      { deviceId: 'recovery', gen: 1, wrapped: b64e(boxSeal(b64d(this.ledger.recoveryBoxPub), vk)) },
    ]);
    await this.keyring().put(vaultId, 1, vk);
    const v = await this.openCloudVault(vaultId, vk);
    await setVaultName(v, name);
    this.emit();
    this.syncNow().catch(() => undefined);
    return vaultId;
  }

  // ————— 重要本地库 —————

  private assertLocalAllowed(): void {
    // 报告 6.2：普通文件级保护不授予重要库
    if (this.level === 'software') throw new MixiaError('hardware_required');
  }

  async createLocalVault(
    name: string,
    passphrase: string,
    opts: { allowSoftware?: boolean } = {},
  ): Promise<{ vaultId: string; recoveryCode: string }> {
    if (!opts.allowSoftware) this.assertLocalAllowed();
    const s = this.requireSession();
    const vaultId = randomId();
    const vk = randomBytes(32);
    const rc = newRecoveryCode();
    const packBox = vaultRecoveryBox(rc.bytes);
    await this.writeLocalRecord(s, vaultId, name, passphrase, vk, packBox.pub, false);
    const v = await Vault.create(
      this.env.openKV(`v-${vaultId}`),
      { vaultId, policy: 'local' },
      vk,
      this.author(),
      this.ledgerSeq,
    );
    this.local.set(vaultId, v);
    v.onChange(() => this.emit());
    await setVaultName(v, name);
    this.emit();
    return { vaultId, recoveryCode: rc.text };
  }

  private async writeLocalRecord(
    s: DeviceSession,
    vaultId: string,
    name: string,
    passphrase: string,
    vk: Uint8Array,
    packPub: Uint8Array,
    readOnly: boolean,
  ): Promise<void> {
    const params = newKdfParams(this.env.info.kdfMem);
    // 恢复公钥和库密钥放在同一个加密槽里：改写磁盘文件换不掉备份的接收方
    const slot = aeadSeal(localSlotKey(s.secret, passphrase, params), concat(vk, packPub), utf8e(vaultId));
    const nameBox = aeadSeal(kdf(s.unlockKey, 'mixia/local-name/v1'), utf8e(name), utf8e(vaultId));
    const rec: LocalRecord = {
      vaultId,
      kdf: params,
      n: b64e(slot.n),
      c: b64e(slot.c),
      nameN: b64e(nameBox.n),
      nameC: b64e(nameBox.c),
      readOnly,
    };
    await this.kv.batch([{ t: 'put', k: `local/${vaultId}`, v: jsonBytes(rec) }]);
    this.localRecords.set(vaultId, rec);
    this.localNames.set(vaultId, name);
    if (packPub.length) this.localPackPub.set(vaultId, b64e(packPub));
  }

  async unlockLocalVault(vaultId: string, passphrase: string): Promise<void> {
    const s = this.requireSession();
    const r = this.localRecords.get(vaultId);
    if (!r) throw new MixiaError('vault_missing');
    let slot: Uint8Array;
    try {
      slot = aeadOpen(localSlotKey(s.secret, passphrase, r.kdf), b64d(r.n), b64d(r.c), utf8e(vaultId));
    } catch {
      throw new MixiaError('wrong_passphrase');
    }
    const vk = slot.slice(0, 32);
    if (slot.length > 32) this.localPackPub.set(vaultId, b64e(slot.slice(32)));
    const v = await Vault.open(this.env.openKV(`v-${vaultId}`), vk, this.author(), this.ledgerSeq);
    this.local.set(vaultId, v);
    v.onChange(() => this.emit());
    this.emit();
  }

  lockLocalVault(vaultId: string): void {
    this.local.get(vaultId)?.close();
    this.local.delete(vaultId);
    this.emit();
  }

  async deleteLocalVault(vaultId: string): Promise<void> {
    await this.env.openKV(`v-${vaultId}`).destroy();
    await this.kv.batch([{ t: 'del', k: `local/${vaultId}` }]);
    this.local.delete(vaultId);
    this.localRecords.delete(vaultId);
    this.localNames.delete(vaultId);
    this.emit();
  }

  // ————— 备份与传输 —————

  /** 云库封给账户恢复码，本地库封给该库恢复码。不需要输入恢复码就能备份。 */
  async exportBackup(vaultId: string): Promise<Uint8Array> {
    const v = this.vault(vaultId);
    const to = v.policy === 'cloud' ? this.ledger.recoveryBoxPub : this.localPackPub.get(vaultId);
    if (!to) throw new MixiaError('no_backup_key');
    const bytes = createPack('backup', v.gen, await snapshotOf(v, this.vaultDisplayName(vaultId)), [
      { t: 'seal', to: b64d(to) },
    ]);
    await v.markBackedUp();
    this.emit();
    return bytes;
  }

  /** 把备份恢复成本机的一个新本地库。原备份不被修改。 */
  async restoreBackup(
    bytes: Uint8Array,
    recoveryCode: string,
    passphrase: string,
    opts: { allowSoftware?: boolean } = {},
  ): Promise<{ vaultId: string; count: number; name: string }> {
    if (!opts.allowSoftware) this.assertLocalAllowed();
    const s = this.requireSession();
    const rc = parseRecoveryCode(recoveryCode);
    const packBox = vaultRecoveryBox(rc);
    let snap: Snapshot;
    try {
      snap = openPackWithBox(bytes, packBox);
    } catch {
      snap = openPackWithBox(bytes, rootKeysFrom(rc).box);
    }
    const vaultId = randomId();
    const vk = randomBytes(32);
    await this.writeLocalRecord(s, vaultId, snap.name, passphrase, vk, packBox.pub, false);
    const v = await Vault.create(
      this.env.openKV(`v-${vaultId}`),
      { vaultId, policy: 'local' },
      vk,
      this.author(),
      this.ledgerSeq,
    );
    await v.importVersions(snap.versions, { readOnly: false });
    await v.importAttachmentBlobs(snap.blobs ?? {});
    this.local.set(vaultId, v);
    v.onChange(() => this.emit());
    this.emit();
    return { vaultId, count: listItems(v).length, name: snap.name };
  }

  /**
   * 恢复演练：真实解开备份并核对条目数，不写入任何东西。
   * 只有演练通过才能说“这份备份可恢复”，导出成功不代表能恢复。
   */
  verifyBackup(bytes: Uint8Array, recoveryCode: string): { name: string; count: number; exportedAt: number } {
    const rc = parseRecoveryCode(recoveryCode);
    let snap: Snapshot;
    try {
      snap = openPackWithBox(bytes, vaultRecoveryBox(rc));
    } catch {
      snap = openPackWithBox(bytes, rootKeysFrom(rc).box);
    }
    const g = new VersionGraph();
    for (const v of snap.versions) g.add(v);
    const count = g.objects('item').filter((id) => !g.resolve('item', id).deleted).length;
    return { name: snap.name, count, exportedAt: snap.exportedAt };
  }

  /** 把本地库封给指定设备。文件走 USB 或局域网，不经过服务器。 */
  async exportTransfer(vaultId: string, targetDeviceId: string): Promise<Uint8Array> {
    const v = this.vault(vaultId);
    const target = this.ledger.devices.get(targetDeviceId);
    if (!target || target.revokedSeq !== undefined) throw new MixiaError('unknown_device');
    return createPack('transfer', v.gen, await snapshotOf(v, this.vaultDisplayName(vaultId)), [
      { t: 'seal', to: b64d(target.boxPub) },
    ]);
  }

  async importTransfer(
    bytes: Uint8Array,
    passphrase: string,
    opts: { allowSoftware?: boolean } = {},
  ): Promise<{ vaultId: string; count: number; name: string }> {
    if (!opts.allowSoftware) this.assertLocalAllowed();
    const s = this.requireSession();
    const snap = openPackWithBox(bytes, s.box);
    const vaultId = randomId();
    const vk = randomBytes(32);
    await this.writeLocalRecord(s, vaultId, snap.name, passphrase, vk, new Uint8Array(), true);
    const v = await Vault.create(
      this.env.openKV(`v-${vaultId}`),
      { vaultId, policy: 'local', readOnly: true },
      vk,
      this.author(),
      this.ledgerSeq,
    );
    await v.importVersions(snap.versions, { readOnly: true });
    await v.importAttachmentBlobs(snap.blobs ?? {});
    this.local.set(vaultId, v);
    v.onChange(() => this.emit());
    this.emit();
    return { vaultId, count: listItems(v).length, name: snap.name };
  }

  // ————— 冷库 —————

  async createColdVault(
    name: string,
    passphrase: string,
  ): Promise<{ handle: string; recoveryCode: string; bytes: Uint8Array }> {
    const rc = newRecoveryCode();
    const vaultId = randomId();
    const v = await Vault.create(new MemoryKV(), { vaultId, policy: 'cold' }, randomBytes(32), this.author(), this.ledgerSeq);
    await setVaultName(v, name);
    const c = new ColdVault(v, name, passphrase, rc.bytes, this.env.info.kdfMem);
    this.cold.set(vaultId, c);
    this.emit();
    return { handle: vaultId, recoveryCode: rc.text, bytes: await c.save() };
  }

  async openColdVault(bytes: Uint8Array, passphrase: string, recoveryCode: string): Promise<string> {
    const code = parseRecoveryCode(recoveryCode);
    const snap = openPackWithCold(bytes, passphrase, code);
    const v = await Vault.create(
      new MemoryKV(),
      { vaultId: snap.vaultId, policy: 'cold' },
      randomBytes(32),
      this.author(),
      this.ledgerSeq,
    );
    await v.importVersions(snap.versions, { readOnly: false });
    await v.importAttachmentBlobs(snap.blobs ?? {});
    this.cold.set(snap.vaultId, new ColdVault(v, snap.name, passphrase, code, this.env.info.kdfMem));
    v.onChange(() => this.emit());
    this.emit();
    return snap.vaultId;
  }

  saveColdVault(handle: string): Promise<Uint8Array> {
    const c = this.cold.get(handle);
    if (!c) throw new MixiaError('vault_locked');
    return c.save();
  }

  closeColdVault(handle: string): void {
    this.cold.get(handle)?.vault.close();
    this.cold.delete(handle);
    this.emit();
  }

  packInfo(bytes: Uint8Array): PackHeader {
    return readPackHeader(bytes);
  }

  // ————— 条目迁移 —————

  /**
   * 跨库移动是显式迁移：先写目标库并读回确认，再处理源记录。
   * 本地 → 云必须显式确认；云 → 本地保留“曾进入云端”标记，因为历史无法撤销。
   */
  async moveItem(
    fromVault: string,
    itemId: string,
    toVault: string,
    opts: { confirmUpload?: boolean } = {},
  ): Promise<string> {
    const src = this.vault(fromVault);
    const dst = this.vault(toVault);
    const it = getItem(src, itemId);
    if (!it) throw new MixiaError('item_not_found');
    if (src.policy !== 'cloud' && dst.policy === 'cloud' && !opts.confirmUpload) {
      throw new MixiaError('upload_needs_confirmation');
    }
    const data: ItemData = { ...it.data, folder: null };
    if (src.policy === 'cloud') data.cloudExposed = true;
    const newId = await saveItem(dst, undefined, data);
    if (!getItem(dst, newId)) throw new MixiaError('move_verify_failed');
    await src.commit('item', itemId, null, { del: true });
    return newId;
  }

  async importRows(vaultId: string, rows: ImportRow[]): Promise<number> {
    const v = this.vault(vaultId);
    const known = new Map(flattenFolders(folderTree(v)).map((n) => [n.path.join('/'), n.id]));
    const ensure = async (path: string): Promise<string | null> => {
      if (!path) return null;
      const hit = known.get(path);
      if (hit) return hit;
      const parts = path.split('/');
      const name = parts.pop()!;
      const parent = await ensure(parts.join('/'));
      const id = await saveFolder(v, undefined, name, parent);
      known.set(path, id);
      return id;
    };
    const now = Date.now();
    const versions: Version[] = [];
    for (const r of rows) {
      const folder = await ensure(r.folderPath);
      versions.push({
        id: randomId(),
        parents: [],
        ts: now,
        device: '',
        kind: 'item',
        obj: randomId(),
        del: false,
        data: { ...r.data, folder, createdAt: now, updatedAt: now, passwordChangedAt: now },
      });
    }
    await v.commitAuthored(versions);
    this.emit();
    this.syncNow().catch(() => undefined);
    return versions.length;
  }

  // ————— 配对 —————

  /** 管理设备发起配对，返回给新设备输入的配对码。 */
  async startPairing(): Promise<{ code: string; pairId: string; secret: string; expiresAt: number }> {
    if (!this.isAdmin || !this.api) throw new MixiaError('admin_required');
    await this.assertNoAlarm();
    await this.book.pull(this.api);
    const pc = newPairCode();
    const { key, token } = pairKeys(pc.secret);
    const me = this.ledger.devices.get(this.requireSession().deviceId)!;
    const expiresAt = Date.now() + 10 * 60_000;
    await this.api.pairOpen({
      pairId: pc.pairId,
      tokenHash: b64e(sha256(b64d(token))),
      expiresAt,
      offer: pairSeal(key, {
        genesisHash: this.ledger.genesisHash,
        serverUrl: this.serverUrl,
        adminName: me.name,
      }),
    });
    return { code: pc.text, pairId: pc.pairId, secret: pc.secret, expiresAt };
  }

  async pollPairing(pairId: string, secret: string): Promise<PendingDevice | undefined> {
    if (!this.api) throw new MixiaError('no_server');
    const r = await this.api.pairAdmin(pairId);
    if (!r.request) return undefined;
    const req = pairOpen<PairRequest>(pairKeys(secret).key, r.request);
    const authPub = b64d(req.authPub);
    return {
      name: req.name,
      platform: req.platform,
      level: req.level,
      fingerprint: deviceFingerprint(req),
      deviceId: b64e(sha256(authPub).slice(0, 16)),
      raw: req,
    };
  }

  /** 批准：写账本并只把选中的库封装给新设备。 */
  async approvePairing(
    pairId: string,
    secret: string,
    dev: PendingDevice,
    opts: { role: Role; vaults: string[]; name?: string },
  ): Promise<void> {
    const s = this.requireSession();
    if (!this.api) throw new MixiaError('no_server');
    await this.assertNoAlarm();
    await this.book.pull(this.api);
    const st = replay(this.book.entries);
    // 管理设备总是持有全部云库
    const vaults = opts.role === 'admin' ? [...st.vaults.keys()] : opts.vaults;
    const e = signEntry(
      nextBody(
        st,
        'device_add',
        {
          deviceId: dev.deviceId,
          name: opts.name || dev.raw.name,
          platform: dev.raw.platform,
          level: dev.raw.level,
          role: opts.role,
          authPub: dev.raw.authPub,
          signPub: dev.raw.signPub,
          boxPub: dev.raw.boxPub,
          vaults,
        },
        s.deviceId,
      ),
      s.sign,
    );
    await this.api.postLedger([e]);
    await this.book.accept([e]);
    const boxPub = b64d(dev.raw.boxPub);
    for (const vaultId of vaults) {
      const v = this.cloud.get(vaultId);
      if (!v) throw new MixiaError('vault_locked');
      const keys: WrappedKey[] = [
        { deviceId: dev.deviceId, gen: v.gen, wrapped: b64e(boxSeal(boxPub, v.vaultKey)) },
      ];
      await this.api.putKeys(vaultId, keys);
    }
    // 把批准时的账本位置告诉新设备：服务器不能给它看一条缺了撤销记录的旧分支
    await this.api.pairGrant(
      pairId,
      pairSeal(pairKeys(secret).key, {
        deviceId: dev.deviceId,
        headSeq: this.ledger.seq,
        headHash: this.ledger.headHash,
      }),
    );
    this.emit();
  }

  async cancelPairing(pairId: string): Promise<void> {
    await this.api?.pairClose(pairId).catch(() => undefined);
  }

  /** 新设备第一步：用配对码取得并钉住信任根。服务器不知道配对码，无法伪造。 */
  async beginJoin(serverUrl: string, codeText: string): Promise<JoinState> {
    const code = parsePairCode(codeText);
    const api = new ServerApi(serverUrl, this.env.http);
    await api.info();
    const { key, token } = pairKeys(code.secret);
    const r = await api.pairGet(code.pairId, token);
    const offer = pairOpen<{ genesisHash: string; serverUrl: string; adminName: string }>(key, r.offer);
    return { serverUrl, code, genesisHash: offer.genesisHash, adminName: offer.adminName, api };
  }

  /** 第二步：生成本机身份，提交申请。返回给用户核对的指纹。 */
  async submitJoin(j: JoinState, passphrase: string, deviceName?: string): Promise<{ fingerprint: string }> {
    if (this.phase !== 'fresh') throw new MixiaError('already_set_up');
    const { store, session } = await DeviceStore.create(
      this.kv,
      this.env.hw,
      passphrase,
      this.env.info.kdfMem,
    );
    this.store = store;
    this.session = session;
    const { key, token } = pairKeys(j.code.secret);
    const req: PairRequest = {
      name: deviceName || this.env.info.defaultName,
      platform: this.env.info.platform,
      level: session.level,
      authPub: b64e(session.authPub),
      signPub: b64e(session.sign.pub),
      boxPub: b64e(session.box.pub),
    };
    await j.api.pairRequest(j.code.pairId, token, pairSeal(key, req));
    return { fingerprint: deviceFingerprint(req) };
  }

  /** 第三步：轮询批准结果。批准后校验账本到钉住的创世哈希，确认自己确实被授权。 */
  async finishJoin(j: JoinState): Promise<boolean> {
    const s = this.requireSession();
    const { key, token } = pairKeys(j.code.secret);
    const r = await j.api.pairGet(j.code.pairId, token);
    if (!r.grant) return false;
    const grant = pairOpen<{ deviceId: string; headSeq: number; headHash: string }>(key, r.grant);
    if (grant.deviceId !== s.deviceId) throw new IntegrityAlarm('pair_tampered');
    const api = new ServerApi(j.serverUrl, this.env.http, this.deviceSigner(s));
    await api.info();
    const { entries } = await api.getLedger(0);
    const st = replay(entries);
    if (st.genesisHash !== j.genesisHash) throw new IntegrityAlarm('genesis_mismatch');
    if (!st.isActive(s.deviceId)) throw new IntegrityAlarm('device_not_in_ledger');
    const seen = entries[grant.headSeq];
    if (!seen || entryHash(seen) !== grant.headHash) throw new IntegrityAlarm('ledger_withheld');
    // 账本里记的公钥必须是自己的：防止批准时被换成别人的
    const mine = st.devices.get(s.deviceId)!;
    if (mine.signPub !== b64e(s.sign.pub) || mine.boxPub !== b64e(s.box.pub)) {
      throw new IntegrityAlarm('device_keys_swapped');
    }
    await this.book.pin(j.genesisHash);
    await this.book.accept(entries);
    await this.saveSettings(j.serverUrl);
    this.phase = 'unlocked';
    this.makeEngine(s);
    await this.loadLocalRecords();
    await this.syncNow();
    this.emit();
    return true;
  }

  // ————— 设备管理 —————

  devices(): DeviceInfo[] {
    return [...this.ledger.devices.values()];
  }

  /** 撤销设备，然后对它能访问的每个云库换钥。 */
  async revokeDevice(deviceId: string, reason = ''): Promise<void> {
    const s = this.requireSession();
    if (!this.isAdmin || !this.api) throw new MixiaError('admin_required');
    await this.book.pull(this.api);
    const st = replay(this.book.entries);
    const e = signEntry(nextBody(st, 'device_revoke', { deviceId, reason }, s.deviceId), s.sign);
    await this.api.postLedger([e]);
    await this.book.accept([e]);
    await this.finishRotations();
  }

  /** 完成所有待换钥的库。撤销成功但换钥失败时可以重试。有库没换成必须报错，不能说成功。 */
  async finishRotations(): Promise<void> {
    for (const vaultId of this.ledger.vaultsNeedingRotation()) {
      if (this.cloud.has(vaultId)) await this.rotateVault(vaultId);
    }
    if (this.ledger.vaultsNeedingRotation().length > 0) throw new MixiaError('rotation_incomplete');
  }

  /**
   * 换钥：新一代密钥，全量重加密，同时压缩日志。
   * 快照要带上它看到的日志位置，服务端不一致就拒绝，这样并发上传的修改不会被吞掉。
   * force 用于服务器日志里有坏数据、无法完成同步时，以本机内容重建这个库。
   */
  async rotateVault(vaultId: string, opts: { force?: boolean } = {}): Promise<void> {
    for (let attempt = 0; ; attempt++) {
      try {
        await this.rotateOnce(vaultId, opts);
        return;
      } catch (e) {
        if (!(e instanceof ApiError && e.code === 'stale_snapshot') || attempt >= 4) throw e;
      }
    }
  }

  private async rotateOnce(vaultId: string, opts: { force?: boolean }): Promise<void> {
    const s = this.requireSession();
    if (!this.isAdmin || !this.api || !this.engine) throw new MixiaError('admin_required');
    const v = this.cloud.get(vaultId);
    if (!v) throw new MixiaError('vault_locked');
    await this.book.pull(this.api);
    let logHead: number;
    if (opts.force) {
      logHead = (await this.api.getChanges(vaultId, Number.MAX_SAFE_INTEGER, 1)).head;
    } else {
      await this.engine.syncVault(v);
      await this.engine.pullVault(v);
      logHead = v.meta.lastSeq;
    }
    const st = replay(this.book.entries);
    const info = st.vaults.get(vaultId);
    if (!info) throw new MixiaError('vault_gone');
    const newGen = info.gen + 1;
    const newKey = randomBytes(32);
    const { changes, snapshotHash } = v.prepareRotation(newKey, newGen);
    const entry = signEntry(
      nextBody(
        st,
        'vault_rotate',
        {
          vaultId,
          gen: newGen,
          keyCommit: keyCommit(newKey, vaultId, newGen),
          snapshotCount: changes.length,
          snapshotHash,
          logHead,
        },
        s.deviceId,
      ),
      s.sign,
    );
    const keys: WrappedKey[] = st.devicesWithVault(vaultId).map((d) => ({
      deviceId: d.deviceId,
      gen: newGen,
      wrapped: b64e(boxSeal(b64d(d.boxPub), newKey)),
    }));
    keys.push({
      deviceId: 'recovery',
      gen: newGen,
      wrapped: b64e(boxSeal(b64d(st.recoveryBoxPub), newKey)),
    });
    await this.api.rotate(vaultId, entry, keys, changes);
    await this.book.pull(this.api);
    await this.engine.pullVault(v);
    await this.engine.pushVault(v);
    this.emit();
  }

  /** 服务器日志坏了时的出路：确认告警后用本机内容重建。 */
  async rebuildVault(vaultId: string): Promise<void> {
    await this.kv.batch([{ t: 'del', k: 'alarm' }]);
    this.status = { state: 'idle', lastSyncAt: this.status.lastSyncAt };
    await this.rotateVault(vaultId, { force: true });
    this.emit();
  }

  async auditLog() {
    if (!this.api) throw new MixiaError('no_server');
    return (await this.api.audit()).events;
  }

  // ————— 账户恢复 —————

  /** 所有设备丢失：用恢复码在新设备上重建管理权限。 */
  async recoverAccount(o: {
    serverUrl: string;
    recoveryCode: string;
    passphrase: string;
    deviceName?: string;
  }): Promise<void> {
    if (this.phase !== 'fresh') throw new MixiaError('already_set_up');
    const rc = parseRecoveryCode(o.recoveryCode);
    const root = rootKeysFrom(rc);
    const api = new ServerApi(o.serverUrl, this.env.http, this.rootSigner(root));
    await api.info();
    let entries: LedgerEntry[];
    try {
      entries = (await api.getLedger(0)).entries;
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) throw new MixiaError('recovery_rejected');
      throw e;
    }
    const st = replay(entries);
    if (st.rootPub !== b64e(root.sign.pub)) throw new IntegrityAlarm('root_mismatch');

    const { store, session } = await DeviceStore.create(
      this.kv,
      this.env.hw,
      o.passphrase,
      this.env.info.kdfMem,
    );
    try {
      const vaultIds = [...st.vaults.keys()];
      const e = signEntry(
        nextBody(st, 'device_add', this.deviceAddData(session, o.deviceName, 'admin', vaultIds), 'root'),
        root.sign,
      );
      await api.postLedger([e]);
      st.apply(e);
      const vks = new Map<string, Uint8Array>();
      for (const id of vaultIds) {
        const info = st.vaults.get(id)!;
        const { keys } = await api.getKeys(id);
        const w = keys.find((k) => k.gen === info.gen);
        if (!w) throw new MixiaError('recovery_key_missing');
        const vk = boxOpen(root.box, b64d(w.wrapped));
        if (keyCommit(vk, id, info.gen) !== info.keyCommit) throw new IntegrityAlarm('key_commit_mismatch');
        vks.set(id, vk);
        await api.putKeys(id, [
          { deviceId: session.deviceId, gen: info.gen, wrapped: b64e(boxSeal(session.box.pub, vk)) },
        ]);
      }
      await this.book.pin(st.genesisHash);
      await this.book.accept([...entries, e]);
      await this.saveSettings(o.serverUrl);
      this.store = store;
      this.session = session;
      this.phase = 'unlocked';
      this.makeEngine(session);
      for (const [id, vk] of vks) {
        await this.keyring().put(id, st.vaults.get(id)!.gen, vk);
      }
      await this.loadLocalRecords();
      await this.syncNow();
      this.emit();
    } catch (err) {
      await store.wipe().catch(() => undefined);
      this.session = undefined;
      throw err;
    }
  }

  /**
   * 换恢复码分两步：先把新码给用户抄好，确认之后才提交。
   * 提交在服务端是一个事务，失败时旧码依然有效，不可能出现“新码没人知道、旧码已作废”。
   */
  beginRecoveryRotation(oldCode: string): { recoveryCode: string; commit: () => Promise<void> } {
    this.requireSession();
    const settings = this.settings;
    if (!settings) throw new MixiaError('no_server');
    const oldRoot = rootKeysFrom(parseRecoveryCode(oldCode));
    if (b64e(oldRoot.sign.pub) !== this.ledger.rootPub) throw new MixiaError('bad_recovery_code');
    const rc = newRecoveryCode();
    const root = rootKeysFrom(rc.bytes);
    const commit = async () => {
      const api = new ServerApi(settings.serverUrl, this.env.http, this.rootSigner(oldRoot));
      await api.info();
      await this.book.pull(this.api!);
      const st = replay(this.book.entries);
      const wraps: { vaultId: string; gen: number; wrapped: string }[] = [];
      for (const [id, info] of st.vaults) {
        const { keys } = await api.getKeys(id);
        const w = keys.find((k) => k.gen === info.gen);
        if (!w) throw new MixiaError('recovery_key_missing');
        const vk = boxOpen(oldRoot.box, b64d(w.wrapped));
        if (keyCommit(vk, id, info.gen) !== info.keyCommit) throw new IntegrityAlarm('key_commit_mismatch');
        wraps.push({ vaultId: id, gen: info.gen, wrapped: b64e(boxSeal(root.box.pub, vk)) });
      }
      const e = signEntry(
        nextBody(
          st,
          'root_rotate',
          { rootPub: b64e(root.sign.pub), recoveryBoxPub: b64e(root.box.pub) },
          'root',
        ),
        oldRoot.sign,
      );
      await api.rootRotate(e, wraps);
      await this.book.accept([e]);
      // 旧码能解开当前代的库密钥，所以换根之后全部换钥，旧码才真正失效
      for (const id of this.cloud.keys()) await this.rotateVault(id);
      this.emit();
    };
    return { recoveryCode: rc.text, commit };
  }

  async rotateRecoveryCode(oldCode: string): Promise<{ recoveryCode: string }> {
    const r = this.beginRecoveryRotation(oldCode);
    await r.commit();
    return { recoveryCode: r.recoveryCode };
  }

  // ————— 重置 —————

  /** 擦除本机全部数据和硬件密钥。不可恢复，界面必须二次确认。 */
  async wipeDevice(): Promise<void> {
    const ids = new Set<string>([...this.cloud.keys(), ...this.localRecords.keys()]);
    this.lock();
    for (const [k] of await this.kv.scan('local/')) ids.add(k.slice(6));
    for (const id of this.ledger.vaults.keys()) ids.add(id);
    for (const id of ids) await this.env.openKV(`v-${id}`).destroy().catch(() => undefined);
    await this.store?.wipe().catch(() => undefined);
    await this.kv.destroy();
    await this.env.unpinServer?.();
    this.revoked = false;
    this.store = undefined;
    this.settings = undefined;
    this.book = await LedgerBook.load(this.kv);
    this.prefs = { ...DEFAULT_PREFS };
    this.phase = 'fresh';
    this.emit();
  }
}

export { entryHash, newItem };

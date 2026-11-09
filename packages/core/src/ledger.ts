/**
 * 信任账本：哈希链 + 签名。规则与 server/ 中的 Go 实现必须一致（协议规范第 2 节）。
 * 客户端从不相信服务器对账本的解释，始终从创世条目起自行校验。
 */
import { b64d, b64e, concat, edSign, edVerify, sha256, utf8d, utf8e, type SignKeys } from './crypto';
import { MixiaError } from './errors';

export type Role = 'admin' | 'member';
export type Level = 'hardware' | 'os' | 'software';

export interface LedgerEntry {
  body: string;
  sig: string;
}

export type EntryType =
  | 'genesis'
  | 'device_add'
  | 'device_revoke'
  | 'grant'
  | 'vault_add'
  | 'vault_rotate'
  | 'vault_delete'
  | 'root_rotate';

export interface EntryBody {
  v: 1;
  seq: number;
  prev: string;
  ts: number;
  signer: string;
  type: EntryType;
  data: Record<string, unknown>;
}

export interface DeviceInfo {
  deviceId: string;
  name: string;
  platform: string;
  level: Level;
  role: Role;
  authPub: string;
  signPub: string;
  boxPub: string;
  vaults: string[];
  addedSeq: number;
  addedAt: number;
  revokedSeq?: number;
  revokedAt?: number;
  revokeReason?: string;
}

export interface VaultInfo {
  vaultId: string;
  gen: number;
  keyCommit: string;
  snapshotCount: number;
  snapshotHash: string;
  /** 最后一次换钥所在的账本序号，用于判断撤销后是否还需要换钥。 */
  genSeq: number;
}

const LEDGER_PREFIX = 'mixia/ledger/v1\n';
const fail = (why: string): never => {
  throw new MixiaError('ledger_invalid', why);
};

export function deviceIdFromAuthPub(authPub: Uint8Array): string {
  return b64e(sha256(authPub).slice(0, 16));
}

export function entryHash(e: LedgerEntry): string {
  return b64e(sha256(b64d(e.body)));
}

export function parseEntry(e: LedgerEntry): EntryBody {
  const body = JSON.parse(utf8d(b64d(e.body))) as EntryBody;
  if (body === null || typeof body !== 'object') fail('entry_shape');
  return body;
}

export function signEntry(body: EntryBody, signer: SignKeys): LedgerEntry {
  const bytes = utf8e(JSON.stringify(body));
  return {
    body: b64e(bytes),
    sig: b64e(edSign(signer.priv, concat(utf8e(LEDGER_PREFIX), bytes))),
  };
}

const isStr = (v: unknown): v is string => typeof v === 'string' && v.length > 0;
const isRole = (v: unknown): v is Role => v === 'admin' || v === 'member';
const isLevel = (v: unknown): v is Level => v === 'hardware' || v === 'os' || v === 'software';

/** 账本状态机。apply 校验失败时抛错。 */
export class LedgerState {
  ownerId = '';
  rootPub = '';
  recoveryBoxPub = '';
  genesisHash = '';
  seq = -1;
  headHash = '';
  devices = new Map<string, DeviceInfo>();
  vaults = new Map<string, VaultInfo>();
  /** 库 → 最后一次有设备被移出的账本序号。 */
  private narrowed = new Map<string, number>();

  get activeDevices(): DeviceInfo[] {
    return [...this.devices.values()].filter((d) => d.revokedSeq === undefined);
  }

  get activeAdmins(): DeviceInfo[] {
    return this.activeDevices.filter((d) => d.role === 'admin');
  }

  isActive(id: string): boolean {
    const d = this.devices.get(id);
    return !!d && d.revokedSeq === undefined;
  }

  devicesWithVault(vaultId: string): DeviceInfo[] {
    return this.activeDevices.filter((d) => d.vaults.includes(vaultId));
  }

  /** 有设备被撤销或移出之后还未换钥的库：旧设备仍持有这些库的当前密钥。 */
  vaultsNeedingRotation(): string[] {
    const out: string[] = [];
    for (const v of this.vaults.values()) {
      const lost = this.narrowed.get(v.vaultId);
      if (lost !== undefined && lost > v.genSeq) out.push(v.vaultId);
    }
    return out;
  }

  private verifySignature(e: LedgerEntry, body: EntryBody, rootPub: string): void {
    const msg = concat(utf8e(LEDGER_PREFIX), b64d(e.body));
    const sig = b64d(e.sig);
    if (body.signer === 'root') {
      if (!isStr(rootPub) || !edVerify(b64d(rootPub), msg, sig)) fail('bad_root_signature');
      return;
    }
    const dev = this.devices.get(body.signer);
    if (!dev) return fail('unknown_signer');
    if (dev.revokedSeq !== undefined) fail('signer_revoked');
    if (dev.role !== 'admin') fail('signer_not_admin');
    if (!edVerify(b64d(dev.signPub), msg, sig)) fail('bad_signature');
  }

  apply(e: LedgerEntry): void {
    let body: EntryBody;
    try {
      body = parseEntry(e);
    } catch (err) {
      if (err instanceof MixiaError) throw err;
      return fail('entry_unparseable');
    }
    if (body.v !== 1) fail('bad_version');
    if (body.seq !== this.seq + 1) fail('bad_seq');
    if (body.prev !== (this.seq < 0 ? '' : this.headHash)) fail('bad_prev');
    if (
      typeof body.ts !== 'number' ||
      !isStr(body.signer) ||
      typeof body.data !== 'object' ||
      body.data === null
    ) {
      fail('entry_shape');
    }
    const d = body.data;

    if (body.seq === 0) {
      if (body.type !== 'genesis' || body.signer !== 'root') fail('first_must_be_genesis');
      if (!isStr(d.ownerId) || !isStr(d.rootPub) || !isStr(d.recoveryBoxPub)) fail('genesis_shape');
      this.verifySignature(e, body, d.rootPub as string);
      this.ownerId = d.ownerId as string;
      this.rootPub = d.rootPub as string;
      this.recoveryBoxPub = d.recoveryBoxPub as string;
      this.genesisHash = entryHash(e);
      this.seq = 0;
      this.headHash = this.genesisHash;
      return;
    }

    if (body.type === 'genesis') fail('genesis_not_first');
    if (body.type === 'root_rotate' && body.signer !== 'root') fail('root_only');
    this.verifySignature(e, body, this.rootPub);

    switch (body.type) {
      case 'device_add':
        this.applyDeviceAdd(body);
        break;
      case 'device_revoke': {
        const dev = this.requireActive(d.deviceId);
        this.guardLastAdmin(dev, body.signer);
        dev.revokedSeq = body.seq;
        dev.revokedAt = body.ts;
        dev.revokeReason = typeof d.reason === 'string' ? d.reason : '';
        for (const v of dev.vaults) this.narrowed.set(v, body.seq);
        break;
      }
      case 'grant': {
        const dev = this.requireActive(d.deviceId);
        if (!isRole(d.role)) fail('bad_role');
        const vaults = this.requireVaultList(d.vaults);
        if (dev.role === 'admin' && d.role !== 'admin') this.guardLastAdmin(dev, body.signer);
        for (const v of dev.vaults) {
          if (!vaults.includes(v)) this.narrowed.set(v, body.seq);
        }
        dev.role = d.role as Role;
        dev.vaults = vaults;
        break;
      }
      case 'vault_add': {
        if (!isStr(d.vaultId) || this.vaults.has(d.vaultId)) fail('vault_exists');
        if (d.gen !== 1 || !isStr(d.keyCommit)) fail('vault_shape');
        this.vaults.set(d.vaultId as string, {
          vaultId: d.vaultId as string,
          gen: 1,
          keyCommit: d.keyCommit as string,
          snapshotCount: 0,
          snapshotHash: '',
          genSeq: body.seq,
        });
        break;
      }
      case 'vault_rotate': {
        const v = this.vaults.get(d.vaultId as string);
        if (!v) return fail('unknown_vault');
        if (d.gen !== v.gen + 1 || !isStr(d.keyCommit)) fail('bad_gen');
        if (typeof d.snapshotCount !== 'number' || typeof d.snapshotHash !== 'string') {
          fail('vault_shape');
        }
        v.gen = d.gen as number;
        v.keyCommit = d.keyCommit as string;
        v.snapshotCount = d.snapshotCount as number;
        v.snapshotHash = d.snapshotHash as string;
        v.genSeq = body.seq;
        break;
      }
      case 'vault_delete': {
        if (!this.vaults.delete(d.vaultId as string)) fail('unknown_vault');
        for (const dev of this.devices.values()) {
          dev.vaults = dev.vaults.filter((x) => x !== d.vaultId);
        }
        break;
      }
      case 'root_rotate': {
        if (!isStr(d.rootPub) || !isStr(d.recoveryBoxPub)) fail('root_shape');
        this.rootPub = d.rootPub as string;
        this.recoveryBoxPub = d.recoveryBoxPub as string;
        break;
      }
      default:
        fail('unknown_type');
    }
    this.seq = body.seq;
    this.headHash = entryHash(e);
  }

  private requireActive(id: unknown): DeviceInfo {
    const dev = this.devices.get(id as string);
    if (!dev) return fail('unknown_device');
    if (dev.revokedSeq !== undefined) fail('device_revoked');
    return dev;
  }

  private requireVaultList(v: unknown): string[] {
    if (!Array.isArray(v)) return fail('bad_vaults');
    for (const x of v) {
      if (!this.vaults.has(x as string)) fail('unknown_vault');
    }
    return [...new Set(v as string[])];
  }

  private guardLastAdmin(dev: DeviceInfo, signer: string): void {
    if (signer === 'root') return;
    if (dev.role === 'admin' && this.activeAdmins.length <= 1) fail('last_admin');
  }

  private applyDeviceAdd(body: EntryBody): void {
    const d = body.data;
    if (!isStr(d.deviceId) || this.devices.has(d.deviceId)) fail('device_exists');
    if (!isStr(d.authPub) || !isStr(d.signPub) || !isStr(d.boxPub)) fail('device_shape');
    if (deviceIdFromAuthPub(b64d(d.authPub as string)) !== d.deviceId) fail('device_id_mismatch');
    if (!isRole(d.role) || !isLevel(d.level)) fail('device_shape');
    this.devices.set(d.deviceId as string, {
      deviceId: d.deviceId as string,
      name: typeof d.name === 'string' ? d.name : '',
      platform: typeof d.platform === 'string' ? d.platform : '',
      level: d.level as Level,
      role: d.role as Role,
      authPub: d.authPub as string,
      signPub: d.signPub as string,
      boxPub: d.boxPub as string,
      vaults: this.requireVaultList(d.vaults),
      addedSeq: body.seq,
      addedAt: body.ts,
    });
  }
}

/** 从头重放一组条目；用于开机加载和首次拉取。 */
export function replay(entries: LedgerEntry[]): LedgerState {
  const st = new LedgerState();
  for (const e of entries) st.apply(e);
  return st;
}

export function nextBody(
  st: LedgerState,
  type: EntryType,
  data: Record<string, unknown>,
  signer: string,
  ts = Date.now(),
): EntryBody {
  return { v: 1, seq: st.seq + 1, prev: st.seq < 0 ? '' : st.headHash, ts, signer, type, data };
}

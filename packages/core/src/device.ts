/**
 * 设备身份与本地密钥库。
 *
 * 解锁密钥 = KDF(硬件封存的设备秘密, Argon2id(口令))。
 * 口令和设备硬件缺一不可：复制数据目录到别的机器，知道口令也打不开。
 */
import { p256 } from '@noble/curves/nist';
import {
  aeadOpen,
  aeadSeal,
  argon2id,
  b64d,
  b64e,
  boxKeysFromSeed,
  concat,
  kdf,
  newKdfParams,
  randomBytes,
  randomId,
  signKeysFromSeed,
  utf8d,
  utf8e,
  wipe,
  type BoxKeys,
  type KdfParams,
  type SignKeys,
} from './crypto';
import { MixiaError } from './errors';
import { deviceIdFromAuthPub, type Level } from './ledger';
import { fromJson, jsonBytes, type KV } from './store';

/** 平台硬件能力。Windows 由 TPM 助手实现，Android 由 Keystore 插件实现。 */
export interface HardwareKeys {
  readonly level: Level;
  /** 创建不可导出的 P-256 认证密钥和封存密钥，返回 65 字节未压缩公钥。 */
  create(name: string): Promise<Uint8Array>;
  /** 对 msg 做 SHA-256 后用 ECDSA P-256 签名，返回 r||s。 */
  sign(name: string, msg: Uint8Array): Promise<Uint8Array>;
  seal(name: string, data: Uint8Array): Promise<Uint8Array>;
  unseal(name: string, blob: Uint8Array): Promise<Uint8Array>;
  destroy(name: string): Promise<void>;
  /** 可选的生物识别快捷解锁，只有经过系统生物识别才能取回。 */
  quick?: QuickUnlock;
}

export interface QuickUnlock {
  available(): Promise<boolean>;
  enroll(name: string, secret: Uint8Array): Promise<void>;
  retrieve(name: string): Promise<Uint8Array>;
  clear(name: string): Promise<void>;
}

/**
 * 纯软件实现：密钥以明文存在 KV 中，没有任何硬件保护。
 * 只用于测试，等级固定 software，界面和策略据此拒绝重要库。
 */
export class SoftwareKeys implements HardwareKeys {
  readonly level: Level = 'software';

  constructor(private kv: KV) {}

  async create(name: string) {
    const priv = p256.utils.randomPrivateKey();
    const sealKey = randomBytes(32);
    await this.kv.batch([
      { t: 'put', k: `sw/${name}/auth`, v: priv },
      { t: 'put', k: `sw/${name}/seal`, v: sealKey },
    ]);
    return p256.getPublicKey(priv, false);
  }

  private async read(name: string, what: string) {
    const v = await this.kv.get(`sw/${name}/${what}`);
    if (!v) throw new MixiaError('no_key');
    return v;
  }

  async sign(name: string, msg: Uint8Array) {
    const sig = p256.sign(msg, await this.read(name, 'auth'), { prehash: true, lowS: false });
    return sig.toCompactRawBytes();
  }

  async seal(name: string, data: Uint8Array) {
    const k = await this.read(name, 'seal');
    const { n, c } = aeadSeal(k, data, utf8e('sw-seal'));
    return concat(n, c);
  }

  async unseal(name: string, blob: Uint8Array) {
    const k = await this.read(name, 'seal');
    return aeadOpen(k, blob.slice(0, 24), blob.slice(24), utf8e('sw-seal'));
  }

  async destroy(name: string) {
    await this.kv.batch([
      { t: 'del', k: `sw/${name}/auth` },
      { t: 'del', k: `sw/${name}/seal` },
    ]);
  }
}

interface DeviceRecord {
  v: 1;
  installId: string;
  deviceId: string;
  level: Level;
  authPub: string;
  kdf: KdfParams;
  sealedSecret: string;
  n: string;
  c: string;
}

const RECORD_KEY = 'device/record';
const aadFor = (deviceId: string) => utf8e(`mixia/keystore/v1\n${deviceId}`);

export function unlockKeyFrom(secret: Uint8Array, stretched: Uint8Array): Uint8Array {
  return kdf(secret, concat(utf8e('mixia/unlock/v1\n'), stretched));
}

/** 已解锁的设备。锁定时 close()，内存中的密钥尽力清零。 */
export class DeviceSession {
  constructor(
    readonly installId: string,
    readonly deviceId: string,
    readonly authPub: Uint8Array,
    readonly level: Level,
    readonly sign: SignKeys,
    readonly box: BoxKeys,
    private readonly hw: HardwareKeys,
    /** 派生本地库密钥槽和本地密钥缓存时用。 */
    readonly secret: Uint8Array,
    readonly unlockKey: Uint8Array,
  ) {}

  /** 用硬件认证密钥签名，这是唯一能让服务器接受请求的东西。 */
  authSign(msg: Uint8Array): Promise<Uint8Array> {
    return this.hw.sign(this.installId, msg);
  }

  close(): void {
    wipe(this.sign.priv);
    wipe(this.box.priv);
    wipe(this.secret);
    wipe(this.unlockKey);
  }
}

function sessionFrom(
  rec: DeviceRecord,
  seed: Uint8Array,
  secret: Uint8Array,
  unlockKey: Uint8Array,
  hw: HardwareKeys,
): DeviceSession {
  return new DeviceSession(
    rec.installId,
    rec.deviceId,
    b64d(rec.authPub),
    rec.level,
    signKeysFromSeed(kdf(seed, 'mixia/dev-sign/v1')),
    boxKeysFromSeed(kdf(seed, 'mixia/dev-box/v1')),
    hw,
    secret,
    unlockKey,
  );
}

export class DeviceStore {
  private constructor(
    private kv: KV,
    private hw: HardwareKeys,
    private rec: DeviceRecord,
  ) {}

  get deviceId() {
    return this.rec.deviceId;
  }
  get level() {
    return this.rec.level;
  }
  get installId() {
    return this.rec.installId;
  }

  static async exists(kv: KV): Promise<boolean> {
    return (await kv.get(RECORD_KEY)) !== undefined;
  }

  static async load(kv: KV, hw: HardwareKeys): Promise<DeviceStore | undefined> {
    const raw = await kv.get(RECORD_KEY);
    return raw ? new DeviceStore(kv, hw, fromJson<DeviceRecord>(raw)) : undefined;
  }

  /** 生成全新设备身份。每次安装都是新身份，不继承任何旧设备。 */
  static async create(
    kv: KV,
    hw: HardwareKeys,
    passphrase: string,
    kdfMem?: number,
  ): Promise<{ store: DeviceStore; session: DeviceSession }> {
    const installId = randomId();
    const authPub = await hw.create(installId);
    const deviceId = deviceIdFromAuthPub(authPub);
    const secret = randomBytes(32);
    const seed = randomBytes(32);
    const params = newKdfParams(kdfMem);
    const unlockKey = unlockKeyFrom(secret, argon2id(passphrase, params));
    const sealedSecret = await hw.seal(installId, secret);
    const inner = aeadSeal(unlockKey, jsonBytes({ seed: b64e(seed) }), aadFor(deviceId));
    const rec: DeviceRecord = {
      v: 1,
      installId,
      deviceId,
      level: hw.level,
      authPub: b64e(authPub),
      kdf: params,
      sealedSecret: b64e(sealedSecret),
      n: b64e(inner.n),
      c: b64e(inner.c),
    };
    await kv.batch([{ t: 'put', k: RECORD_KEY, v: jsonBytes(rec) }]);
    return {
      store: new DeviceStore(kv, hw, rec),
      session: sessionFrom(rec, seed, secret, unlockKey, hw),
    };
  }

  private async openWith(unlockKey: Uint8Array, secret: Uint8Array): Promise<DeviceSession> {
    let seed: Uint8Array;
    try {
      const raw = aeadOpen(
        unlockKey,
        b64d(this.rec.n),
        b64d(this.rec.c),
        aadFor(this.rec.deviceId),
      );
      seed = b64d(JSON.parse(utf8d(raw)).seed as string);
    } catch {
      throw new MixiaError('wrong_passphrase');
    }
    return sessionFrom(this.rec, seed, secret, unlockKey, this.hw);
  }

  async unlock(passphrase: string): Promise<DeviceSession> {
    let secret: Uint8Array;
    try {
      secret = await this.hw.unseal(this.rec.installId, b64d(this.rec.sealedSecret));
    } catch {
      // 封存密钥不在这台设备的硬件里：数据目录被复制，或硬件被重置。
      throw new MixiaError('device_binding_failed');
    }
    return this.openWith(unlockKeyFrom(secret, argon2id(passphrase, this.rec.kdf)), secret);
  }

  /** 更换口令只重写本地密钥库，不影响任何库密钥或服务器数据。 */
  async changePassphrase(session: DeviceSession, oldPass: string, newPass: string): Promise<void> {
    const check = await this.unlock(oldPass);
    check.close();
    const seedBox = aeadOpen(
      session.unlockKey,
      b64d(this.rec.n),
      b64d(this.rec.c),
      aadFor(this.rec.deviceId),
    );
    const params = newKdfParams(this.rec.kdf.mem);
    const unlockKey = unlockKeyFrom(session.secret, argon2id(newPass, params));
    const inner = aeadSeal(unlockKey, seedBox, aadFor(this.rec.deviceId));
    const rec: DeviceRecord = { ...this.rec, kdf: params, n: b64e(inner.n), c: b64e(inner.c) };
    await this.kv.batch([{ t: 'put', k: RECORD_KEY, v: jsonBytes(rec) }]);
    this.rec = rec;
  }

  async enableQuickUnlock(session: DeviceSession): Promise<void> {
    if (!this.hw.quick) throw new MixiaError('quick_unavailable');
    await this.hw.quick.enroll(this.rec.installId, session.unlockKey);
  }

  async disableQuickUnlock(): Promise<void> {
    await this.hw.quick?.clear(this.rec.installId);
  }

  async quickUnlock(): Promise<DeviceSession> {
    if (!this.hw.quick) throw new MixiaError('quick_unavailable');
    const unlockKey = await this.hw.quick.retrieve(this.rec.installId);
    const secret = await this.hw.unseal(this.rec.installId, b64d(this.rec.sealedSecret));
    return this.openWith(unlockKey, secret);
  }

  /** 擦除本机身份：硬件密钥销毁后，本地数据永久无法解开。 */
  async wipe(): Promise<void> {
    await this.hw.quick?.clear(this.rec.installId).catch(() => undefined);
    await this.hw.destroy(this.rec.installId);
    await this.kv.batch([{ t: 'del', k: RECORD_KEY }]);
  }
}

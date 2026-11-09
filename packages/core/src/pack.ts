/**
 * Pack：一种文件格式覆盖备份、设备传输和冷库，只有接收方（slot）不同。
 * 头部不加密但被 AEAD 认证；头部里没有库名和任何业务内容。
 */
import {
  aeadOpen,
  aeadSeal,
  argon2id,
  assertKdfParams,
  b64d,
  b64e,
  boxOpen,
  boxSeal,
  concat,
  equalBytes,
  kdf,
  newKdfParams,
  randomBytes,
  utf8d,
  utf8e,
  type BoxKeys,
  type KdfParams,
} from './crypto';
import { MixiaError } from './errors';
import type { Policy, Version } from './vault';

const MAGIC = utf8e('MIXIAPK1');

export type PackKind = 'backup' | 'cold' | 'transfer';

export type PackSlot =
  | { t: 'seal'; to: string; w: string }
  | { t: 'pw'; kdf: KdfParams; n: string; w: string };

export interface PackHeader {
  v: 1;
  kind: PackKind;
  vaultId: string;
  gen: number;
  createdAt: number;
  count: number;
  slots: PackSlot[];
}

export interface Snapshot {
  vaultId: string;
  name: string;
  policy: Policy;
  versions: Version[];
  exportedAt: number;
  /** 附件密文。设备丢失后附件只能从这里找回。 */
  blobs?: Record<string, string>;
}

export type SlotSpec =
  | { t: 'seal'; to: Uint8Array }
  | { t: 'pw'; passphrase: string; code: Uint8Array; mem?: number };

function coldKey(code: Uint8Array, stretched: Uint8Array): Uint8Array {
  return kdf(code, concat(utf8e('mixia/cold/v1\n'), stretched));
}

export function createPack(kind: PackKind, gen: number, snap: Snapshot, specs: SlotSpec[]): Uint8Array {
  if (specs.length === 0) throw new MixiaError('pack_no_slots');
  const packKey = randomBytes(32);
  const slots: PackSlot[] = specs.map((s) => {
    if (s.t === 'seal') return { t: 'seal', to: b64e(s.to), w: b64e(boxSeal(s.to, packKey)) };
    const params = newKdfParams(s.mem);
    const { n, c } = aeadSeal(
      coldKey(s.code, argon2id(s.passphrase, params)),
      packKey,
      utf8e('mixia/pack-slot/v1'),
    );
    return { t: 'pw', kdf: params, n: b64e(n), w: b64e(c) };
  });
  const header: PackHeader = {
    v: 1,
    kind,
    vaultId: snap.vaultId,
    gen,
    createdAt: snap.exportedAt,
    count: snap.versions.length,
    slots,
  };
  const hb = utf8e(JSON.stringify(header));
  const { n, c } = aeadSeal(packKey, utf8e(JSON.stringify(snap)), hb);
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, hb.length, true);
  return concat(MAGIC, len, hb, n, c);
}

function split(bytes: Uint8Array): { header: PackHeader; hb: Uint8Array; body: Uint8Array } {
  if (bytes.length < 12 || !equalBytes(bytes.slice(0, 8), MAGIC)) throw new MixiaError('not_a_pack');
  const len = new DataView(bytes.buffer, bytes.byteOffset + 8, 4).getUint32(0, true);
  if (12 + len > bytes.length) throw new MixiaError('pack_truncated');
  const hb = bytes.slice(12, 12 + len);
  let header: PackHeader;
  try {
    header = JSON.parse(utf8d(hb)) as PackHeader;
  } catch {
    throw new MixiaError('pack_corrupt');
  }
  if (header.v !== 1) throw new MixiaError('pack_unsupported_version');
  return { header, hb, body: bytes.slice(12 + len) };
}

export function readPackHeader(bytes: Uint8Array): PackHeader {
  return split(bytes).header;
}

function decryptBody(packKey: Uint8Array, hb: Uint8Array, body: Uint8Array): Snapshot {
  let plain: Uint8Array;
  try {
    plain = aeadOpen(packKey, body.slice(0, 24), body.slice(24), hb);
  } catch {
    throw new MixiaError('pack_corrupt');
  }
  return JSON.parse(utf8d(plain)) as Snapshot;
}

/** 用恢复私钥或设备私钥打开。 */
export function openPackWithBox(bytes: Uint8Array, box: BoxKeys): Snapshot {
  const { header, hb, body } = split(bytes);
  const pub = b64e(box.pub);
  const slot = header.slots.find((s) => s.t === 'seal' && s.to === pub);
  if (!slot || slot.t !== 'seal') throw new MixiaError('pack_wrong_key');
  let packKey: Uint8Array;
  try {
    packKey = boxOpen(box, b64d(slot.w));
  } catch {
    throw new MixiaError('pack_wrong_key');
  }
  return decryptBody(packKey, hb, body);
}

/** 冷库：口令和恢复码都对才能打开。 */
export function openPackWithCold(bytes: Uint8Array, passphrase: string, code: Uint8Array): Snapshot {
  const { header, hb, body } = split(bytes);
  const slot = header.slots.find((s) => s.t === 'pw');
  if (!slot || slot.t !== 'pw') throw new MixiaError('pack_wrong_key');
  assertKdfParams(slot.kdf);
  let packKey: Uint8Array;
  try {
    packKey = aeadOpen(
      coldKey(code, argon2id(passphrase, slot.kdf)),
      b64d(slot.n),
      b64d(slot.w),
      utf8e('mixia/pack-slot/v1'),
    );
  } catch {
    throw new MixiaError('pack_wrong_key');
  }
  return decryptBody(packKey, hb, body);
}

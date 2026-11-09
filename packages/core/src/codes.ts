/**
 * 面向人的编码：恢复码与配对码，Crockford base32（去掉易混淆字母）。
 */
import { kdf, randomBytes, signKeysFromSeed, boxKeysFromSeed, type BoxKeys, type SignKeys } from './crypto';
import { MixiaError } from './errors';

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function base32Encode(bytes: Uint8Array): string {
  let out = '';
  let bits = 0;
  let value = 0;
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text: string, byteLength: number): Uint8Array {
  const out = new Uint8Array(byteLength);
  let bits = 0;
  let value = 0;
  let o = 0;
  for (const ch of text) {
    const i = ALPHABET.indexOf(ch);
    if (i < 0) throw new MixiaError('bad_code');
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      if (o >= byteLength) break;
      out[o++] = (value >>> (bits - 8)) & 255;
      bits -= 8;
      value &= (1 << bits) - 1;
    }
  }
  if (o !== byteLength) throw new MixiaError('bad_code');
  return out;
}

/** 容错输入：大小写、连字符、空格，以及 O/I/L 这些容易写错的字符。 */
export function normalizeCode(text: string): string {
  return text
    .toUpperCase()
    .replace(/[^0-9A-Z]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1')
    .replace(/U/g, 'V');
}

const group = (s: string, n: number): string => s.match(new RegExp(`.{1,${n}}`, 'g'))?.join('-') ?? s;

const RC_BYTES = 25;
const RC_CHARS = 40;

function checksum(rc: Uint8Array): string {
  return base32Encode(kdf(rc, 'mixia/rc-check/v1').slice(0, 3)).slice(0, 4);
}

export interface RecoveryCode {
  /** 打印 / 展示用的文本。 */
  text: string;
  bytes: Uint8Array;
}

export function newRecoveryCode(): RecoveryCode {
  const bytes = randomBytes(RC_BYTES);
  return { bytes, text: formatRecoveryCode(bytes) };
}

export function formatRecoveryCode(bytes: Uint8Array): string {
  return group(base32Encode(bytes) + checksum(bytes), 4);
}

/** 校验位不符时报错，避免用户抄错一位后得到一把错误的根密钥。 */
export function parseRecoveryCode(text: string): Uint8Array {
  const n = normalizeCode(text);
  if (n.length !== RC_CHARS + 4) throw new MixiaError('bad_recovery_code');
  const bytes = base32Decode(n.slice(0, RC_CHARS), RC_BYTES);
  if (checksum(bytes) !== n.slice(RC_CHARS)) throw new MixiaError('bad_recovery_code');
  return bytes;
}

export interface RootKeys {
  sign: SignKeys;
  box: BoxKeys;
}

export function rootKeysFrom(rc: Uint8Array): RootKeys {
  return {
    sign: signKeysFromSeed(kdf(rc, 'mixia/root-sign/v1')),
    box: boxKeysFromSeed(kdf(rc, 'mixia/root-box/v1')),
  };
}

/** 库恢复公钥：备份时用它封装，恢复时才需要输入恢复码。 */
export function vaultRecoveryBox(rc: Uint8Array): BoxKeys {
  return boxKeysFromSeed(kdf(rc, 'mixia/vault-box/v1'));
}

export interface PairCode {
  text: string;
  pairId: string;
  secret: string;
}

export function newPairCode(): PairCode {
  const raw = base32Encode(randomBytes(15));
  return { text: group(raw, 4), pairId: raw.slice(0, 6), secret: raw.slice(6) };
}

export function parsePairCode(text: string): PairCode {
  const n = normalizeCode(text);
  if (n.length !== 24) throw new MixiaError('bad_pair_code');
  return { text: group(n, 4), pairId: n.slice(0, 6), secret: n.slice(6) };
}

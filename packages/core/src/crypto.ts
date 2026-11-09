/**
 * 密码学原语。全部来自 libsodium（WASM）和 @noble，这里只做薄封装与用途分离，不实现任何算法。
 */
import sodiumLib from 'libsodium-wrappers-sumo';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2';

let ready = false;
export async function initCrypto(): Promise<void> {
  if (ready) return;
  await sodiumLib.ready;
  ready = true;
}

function s(): typeof sodiumLib {
  if (!ready) throw new Error('crypto_not_ready');
  return sodiumLib;
}

export const utf8e = (t: string): Uint8Array => new TextEncoder().encode(t);
export const utf8d = (b: Uint8Array): string => new TextDecoder('utf-8', { fatal: true }).decode(b);

export function b64e(b: Uint8Array): string {
  return s().to_base64(b, s().base64_variants.URLSAFE_NO_PADDING);
}
export function b64d(t: string): Uint8Array {
  return s().from_base64(t, s().base64_variants.URLSAFE_NO_PADDING);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export const randomBytes = (n: number): Uint8Array => s().randombytes_buf(n);
export const randomId = (): string => b64e(randomBytes(16));
export const sha256 = (b: Uint8Array): Uint8Array => nobleSha256(b);
export const hex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && s().memcmp(a, b);
}

/** 尽力清零。JS 中其他副本无法保证被清除，这是架构文档中声明的边界。 */
export function wipe(b: Uint8Array | undefined): void {
  if (b) s().memzero(b);
}

/** 带用途标签的密钥派生：BLAKE2b-256(key=key, msg=label)。key 长度须在 16..64 字节。 */
export function kdf(key: Uint8Array, label: string | Uint8Array): Uint8Array {
  const msg = typeof label === 'string' ? utf8e(label) : label;
  return s().crypto_generichash(32, msg, key);
}

export interface Sealed {
  n: Uint8Array;
  c: Uint8Array;
}

export function aeadSeal(key: Uint8Array, plain: Uint8Array, aad: Uint8Array): Sealed {
  const n = randomBytes(s().crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const c = s().crypto_aead_xchacha20poly1305_ietf_encrypt(plain, aad, null, n, key);
  return { n, c };
}

/** 认证失败时抛错，绝不返回未认证的明文。 */
export function aeadOpen(key: Uint8Array, n: Uint8Array, c: Uint8Array, aad: Uint8Array): Uint8Array {
  return s().crypto_aead_xchacha20poly1305_ietf_decrypt(null, c, aad, n, key);
}

export interface KdfParams {
  salt: string;
  ops: number;
  mem: number;
}

export const KDF_FLOOR = { ops: 3, mem: 64 * 1024 * 1024 };
export const KDF_CEIL = { ops: 16, mem: 1024 * 1024 * 1024 };

/** 校验头部里的参数：防止攻击者改写文件把口令派生降级，也防止超大参数造成拒绝服务。 */
export function assertKdfParams(p: KdfParams): void {
  if (
    !Number.isInteger(p.ops) ||
    !Number.isInteger(p.mem) ||
    p.ops < KDF_FLOOR.ops ||
    p.mem < KDF_FLOOR.mem ||
    p.ops > KDF_CEIL.ops ||
    p.mem > KDF_CEIL.mem
  ) {
    throw new Error('kdf_params_rejected');
  }
}

export function newKdfParams(mem = 128 * 1024 * 1024, ops = 3): KdfParams {
  const p = { salt: b64e(randomBytes(s().crypto_pwhash_SALTBYTES)), ops, mem };
  assertKdfParams(p);
  return p;
}

/** 口令先做 NFKC，避免不同平台输入法产生的等价字符得到不同密钥。 */
export function argon2id(passphrase: string, p: KdfParams): Uint8Array {
  assertKdfParams(p);
  return s().crypto_pwhash(
    32,
    utf8e(passphrase.normalize('NFKC')),
    b64d(p.salt),
    p.ops,
    p.mem,
    s().crypto_pwhash_ALG_ARGON2ID13,
  );
}

export interface SignKeys {
  pub: Uint8Array;
  priv: Uint8Array;
}
export interface BoxKeys {
  pub: Uint8Array;
  priv: Uint8Array;
}

export function signKeysFromSeed(seed: Uint8Array): SignKeys {
  const k = s().crypto_sign_seed_keypair(seed);
  return { pub: k.publicKey, priv: k.privateKey };
}
export function boxKeysFromSeed(seed: Uint8Array): BoxKeys {
  const k = s().crypto_box_seed_keypair(seed);
  return { pub: k.publicKey, priv: k.privateKey };
}
export const edSign = (priv: Uint8Array, msg: Uint8Array): Uint8Array =>
  s().crypto_sign_detached(msg, priv);

export function edVerify(pub: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  try {
    return s().crypto_sign_verify_detached(sig, msg, pub);
  } catch {
    return false;
  }
}
export const boxSeal = (pub: Uint8Array, msg: Uint8Array): Uint8Array => s().crypto_box_seal(msg, pub);
export const boxOpen = (k: BoxKeys, c: Uint8Array): Uint8Array =>
  s().crypto_box_seal_open(c, k.pub, k.priv);

/**
 * 工具：搜索、密码生成、强度评估、TOTP、本地安全检查。全部纯本地运行。
 */
import { hmac } from '@noble/hashes/hmac';
import { sha1 } from '@noble/hashes/legacy';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { wordlist } from '@scure/bip39/wordlists/english';
import { randomBytes } from './crypto';
import { isKeyItem, needsAttention } from './keys';
import { MixiaError } from './errors';
import type { ItemView } from './model';

// —— 搜索 ——

export interface ParsedQuery {
  terms: string[];
  provider: string[];
  tag: string[];
  type: string[];
  env: string[];
  vault: string[];
  is: string[];
}

const TOKEN = /(tag|type|env|vault|is|provider):("[^"]*"|\S+)/g;

export function parseQuery(q: string): ParsedQuery {
  const out: ParsedQuery = { terms: [], provider: [], tag: [], type: [], env: [], vault: [], is: [] };
  const rest = q.replace(TOKEN, (_m, k: keyof ParsedQuery, v: string) => {
    (out[k] as string[]).push(v.replace(/^"|"$/g, '').toLowerCase());
    return ' ';
  });
  out.terms = rest
    .toLowerCase()
    .split(/\s+/)
    .filter((t) => t.length > 0);
  return out;
}

export function matches(it: ItemView, q: ParsedQuery, vaultName = ''): boolean {
  const d = it.data;
  if (q.tag.length && !q.tag.every((t) => d.tags?.some((x) => x.toLowerCase() === t))) return false;
  if (q.type.length && !q.type.includes(d.type)) return false;
  if (q.env.length && !q.env.includes((d.env ?? '').toLowerCase())) return false;
  if (q.vault.length && !q.vault.some((x) => vaultName.toLowerCase().includes(x))) return false;
  if (q.provider.length && !q.provider.includes((d.provider ?? '').toLowerCase())) return false;
  for (const flag of q.is) {
    if (flag === 'fav' && !d.favorite) return false;
    if (flag === 'conflict' && !it.conflict) return false;
    if (flag === 'totp' && !d.totp) return false;
    if (flag === 'key' && !isKeyItem(d)) return false;
    if (flag === 'expiring' && !needsAttention(d)) return false;
  }
  if (q.terms.length === 0) return true;
  // 只搜索非机密字段，避免输入框里的片段和密码内容产生匹配信号
  const hay = [
    d.title,
    d.username,
    d.notes,
    d.env,
    d.provider,
    ...(d.urls ?? []),
    ...(d.tags ?? []),
    ...(d.usedBy ?? []),
    // 机密字段可以按名字搜（比如变量名），但绝不搜它的值
    ...(d.fields ?? []).flatMap((f) => (f.secret ? [f.name, f.envName] : [f.name, f.value, f.envName])),
  ]
    .filter(Boolean)
    .join('\n')
    .toLowerCase();
  return q.terms.every((t) => hay.includes(t));
}

export function search(items: ItemView[], query: string, vaultNameOf?: (id: string) => string): ItemView[] {
  const q = parseQuery(query);
  return items.filter((it) => matches(it, q, vaultNameOf?.(it.vaultId) ?? ''));
}

// —— 密码生成 ——

/** 无偏随机整数：拒绝采样，避免取模偏差。 */
function randomInt(maxExclusive: number): number {
  const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
  for (;;) {
    const b = randomBytes(4);
    const n = new DataView(b.buffer, b.byteOffset, 4).getUint32(0, true);
    if (n < limit) return n % maxExclusive;
  }
}

export interface GenOptions {
  length: number;
  lower: boolean;
  upper: boolean;
  digits: boolean;
  symbols: boolean;
  /** 去掉 0O1lI 等容易看错的字符。 */
  unambiguous: boolean;
}

export const DEFAULT_GEN: GenOptions = {
  length: 20,
  lower: true,
  upper: true,
  digits: true,
  symbols: true,
  unambiguous: false,
};

const AMBIGUOUS = /[0O1lI|]/g;

export function generatePassword(o: GenOptions = DEFAULT_GEN): string {
  const sets: string[] = [];
  if (o.lower) sets.push('abcdefghijklmnopqrstuvwxyz');
  if (o.upper) sets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  if (o.digits) sets.push('0123456789');
  if (o.symbols) sets.push('!@#$%^&*()-_=+[]{};:,.?');
  const clean = sets.map((s) => (o.unambiguous ? s.replace(AMBIGUOUS, '') : s));
  if (clean.length === 0) throw new MixiaError('gen_no_charset');
  if (o.length < clean.length) throw new MixiaError('gen_too_short');
  const all = clean.join('');
  const chars: string[] = clean.map((s) => s[randomInt(s.length)]!);
  while (chars.length < o.length) chars.push(all[randomInt(all.length)]!);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j]!, chars[i]!];
  }
  return chars.join('');
}

export function generatePassphrase(words = 6, sep = '-'): string {
  const out: string[] = [];
  for (let i = 0; i < words; i++) out.push(wordlist[randomInt(wordlist.length)]!);
  return out.join(sep);
}

// —— 强度 ——

const COMMON = /(password|passwd|qwerty|asdf|zxcv|admin|welcome|letmein|iloveyou|abc123|111111|123456)/i;

export interface Strength {
  score: 0 | 1 | 2 | 3 | 4;
  bits: number;
  label: string;
}

/** 粗略估计：字符池熵扣除常见模式。只用于提示，不作为安全判定。 */
export function strength(pw: string): Strength {
  if (!pw) return { score: 0, bits: 0, label: '空' };
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  const unique = new Set(pw).size;
  let bits = Math.log2(Math.max(pool, 2)) * Math.min(pw.length, unique * 2);
  if (COMMON.test(pw)) bits *= 0.4;
  if (/^(.)\1+$/.test(pw)) bits = 2;
  if (/^\d+$/.test(pw)) bits = Math.min(bits, 20);
  const score = (bits < 28 ? 0 : bits < 45 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4) as Strength['score'];
  return { score, bits: Math.round(bits), label: ['很弱', '弱', '一般', '强', '很强'][score]! };
}

// —— TOTP (RFC 6238) ——

export interface TotpConfig {
  secret: Uint8Array;
  digits: number;
  period: number;
  algo: 'SHA1' | 'SHA256' | 'SHA512';
}

function base32Rfc(text: string): Uint8Array {
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = text.toUpperCase().replace(/[\s=-]/g, '');
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    const i = alpha.indexOf(ch);
    if (i < 0) throw new MixiaError('bad_totp');
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
      value &= (1 << bits) - 1;
    }
  }
  if (out.length === 0) throw new MixiaError('bad_totp');
  return new Uint8Array(out);
}

export function parseTotp(input: string): TotpConfig {
  const text = input.trim();
  if (text.toLowerCase().startsWith('otpauth://')) {
    const u = new URL(text);
    const secret = u.searchParams.get('secret');
    if (!secret) throw new MixiaError('bad_totp');
    const algo = (u.searchParams.get('algorithm') ?? 'SHA1').toUpperCase();
    if (algo !== 'SHA1' && algo !== 'SHA256' && algo !== 'SHA512') throw new MixiaError('bad_totp');
    return {
      secret: base32Rfc(secret),
      digits: Number(u.searchParams.get('digits') ?? 6),
      period: Number(u.searchParams.get('period') ?? 30),
      algo,
    };
  }
  return { secret: base32Rfc(text), digits: 6, period: 30, algo: 'SHA1' };
}

export function totpCode(cfg: TotpConfig, nowMs = Date.now()): { code: string; remaining: number } {
  const counter = Math.floor(nowMs / 1000 / cfg.period);
  const msg = new Uint8Array(8);
  new DataView(msg.buffer).setBigUint64(0, BigInt(counter), false);
  const hash = cfg.algo === 'SHA1' ? sha1 : cfg.algo === 'SHA256' ? sha256 : sha512;
  const mac = hmac(hash, cfg.secret, msg);
  const off = mac[mac.length - 1]! & 15;
  const bin =
    ((mac[off]! & 127) << 24) | (mac[off + 1]! << 16) | (mac[off + 2]! << 8) | mac[off + 3]!;
  const code = (bin % 10 ** cfg.digits).toString().padStart(cfg.digits, '0');
  return { code, remaining: cfg.period - (Math.floor(nowMs / 1000) % cfg.period) };
}

// —— 本地安全检查 ——

export interface SecurityReport {
  weak: ItemView[];
  reused: ItemView[][];
  stale: ItemView[];
  noTotp: ItemView[];
  exposed: ItemView[];
}

export function securityReport(items: ItemView[], staleDays = 365): SecurityReport {
  const withPw = items.filter((i) => i.data.password);
  const groups = new Map<string, ItemView[]>();
  for (const it of withPw) {
    const k = it.data.password!;
    const g = groups.get(k);
    if (g) g.push(it);
    else groups.set(k, [it]);
  }
  const cutoff = Date.now() - staleDays * 86_400_000;
  return {
    weak: withPw.filter((i) => strength(i.data.password!).score <= 1),
    reused: [...groups.values()].filter((g) => g.length > 1),
    stale: withPw.filter((i) => (i.data.passwordChangedAt ?? i.data.updatedAt) < cutoff),
    noTotp: items.filter((i) => i.data.type === 'login' && !i.data.totp && i.data.env === 'production'),
    exposed: items.filter((i) => i.data.cloudExposed),
  };
}

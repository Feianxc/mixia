/**
 * 导入导出。解析全部在本地完成，导入前先给出预览，不删除任何原始数据。
 */
import { MixiaError } from './errors';
import { ITEM_TEMPLATES, newItem, type Field, type ItemData, type ItemType, type ItemView } from './model';

/** RFC 4180 CSV 解析：引号、转义引号、字段内换行、BOM。 */
export function parseCsv(text: string): string[][] {
  const src = text.replace(/^﻿/, '');
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let quoted = false;
  let started = false;
  for (let i = 0; i < src.length; i++) {
    const ch = src[i]!;
    if (quoted) {
      if (ch === '"') {
        if (src[i + 1] === '"') {
          cell += '"';
          i++;
        } else quoted = false;
      } else cell += ch;
      continue;
    }
    if (ch === '"') {
      quoted = true;
      started = true;
    } else if (ch === ',') {
      row.push(cell);
      cell = '';
      started = true;
    } else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && src[i + 1] === '\n') i++;
      if (started || cell) {
        row.push(cell);
        rows.push(row);
      }
      row = [];
      cell = '';
      started = false;
    } else {
      cell += ch;
      started = true;
    }
  }
  if (started || cell) {
    row.push(cell);
    rows.push(row);
  }
  return rows;
}

const ALIASES: Record<string, string[]> = {
  title: ['title', 'name', '标题', '名称', 'account'],
  username: ['username', 'login_username', 'user name', 'login', '用户名', '账号', 'user'],
  password: ['password', 'login_password', '密码'],
  url: ['url', 'login_uri', 'uri', 'website', 'web site', 'hostname', '网址', '地址'],
  notes: ['notes', 'note', 'extra', 'comment', 'comments', '备注'],
  totp: ['totp', 'login_totp', 'otpauth', 'otp'],
  folder: ['folder', 'group', 'grouping', '分类', '文件夹', '分组', 'category'],
  tags: ['tags', 'tag', '标签'],
};

export interface ImportRow {
  data: ItemData;
  /** 以 / 分隔的文件夹路径，空字符串表示根。 */
  folderPath: string;
}

export interface ImportPreview {
  format: string;
  rows: ImportRow[];
  skipped: number;
  warnings: string[];
  /** 文件里写明的目标库名称（所有条目一致时才有）。导入对话框据此预选，免得把重要内容导进云库 */
  suggestedVault?: string;
}

function mapHeader(header: string[]): Map<string, number> {
  const m = new Map<string, number>();
  header.forEach((h, i) => {
    const k = h.trim().toLowerCase();
    for (const [field, names] of Object.entries(ALIASES)) {
      if (names.includes(k) && !m.has(field)) m.set(field, i);
    }
  });
  return m;
}

function titleFromUrl(url: string): string {
  try {
    return new URL(url.includes('://') ? url : `https://${url}`).hostname.replace(/^www\./, '');
  } catch {
    return url;
  }
}

export function importCsv(text: string): ImportPreview {
  const rows = parseCsv(text);
  const header = rows[0];
  if (!header) return { format: 'CSV', rows: [], skipped: 0, warnings: ['文件为空'] };
  const map = mapHeader(header);
  if (!map.has('password') && !map.has('username') && !map.has('title')) {
    throw new MixiaError('csv_unrecognized');
  }
  const known = new Set(map.values());
  const out: ImportRow[] = [];
  let skipped = 0;
  for (const r of rows.slice(1)) {
    const get = (k: string) => {
      const i = map.get(k);
      return i === undefined ? '' : (r[i] ?? '').trim();
    };
    const url = get('url');
    const title = get('title') || titleFromUrl(url) || get('username');
    if (!title && !get('password')) {
      skipped++;
      continue;
    }
    const data = newItem('login', title || '未命名');
    data.fields = [];
    if (get('username')) data.username = get('username');
    if (get('password')) data.password = r[map.get('password')!] ?? '';
    if (url) data.urls = [url];
    if (get('notes')) data.notes = get('notes');
    if (get('totp')) data.totp = get('totp');
    if (get('tags')) data.tags = get('tags').split(/[,;，；]/).map((t) => t.trim()).filter(Boolean);
    // 无法识别的列不丢弃，作为自定义字段保留
    header.forEach((h, i) => {
      if (!known.has(i) && (r[i] ?? '').trim()) {
        data.fields!.push({ name: h.trim(), value: r[i]!.trim(), secret: false });
      }
    });
    out.push({ data, folderPath: get('folder').replace(/\\/g, '/').replace(/^\/+|\/+$/g, '') });
  }
  return { format: 'CSV', rows: out, skipped, warnings: [] };
}

interface BwItem {
  type: number;
  name?: string;
  notes?: string | null;
  favorite?: boolean;
  folderId?: string | null;
  login?: {
    username?: string | null;
    password?: string | null;
    totp?: string | null;
    uris?: { uri?: string | null }[] | null;
  };
  card?: Record<string, string | null>;
  fields?: { name?: string; value?: string | null; type?: number }[] | null;
}

export function importBitwardenJson(text: string): ImportPreview {
  const doc = JSON.parse(text) as {
    encrypted?: boolean;
    folders?: { id: string; name: string }[];
    items?: BwItem[];
  };
  if (doc.encrypted) throw new MixiaError('bitwarden_encrypted');
  if (!Array.isArray(doc.items)) throw new MixiaError('json_unrecognized');
  const folders = new Map((doc.folders ?? []).map((f) => [f.id, f.name]));
  const rows: ImportRow[] = [];
  let skipped = 0;
  const warnings: string[] = [];
  for (const it of doc.items) {
    const type: ItemType | undefined = it.type === 1 ? 'login' : it.type === 2 ? 'note' : it.type === 3 ? 'card' : undefined;
    if (!type) {
      skipped++;
      continue;
    }
    const data = newItem(type, it.name ?? '未命名');
    if (type !== 'card') data.fields = [];
    if (it.notes) data.notes = it.notes;
    if (it.favorite) data.favorite = true;
    if (it.login) {
      if (it.login.username) data.username = it.login.username;
      if (it.login.password) data.password = it.login.password;
      if (it.login.totp) data.totp = it.login.totp;
      const urls = (it.login.uris ?? []).map((u) => u.uri).filter((u): u is string => !!u);
      if (urls.length) data.urls = urls;
    }
    if (it.card) {
      const c = it.card;
      data.fields = (
        [
          { name: '持卡人', value: c.cardholderName ?? '' },
          { name: '卡号', value: c.number ?? '', secret: true },
          { name: '有效期', value: [c.expMonth, c.expYear].filter(Boolean).join('/') },
          { name: 'CVV', value: c.code ?? '', secret: true },
        ] as Field[]
      ).filter((f) => f.value);
    }
    for (const f of it.fields ?? []) {
      (data.fields ??= []).push({ name: f.name ?? '', value: f.value ?? '', secret: f.type === 1 });
    }
    rows.push({ data, folderPath: (it.folderId && folders.get(it.folderId)) || '' });
  }
  if (skipped) warnings.push(`跳过 ${skipped} 条不支持的类型`);
  return { format: 'Bitwarden JSON', rows, skipped, warnings };
}

const ITEM_TYPES = Object.keys(ITEM_TEMPLATES) as ItemType[];
const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);
const strList = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x.trim() !== '').map((x) => x.trim()) : [];
const cleanPath = (p: string) => p.replace(/\\/g, '/').split('/').map((s) => s.trim()).filter(Boolean).join('/');

/**
 * 密匣自己的明文 JSON：导出的 mixia-plain-v1，或按同一格式整理出来的迁移文件。
 * 和 Bitwarden 不同，它保留条目类型（API 密钥、SSH 密钥等）、机密字段、服务商和文件夹路径。
 * 只取认识的字段；id、所在库、时间戳、回收站里的条目一律不带进来。
 */
export function importMixiaJson(doc: { items?: unknown }): ImportPreview {
  if (!Array.isArray(doc.items)) throw new MixiaError('json_unrecognized');
  const rows: ImportRow[] = [];
  let skipped = 0;
  for (const raw of doc.items) {
    const it = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
    const type = it.type as ItemType;
    const title = str(it.title)?.trim();
    if (!ITEM_TYPES.includes(type) || !title || typeof it.trashedAt === 'number') {
      skipped++;
      continue;
    }
    const data = newItem(type, title);
    data.fields = Array.isArray(it.fields)
      ? it.fields.flatMap((f): Field[] => {
          const o = (f && typeof f === 'object' ? f : {}) as Record<string, unknown>;
          const name = str(o.name);
          const value = str(o.value);
          if (name === undefined || value === undefined) return [];
          const envName = str(o.envName);
          return [{ name, value, ...(o.secret === true ? { secret: true } : {}), ...(envName && /^[A-Za-z_][A-Za-z0-9_]*$/.test(envName) ? { envName } : {}) }];
        })
      : [];
    for (const k of ['username', 'password', 'totp', 'notes', 'provider', 'env'] as const) {
      const v = str(it[k]);
      if (v) data[k] = v;
    }
    const urls = strList(it.urls);
    if (urls.length) data.urls = urls;
    const tags = strList(it.tags);
    if (tags.length) data.tags = tags;
    const usedBy = strList(it.usedBy);
    if (usedBy.length) data.usedBy = usedBy;
    if (it.favorite === true) data.favorite = true;
    if (typeof it.expiresAt === 'number' && Number.isFinite(it.expiresAt)) data.expiresAt = it.expiresAt;
    if (typeof it.rotateDays === 'number' && it.rotateDays > 0) data.rotateDays = it.rotateDays;
    rows.push({ data, folderPath: cleanPath(str(it.folderPath) ?? '') });
  }
  const vaults = new Set(
    (doc.items as unknown[]).map((x) => (x && typeof x === 'object' ? str((x as Record<string, unknown>).vault)?.trim() : undefined)),
  );
  const only = vaults.size === 1 ? [...vaults][0] : undefined;
  return {
    format: '密匣 JSON',
    rows,
    skipped,
    warnings: skipped ? [`跳过 ${skipped} 条无法识别或在回收站里的条目`] : [],
    ...(only ? { suggestedVault: only } : {}),
  };
}

export function detectAndImport(fileName: string, text: string): ImportPreview {
  const t = text.trimStart();
  if (fileName.toLowerCase().endsWith('.json') || t.startsWith('{')) {
    const doc = JSON.parse(text) as { format?: unknown };
    if (typeof doc?.format === 'string' && doc.format.startsWith('mixia-plain')) return importMixiaJson(doc as { items?: unknown });
    return importBitwardenJson(text);
  }
  return importCsv(text);
}

export const dedupeKey = (d: ItemData): string =>
  [
    d.title.toLowerCase(),
    (d.username ?? '').toLowerCase(),
    d.password ?? '',
    (d.urls ?? [])[0] ?? '',
    // 密钥条目没有账号密码，只看标题会把内容不同的同名条目当成重复
    ...(d.fields ?? []).filter((f) => f.secret).map((f) => `${f.name}\0${f.value}`),
  ].join('\0');

export function markDuplicates(rows: ImportRow[], existing: ItemView[]): { fresh: ImportRow[]; dupes: ImportRow[] } {
  const seen = new Set(existing.map((e) => dedupeKey(e.data)));
  const fresh: ImportRow[] = [];
  const dupes: ImportRow[] = [];
  for (const r of rows) {
    const k = dedupeKey(r.data);
    if (seen.has(k)) dupes.push(r);
    else {
      seen.add(k);
      fresh.push(r);
    }
  }
  return { fresh, dupes };
}

/** 明文导出。调用方必须先重新验证口令并让用户确认风险。带上文件夹路径，再导入时分类不丢。 */
export function exportJson(items: ItemView[], vaultName: (id: string) => string, folderPath?: (it: ItemView) => string): string {
  return JSON.stringify(
    {
      format: 'mixia-plain-v1',
      exportedAt: new Date().toISOString(),
      items: items.map((i) => ({ vault: vaultName(i.vaultId), id: i.id, ...i.data, folderPath: folderPath?.(i) ?? '' })),
    },
    null,
    2,
  );
}

const csvCell = (s: string) => (/[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s);

export function exportCsv(items: ItemView[], folderPath: (it: ItemView) => string): string {
  const head = ['title', 'username', 'password', 'url', 'notes', 'totp', 'folder', 'tags'];
  const lines = [head.join(',')];
  for (const i of items) {
    const d = i.data;
    lines.push(
      [
        d.title,
        d.username ?? '',
        d.password ?? '',
        (d.urls ?? [])[0] ?? '',
        d.notes ?? '',
        d.totp ?? '',
        folderPath(i),
        (d.tags ?? []).join(';'),
      ]
        .map(csvCell)
        .join(','),
    );
  }
  return lines.join('\r\n');
}

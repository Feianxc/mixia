/**
 * 领域模型：条目、文件夹、自定义分组。
 * 未知字段全部原样保留，旧客户端不会把新版本写入的数据丢掉。
 */
import { randomId } from './crypto';
import { MixiaError } from './errors';
import type { AttachmentRef, Vault, Version } from './vault';

export type ItemType =
  | 'login'
  | 'server'
  | 'database'
  | 'api'
  | 'token'
  | 'ssh'
  | 'cert'
  | 'env'
  | 'note'
  | 'card'
  | 'wifi';

export interface Field {
  name: string;
  value: string;
  secret?: boolean;
  /** 复制为环境变量时用的名字。 */
  envName?: string;
}

export interface ItemData {
  type: ItemType;
  title: string;
  username?: string;
  password?: string;
  urls?: string[];
  totp?: string;
  notes?: string;
  fields?: Field[];
  folder?: string | null;
  tags?: string[];
  env?: string;
  favorite?: boolean;
  /** 换下来的旧值。field 为空表示密码，否则是机密字段的名字。 */
  passwordHistory?: { value: string; changedAt: number; field?: string }[];
  attachments?: AttachmentRef[];
  trashedAt?: number;
  createdAt: number;
  updatedAt: number;
  passwordChangedAt?: number;
  /** 密钥所属的服务商。 */
  provider?: string;
  /** 到期时间。 */
  expiresAt?: number;
  /** 轮换周期（天）。 */
  rotateDays?: number;
  /** 这把密钥用在哪些项目、服务器上。换的时候要逐个更新。 */
  usedBy?: string[];
  /** 曾进入云端：从云库移回本地时保留，提示用户去原系统改密码。 */
  cloudExposed?: boolean;
  [unknownField: string]: unknown;
}

export const ITEM_TEMPLATES: Record<ItemType, { label: string; fields: Field[] }> = {
  login: { label: '网站登录', fields: [] },
  server: {
    label: '服务器',
    fields: [
      { name: '主机', value: '' },
      { name: '端口', value: '22' },
      { name: 'SSH 私钥', value: '', secret: true },
    ],
  },
  database: {
    label: '数据库',
    fields: [
      { name: '主机', value: '' },
      { name: '端口', value: '' },
      { name: '数据库名', value: '' },
    ],
  },
  api: {
    label: 'API 密钥',
    fields: [
      { name: 'Endpoint', value: '' },
      { name: 'API Key', value: '', secret: true },
      { name: 'Secret', value: '', secret: true },
    ],
  },
  token: {
    label: '访问令牌',
    fields: [
      { name: 'Token', value: '', secret: true },
      { name: '权限范围', value: '' },
    ],
  },
  ssh: {
    label: 'SSH 密钥',
    fields: [
      { name: '私钥', value: '', secret: true },
      { name: '公钥', value: '' },
      { name: '私钥口令', value: '', secret: true },
    ],
  },
  cert: {
    label: '证书',
    fields: [
      { name: '证书', value: '' },
      { name: '私钥', value: '', secret: true },
      { name: '域名', value: '' },
    ],
  },
  env: { label: '环境变量组', fields: [] },
  note: { label: '安全笔记', fields: [] },
  card: {
    label: '银行卡',
    fields: [
      { name: '卡号', value: '', secret: true },
      { name: '有效期', value: '' },
      { name: 'CVV', value: '', secret: true },
    ],
  },
  wifi: { label: 'Wi-Fi', fields: [{ name: 'SSID', value: '' }] },
};

export const ENVIRONMENTS = ['production', 'staging', 'testing', 'development'] as const;
export const ENV_LABELS: Record<string, string> = {
  production: '生产',
  staging: '预发布',
  testing: '测试',
  development: '开发',
};

export interface ItemView {
  vaultId: string;
  id: string;
  data: ItemData;
  conflict: boolean;
  heads: Version[];
}

export function listItems(v: Vault, opts: { trash?: boolean } = {}): ItemView[] {
  const out: ItemView[] = [];
  for (const id of v.graph.objects('item')) {
    const r = v.graph.resolve('item', id);
    if (r.deleted || !r.current?.data) continue;
    const data = r.current.data as ItemData;
    if (!!data.trashedAt !== !!opts.trash) continue;
    out.push({ vaultId: v.id, id, data, conflict: r.conflict, heads: r.heads });
  }
  return out;
}

export function getItem(v: Vault, id: string): ItemView | undefined {
  const r = v.graph.resolve('item', id);
  if (r.deleted || !r.current?.data) return undefined;
  return { vaultId: v.id, id, data: r.current.data as ItemData, conflict: r.conflict, heads: r.heads };
}

export function newItem(type: ItemType, title = ''): ItemData {
  const now = Date.now();
  return {
    type,
    title,
    fields: ITEM_TEMPLATES[type].fields.map((f) => ({ ...f })),
    createdAt: now,
    updatedAt: now,
  };
}

/** 保存整条目。parents 默认取当前所有头，因此保存也就解决了冲突。 */
export async function saveItem(v: Vault, id: string | undefined, data: ItemData): Promise<string> {
  const objId = id ?? randomId();
  const prev = id ? (v.graph.resolve('item', id).current?.data as ItemData | undefined) : undefined;
  const now = Date.now();
  const next: ItemData = { ...data, updatedAt: now };
  // 换密钥时旧值要留得住：新 Key 没生效之前可能还要用旧的
  const replaced: NonNullable<ItemData['passwordHistory']> = [];
  if (prev?.password && prev.password !== data.password) replaced.push({ value: prev.password, changedAt: now });
  for (const f of prev?.fields ?? []) {
    if (!f.secret || !f.value) continue;
    if (data.fields?.find((x) => x.name === f.name)?.value !== f.value) {
      replaced.push({ value: f.value, changedAt: now, field: f.name });
    }
  }
  if (replaced.length) next.passwordHistory = [...replaced, ...(prev?.passwordHistory ?? [])].slice(0, 10);
  if (!prev || replaced.length) next.passwordChangedAt = now;
  await v.commit('item', objId, next as Record<string, unknown>);
  return objId;
}

export async function trashItem(v: Vault, id: string): Promise<void> {
  const it = getItem(v, id);
  if (!it) throw new MixiaError('item_not_found');
  await v.commit('item', id, { ...it.data, trashedAt: Date.now() });
}

export async function restoreItem(v: Vault, id: string): Promise<void> {
  const it = getItem(v, id);
  if (!it) throw new MixiaError('item_not_found');
  const { trashedAt: _drop, ...rest } = it.data;
  await v.commit('item', id, rest as Record<string, unknown>);
}

/** 永久删除：写墓碑版本，防止离线的旧设备把它传回来。 */
export async function purgeItem(v: Vault, id: string): Promise<void> {
  await v.commit('item', id, null, { del: true });
}

/** 恢复到某个历史版本：作为新版本写入，历史本身不被改写。 */
export async function restoreVersion(v: Vault, id: string, versionId: string): Promise<void> {
  const ver = v.graph.versions.get(versionId);
  if (!ver || ver.obj !== id || !ver.data) throw new MixiaError('version_not_found');
  await saveItem(v, id, ver.data as ItemData);
}

export interface FolderData {
  name: string;
  parent: string | null;
  [unknownField: string]: unknown;
}

export interface FolderNode {
  id: string;
  name: string;
  parent: string | null;
  children: FolderNode[];
  depth: number;
  path: string[];
}

/**
 * 构建文件夹树。两台设备离线各自移动文件夹可能合成环；
 * 这里确定性地把环上 id 最小的节点提到根，保证所有设备看到同一棵树。
 */
export function folderTree(v: Vault): FolderNode[] {
  const raw = new Map<string, FolderData>();
  for (const id of v.graph.objects('folder')) {
    const r = v.graph.resolve('folder', id);
    if (!r.deleted && r.current?.data) raw.set(id, r.current.data as FolderData);
  }
  const parentOf = new Map<string, string | null>();
  for (const [id, f] of raw) parentOf.set(id, f.parent && raw.has(f.parent) ? f.parent : null);

  for (const start of [...raw.keys()].sort()) {
    const seen = new Set<string>();
    let cur: string | null | undefined = start;
    while (cur) {
      if (seen.has(cur)) {
        const cycle: string[] = [];
        let c: string | null | undefined = cur;
        do {
          cycle.push(c!);
          c = parentOf.get(c!);
        } while (c && c !== cur);
        parentOf.set(cycle.sort()[0]!, null);
        break;
      }
      seen.add(cur);
      cur = parentOf.get(cur);
    }
  }

  const nodes = new Map<string, FolderNode>();
  for (const [id, f] of raw) {
    nodes.set(id, { id, name: f.name, parent: parentOf.get(id) ?? null, children: [], depth: 0, path: [] });
  }
  const roots: FolderNode[] = [];
  for (const n of nodes.values()) {
    const p = n.parent ? nodes.get(n.parent) : undefined;
    if (p) p.children.push(n);
    else roots.push(n);
  }
  const walk = (n: FolderNode, depth: number, path: string[]) => {
    n.depth = depth;
    n.path = [...path, n.name];
    n.children.sort((a, b) => a.name.localeCompare(b.name, 'zh-CN'));
    for (const c of n.children) walk(c, depth + 1, n.path);
  };
  roots.sort((a, b) => a.name.localeCompare(b.name, 'zh-CN'));
  for (const r of roots) walk(r, 0, []);
  return roots;
}

export function flattenFolders(tree: FolderNode[]): FolderNode[] {
  const out: FolderNode[] = [];
  const go = (ns: FolderNode[]) => {
    for (const n of ns) {
      out.push(n);
      go(n.children);
    }
  };
  go(tree);
  return out;
}

export async function saveFolder(
  v: Vault,
  id: string | undefined,
  name: string,
  parent: string | null,
): Promise<string> {
  const objId = id ?? randomId();
  if (id && parent) {
    let cur: string | null = parent;
    const flat = new Map(flattenFolders(folderTree(v)).map((n) => [n.id, n]));
    while (cur) {
      if (cur === id) throw new MixiaError('folder_cycle');
      cur = flat.get(cur)?.parent ?? null;
    }
  }
  const prev = id ? (v.graph.resolve('folder', id).current?.data as FolderData | undefined) : undefined;
  await v.commit('folder', objId, { ...prev, name, parent });
  return objId;
}

/** 删文件夹不删条目：子文件夹和条目上移到父级，一次事务完成。 */
export async function deleteFolder(v: Vault, id: string): Promise<void> {
  const r = v.graph.resolve('folder', id);
  if (r.deleted || !r.current?.data) throw new MixiaError('folder_not_found');
  const parent = (r.current.data as FolderData).parent;
  const now = Date.now();
  const mk = (kind: 'item' | 'folder', obj: string, data: Record<string, unknown> | null, del = false): Version => ({
    id: randomId(),
    parents: v.graph.headsOf(kind, obj).map((h) => h.id),
    ts: now,
    device: '',
    kind,
    obj,
    del,
    data,
  });
  const batch: Version[] = [];
  for (const it of [...listItems(v), ...listItems(v, { trash: true })]) {
    if (it.data.folder === id) batch.push(mk('item', it.id, { ...it.data, folder: parent }));
  }
  for (const fid of v.graph.objects('folder')) {
    const fr = v.graph.resolve('folder', fid);
    if (!fr.deleted && (fr.current?.data as FolderData)?.parent === id) {
      batch.push(mk('folder', fid, { ...(fr.current!.data as FolderData), parent }));
    }
  }
  batch.push(mk('folder', id, null, true));
  await v.commitAuthored(batch);
}

export interface ViewData {
  name: string;
  query: string;
}

export function listViews(v: Vault): { id: string; data: ViewData }[] {
  const out: { id: string; data: ViewData }[] = [];
  for (const id of v.graph.objects('view')) {
    const r = v.graph.resolve('view', id);
    if (!r.deleted && r.current?.data) out.push({ id, data: r.current.data as unknown as ViewData });
  }
  return out.sort((a, b) => a.data.name.localeCompare(b.data.name, 'zh-CN'));
}

export async function saveView(v: Vault, id: string | undefined, data: ViewData): Promise<string> {
  const objId = id ?? randomId();
  await v.commit('view', objId, data as unknown as Record<string, unknown>);
  return objId;
}

export async function deleteView(v: Vault, id: string): Promise<void> {
  await v.commit('view', id, null, { del: true });
}

const META_OBJ = 'vault';

export function vaultName(v: Vault): string {
  const r = v.graph.resolve('meta', META_OBJ);
  return ((r.current?.data as { name?: string } | undefined)?.name as string) ?? '未命名保险库';
}

export async function setVaultName(v: Vault, name: string): Promise<void> {
  await v.commit('meta', META_OBJ, { name });
}

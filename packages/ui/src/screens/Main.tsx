import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ArchiveRestore,
  Cloud,
  FolderPlus,
  Lock as LockIcon,
  Menu,
  MonitorSmartphone,
  Plus,
  RefreshCw,
  Search,
  Settings as SettingsIcon,
  ShieldCheck,
  Star,
  TriangleAlert,
  Trash2,
  Unlock,
  Wand2,
  Layers,
  ChevronRight,
  KeyRound,
  Folder,
  Tag,
  Bookmark,
  LockKeyhole,
  type LucideIcon,
} from 'lucide-react';
import {
  ENV_LABELS,
  ITEM_TEMPLATES,
  KEY_TYPES,
  flattenFolders,
  folderTree,
  isKeyItem,
  keyHint,
  listViews,
  needsAttention,
  saveFolder,
  saveView,
  search,
  deleteFolder,
  type FolderNode,
  type ItemType,
  type ItemView,
  type Policy,
  type VaultSummary,
} from '@mixia/core';
import { BlackHoleMark, useStarfield } from '../cosmos';
import { POLICY_HINT, POLICY_LABEL, Seal } from '../seal';
import { ALARM_TEXT, timeAgo, useApp, useAsync } from '../state';
import { Confirm, Dialog, PasswordInput } from './Common';
import { ItemDetail, ItemEditor } from './Item';
import { GeneratorPage } from './Generator';
import { DevicesPage } from './Devices';
import { BackupPage } from './Backup';
import { SecurityPage } from './Security';
import { SettingsPage } from './Settings';
import { AutofillPicker } from './Autofill';
import { KeyBadge, KeysOverview } from './Keys';

export type Filter =
  | { k: 'all' }
  | { k: 'fav' }
  | { k: 'conflict' }
  | { k: 'keys'; attention?: boolean }
  | { k: 'trash' }
  | { k: 'vault'; vaultId: string }
  | { k: 'folder'; vaultId: string; folderId: string }
  | { k: 'tag'; tag: string }
  | { k: 'view'; vaultId: string; query: string; name: string };

export type Route =
  | { p: 'none' }
  | { p: 'item'; vaultId: string; id: string }
  | { p: 'new'; vaultId: string; type: ItemType; folder: string | null }
  | { p: 'edit'; vaultId: string; id: string }
  | { p: 'devices' | 'backup' | 'security' | 'settings' | 'generator' | 'keys' };

function collectIds(n: FolderNode, out: Set<string> = new Set()): Set<string> {
  out.add(n.id);
  n.children.forEach((c) => collectIds(c, out));
  return out;
}

export function Main({ entering = false }: { entering?: boolean }) {
  useStarfield();
  // 入场方式在挂载时定下就不再变：中途换类名会让动画重放一次，画面闪一下
  const [arrival] = useState(entering ? 'entering' : '');
  const { m, bridge } = useApp();
  const [filter, setFilter] = useState<Filter>({ k: 'all' });
  const [route, setRoute] = useState<Route>({ p: 'none' });
  const [query, setQuery] = useState('');
  const [navOpen, setNavOpen] = useState(false);
  const [unlockId, setUnlockId] = useState<string | null>(null);
  const [newMenu, setNewMenu] = useState(false);
  const [fill, setFill] = useState<{ target: string; kind: 'web' | 'app' } | null>(null);

  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        document.getElementById('global-search')?.focus();
      }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'l') {
        e.preventDefault();
        m.lock();
      }
    };
    window.addEventListener('keydown', k);
    return () => window.removeEventListener('keydown', k);
  }, [m]);

  useEffect(() => {
    if (!bridge.autofill) return;
    void bridge.autofill.pending().then((r) => r && setFill(r));
    bridge.autofill.onRequest(setFill);
  }, [bridge]);

  const vaults = m.vaults();
  const items = useMemo(() => {
    const base = filter.k === 'trash' ? m.allItems({ trash: true }) : m.allItems();
    let list = base;
    if (filter.k === 'vault') list = base.filter((i) => i.vaultId === filter.vaultId);
    else if (filter.k === 'fav') list = base.filter((i) => i.data.favorite);
    else if (filter.k === 'conflict') list = base.filter((i) => i.conflict);
    else if (filter.k === 'keys') {
      list = base.filter((i) => isKeyItem(i.data) && (!filter.attention || needsAttention(i.data)));
    }
    else if (filter.k === 'tag') list = base.filter((i) => i.data.tags?.includes(filter.tag));
    else if (filter.k === 'folder') {
      const node = flattenFolders(folderTree(m.vault(filter.vaultId))).find((n) => n.id === filter.folderId);
      const ids = node ? collectIds(node) : new Set<string>();
      list = base.filter((i) => i.vaultId === filter.vaultId && i.data.folder && ids.has(i.data.folder));
    } else if (filter.k === 'view') list = search(base, filter.query, (id) => m.vaultDisplayName(id));
    if (query.trim()) list = search(list, query, (id) => m.vaultDisplayName(id));
    return [...list].sort((a, b) => a.data.title.localeCompare(b.data.title, 'zh-CN'));
    // m 内部变化时 Root 已经重新渲染，这里按渲染计算
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter, query, m, m.allItems().length, m.syncStatus.lastSyncAt, route]);

  const go = useCallback((r: Route) => {
    setRoute(r);
    setNavOpen(false);
  }, []);

  // 手机返回键：先退到列表，再收起抽屉，最后才退到后台
  const backState = useRef({ route, navOpen });
  backState.current = { route, navOpen };
  useEffect(() => {
    bridge.onBack?.(() => {
      const s = backState.current;
      if (s.navOpen) setNavOpen(false);
      else if (s.route.p !== 'none') setRoute({ p: 'none' });
      else bridge.exitApp?.();
    });
  }, [bridge]);

  const searchKeys = useCallback((q: string) => {
    setQuery(q);
    setRoute({ p: 'none' });
  }, []);

  const pick = useCallback((f: Filter) => {
    setFilter(f);
    setNavOpen(false);
    setRoute({ p: 'none' });
  }, []);

  const writable = vaults.filter((v) => !v.locked && !v.readOnly);
  const defaultVault =
    (filter.k === 'vault' || filter.k === 'folder' ? writable.find((v) => v.id === filter.vaultId) : undefined) ?? writable[0];

  const mainOpen = route.p !== 'none';
  return (
    <div className={`app ${navOpen ? 'nav-open' : ''} ${mainOpen ? 'main-open' : ''} ${arrival}`}>
      {navOpen && <div className="scrim only-mobile" style={{ display: 'block' }} onClick={() => setNavOpen(false)} />}
      <Sidebar
        filter={filter}
        route={route}
        vaults={vaults}
        onPick={pick}
        onRoute={go}
        onUnlock={setUnlockId}
      />
      <section className="pane list" aria-label="条目列表">
        <div className="list-head">
          <div className="row">
            <button className="iconbtn only-mobile" aria-label="打开导航" onClick={() => setNavOpen(true)}>
              <Menu size={20} />
            </button>
            <div className="search grow">
              <Search size={15} />
              <input
                id="global-search"
                className="input"
                placeholder="搜索标题、账号、网址…"
                value={query}
                spellCheck={false}
                onChange={(e) => setQuery(e.target.value)}
              />
            </div>
          </div>
          <div className="list-title">
            <span className="muted small truncate">{filterName(filter, m, vaults)} · {items.length} 条</span>
            <div style={{ position: 'relative' }}>
              <button className="btn" disabled={!defaultVault} onClick={() => setNewMenu((s) => !s)}>
                <Plus size={15} /> 新建
              </button>
              {newMenu && defaultVault && (
                <div className="menu" style={{ right: 0, top: 38 }} onMouseLeave={() => setNewMenu(false)}>
                  {(filter.k === 'keys' ? [...KEY_TYPES] : (Object.keys(ITEM_TEMPLATES) as ItemType[])).map((t) => (
                    <button
                      key={t}
                      onClick={() => {
                        setNewMenu(false);
                        go({
                          p: 'new',
                          vaultId: defaultVault.id,
                          type: t,
                          folder: filter.k === 'folder' ? filter.folderId : null,
                        });
                      }}
                    >
                      {ITEM_TEMPLATES[t].label}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
        <Alarm />
        {filter.k === 'keys' && (
          <div className="tagchips" style={{ padding: '8px 12px 2px' }}>
            <button className={`chip ${!filter.attention ? 'on' : ''}`} onClick={() => setFilter({ k: 'keys' })}>全部</button>
            <button className={`chip ${filter.attention ? 'on' : ''}`} onClick={() => setFilter({ k: 'keys', attention: true })}>需要处理</button>
            <button className="chip only-mobile" onClick={() => go({ p: 'keys' })}>总览</button>
          </div>
        )}
        <div className="scroll">
          {items.length === 0 ? (
            <EmptyList filter={filter} query={query} />
          ) : (
            items.map((it) => {
              const v = vaults.find((x) => x.id === it.vaultId);
              return (
                <ItemRow
                  key={`${it.vaultId}/${it.id}`}
                  it={it}
                  policy={v?.policy ?? 'cloud'}
                  on={route.p === 'item' && route.id === it.id}
                  onClick={() => go({ p: 'item', vaultId: it.vaultId, id: it.id })}
                />
              );
            })
          )}
        </div>
      </section>
      <section className="pane main" aria-label="内容">
        <div className="scroll">
          {route.p === 'none' && (filter.k === 'keys' ? <KeysOverview go={go} onQuery={searchKeys} /> : <Welcome vaults={vaults} />)}
          {route.p === 'keys' && <KeysOverview go={go} onQuery={searchKeys} />}
          {route.p === 'item' && <ItemDetail key={route.id} vaultId={route.vaultId} id={route.id} go={go} />}
          {route.p === 'new' && (
            <ItemEditor key="new" vaultId={route.vaultId} type={route.type} folder={route.folder} go={go} />
          )}
          {route.p === 'edit' && <ItemEditor key={route.id} vaultId={route.vaultId} id={route.id} go={go} />}
          {route.p === 'devices' && <DevicesPage go={go} />}
          {route.p === 'backup' && <BackupPage go={go} />}
          {route.p === 'security' && <SecurityPage go={go} />}
          {route.p === 'settings' && <SettingsPage go={go} />}
          {route.p === 'generator' && <GeneratorPage go={go} />}
        </div>
      </section>
      {unlockId && <UnlockLocal vaultId={unlockId} onClose={() => setUnlockId(null)} />}
      {fill && <AutofillPicker req={fill} onDone={() => setFill(null)} />}
    </div>
  );
}

function filterName(f: Filter, m: ReturnType<typeof useApp>['m'], vaults: VaultSummary[]): string {
  switch (f.k) {
    case 'all': return '全部条目';
    case 'fav': return '收藏';
    case 'conflict': return '有冲突';
    case 'keys': return f.attention ? '需要处理的密钥' : '密钥与 API';
    case 'trash': return '回收站';
    case 'vault': return vaults.find((v) => v.id === f.vaultId)?.name ?? '保险库';
    case 'tag': return `标签：${f.tag}`;
    case 'view': return f.name;
    case 'folder':
      return flattenFolders(folderTree(m.vault(f.vaultId))).find((n) => n.id === f.folderId)?.path.join(' / ') ?? '文件夹';
  }
}

function EmptyList({ filter, query }: { filter: Filter; query: string }) {
  if (query) return <div className="empty"><p>没有匹配“{query}”的条目</p></div>;
  if (filter.k === 'trash') return <div className="empty"><p>回收站是空的</p></div>;
  if (filter.k === 'conflict') return <div className="empty"><p>没有需要处理的冲突</p></div>;
  if (filter.k === 'keys') {
    return (
      <div className="empty">
        <p>{filter.attention ? '没有需要处理的密钥' : '这里还没有密钥'}</p>
        {!filter.attention && <p className="small">点“新建”添加，或在总览里导入项目的 .env</p>}
      </div>
    );
  }
  return (
    <div className="empty">
      <BlackHoleMark size={132} className="empty-mark" />
      <p>这里还没有条目</p>
      <p className="small">点“新建”添加，或到“备份与迁移”导入原来的密码</p>
    </div>
  );
}

function ItemRow({ it, policy, on, onClick }: { it: ItemView; policy: Policy; on: boolean; onClick: () => void }) {
  const d = it.data;
  const sub = isKeyItem(d)
    ? [d.provider, d.env && ENV_LABELS[d.env], keyHint(d)].filter(Boolean).join(' · ') || ITEM_TEMPLATES[d.type]?.label
    : d.username || (d.urls ?? [])[0] || ITEM_TEMPLATES[d.type]?.label || '';
  return (
    <button className={`row-item ${on ? 'on' : ''}`} onClick={onClick}>
      <Seal policy={policy} size={24} />
      <span className="grow">
        <span className="t truncate" style={{ display: 'block' }}>{d.title || '未命名'}</span>
        <span className="s truncate" style={{ display: 'block' }}>{sub}</span>
      </span>
      {isKeyItem(d) && <KeyBadge data={d} />}
      {it.conflict && <TriangleAlert size={15} className="conflict-dot" aria-label="有冲突" />}
      {d.favorite && <Star size={13} className="muted" fill="currentColor" aria-label="收藏" />}
    </button>
  );
}

/** 打开这些页面时，上面的筛选项退成淡色，同一时间只有一个主高亮。 */
const FOOT_PAGES: Route['p'][] = ['generator', 'devices', 'backup', 'security', 'settings'];

function Sidebar({
  filter,
  route,
  vaults,
  onPick,
  onRoute,
  onUnlock,
}: {
  filter: Filter;
  route: Route;
  vaults: VaultSummary[];
  onPick: (f: Filter) => void;
  onRoute: (r: Route) => void;
  onUnlock: (id: string) => void;
}) {
  const { m } = useApp();
  const [menuFor, setMenuFor] = useState<string | null>(null);
  const [folderDlg, setFolderDlg] = useState<{ vaultId: string; parent: string | null; id?: string; name: string } | null>(null);
  const [delFolder, setDelFolder] = useState<{ vaultId: string; id: string; name: string } | null>(null);
  const [viewDlg, setViewDlg] = useState<string | null>(null);
  const { run } = useAsync();

  const open = vaults.filter((v) => !v.locked);
  const conflicts = m.allItems().filter((i) => i.conflict).length;
  const allTags = useMemo(() => {
    const c = new Map<string, number>();
    for (const i of m.allItems()) for (const t of i.data.tags ?? []) c.set(t, (c.get(t) ?? 0) + 1);
    return [...c.entries()].sort((a, b) => b[1] - a[1]).slice(0, 24);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [m, m.allItems().length, route]);

  const vaultInFocus =
    filter.k === 'vault' || filter.k === 'folder' ? filter.vaultId : open.length === 1 ? open[0]!.id : undefined;
  const focused = vaultInFocus ? open.find((v) => v.id === vaultInFocus) : undefined;
  const tree = focused ? folderTree(m.vault(focused.id)) : [];
  const views = open.flatMap((v) => listViews(m.vault(v.id)).map((x) => ({ ...x, vaultId: v.id })));

  const NavBtn = ({ icon: Icon, label, on, onClick, count }: { icon: LucideIcon; label: string; on: boolean; onClick: () => void; count?: number }) => (
    <button className={`nav-item ${on ? 'on' : ''}`} onClick={onClick}>
      <Icon size={16} />
      <span>{label}</span>
      {count !== undefined && <span className="count">{count}</span>}
    </button>
  );

  const renderFolder = (n: FolderNode) => (
    <div key={n.id}>
      <button
        className={`nav-item ${filter.k === 'folder' && filter.folderId === n.id ? 'on' : ''}`}
        style={{ paddingLeft: 8 + n.depth * 14 }}
        onClick={() => onPick({ k: 'folder', vaultId: focused!.id, folderId: n.id })}
        onContextMenu={(e) => {
          e.preventDefault();
          setMenuFor(n.id);
        }}
      >
        {n.children.length ? <ChevronRight size={13} /> : <Folder size={14} />}
        <span className="truncate grow">{n.name}</span>
      </button>
      {menuFor === n.id && !focused!.readOnly && (
        <div className="menu" style={{ left: 40 }} onMouseLeave={() => setMenuFor(null)}>
          <button onClick={() => { setMenuFor(null); setFolderDlg({ vaultId: focused!.id, parent: n.id, name: '' }); }}>新建子文件夹</button>
          <button onClick={() => { setMenuFor(null); setFolderDlg({ vaultId: focused!.id, parent: n.parent, id: n.id, name: n.name }); }}>重命名</button>
          <button onClick={() => { setMenuFor(null); setDelFolder({ vaultId: focused!.id, id: n.id, name: n.name }); }}>删除</button>
        </div>
      )}
      {n.children.map(renderFolder)}
    </div>
  );

  return (
    <nav className={`pane nav ${FOOT_PAGES.includes(route.p) ? 'page-open' : ''}`} aria-label="导航">
      <div className="brand">
        <BlackHoleMark size={30} />
        <span className="name grow">密匣</span>
        <SyncIndicator />
        <button className="iconbtn" title="立即锁定 (Ctrl+L)" aria-label="立即锁定" onClick={() => m.lock()}>
          <LockKeyhole size={16} />
        </button>
      </div>
      <div className="scroll">
        <div className="nav-group">
          <NavBtn icon={Layers} label="全部条目" on={filter.k === 'all'} onClick={() => onPick({ k: 'all' })} count={m.allItems().length} />
          <NavBtn icon={Star} label="收藏" on={filter.k === 'fav'} onClick={() => onPick({ k: 'fav' })} />
          <NavBtn
            icon={KeyRound}
            label="密钥与 API"
            on={filter.k === 'keys'}
            onClick={() => onPick({ k: 'keys' })}
            count={m.allItems().filter((i) => isKeyItem(i.data)).length}
          />
          {conflicts > 0 && (
            <NavBtn icon={TriangleAlert} label="有冲突" on={filter.k === 'conflict'} onClick={() => onPick({ k: 'conflict' })} count={conflicts} />
          )}
          <NavBtn icon={Trash2} label="回收站" on={filter.k === 'trash'} onClick={() => onPick({ k: 'trash' })} />
        </div>
        <div className="nav-group">
          <div className="nav-title"><span>保险库</span></div>
          {vaults.map((v) => (
            <button
              key={v.id}
              className={`nav-item vault ${filter.k === 'vault' && filter.vaultId === v.id ? 'on' : ''}`}
              title={`${POLICY_LABEL[v.policy]}：${POLICY_HINT[v.policy]}`}
              onClick={() => (v.locked ? onUnlock(v.id) : onPick({ k: 'vault', vaultId: v.id }))}
            >
              <Seal policy={v.policy} size={20} />
              <span className="label truncate">{v.name}</span>
              {v.locked ? <LockIcon size={13} className="muted" aria-label="已锁定" /> : <span className="count">{v.count}</span>}
              {!v.locked && v.policy === 'local' && <Unlock size={12} className="muted" aria-label="已解锁" />}
            </button>
          ))}
        </div>
        {focused && (
          <div className="nav-group">
            <div className="nav-title">
              <span className="truncate">{focused.name} 的文件夹</span>
              {!focused.readOnly && (
                <button className="iconbtn" style={{ width: 24, height: 24 }} aria-label="新建文件夹" onClick={() => setFolderDlg({ vaultId: focused.id, parent: null, name: '' })}>
                  <FolderPlus size={14} />
                </button>
              )}
            </div>
            {tree.map(renderFolder)}
            {tree.length === 0 && <p className="muted small" style={{ padding: '0 8px' }}>按项目、系统、环境分层</p>}
          </div>
        )}
        {views.length > 0 && (
          <div className="nav-group">
            <div className="nav-title"><span>分组</span></div>
            {views.map((v) => (
              <button
                key={v.id}
                className={`nav-item ${filter.k === 'view' && filter.name === v.data.name ? 'on' : ''}`}
                onClick={() => onPick({ k: 'view', vaultId: v.vaultId, query: v.data.query, name: v.data.name })}
              >
                <Bookmark size={14} /> <span className="truncate">{v.data.name}</span>
              </button>
            ))}
          </div>
        )}
        {allTags.length > 0 && (
          <div className="nav-group">
            <div className="nav-title"><span>标签</span></div>
            <div className="tagchips">
              {allTags.map(([t]) => (
                <button key={t} className={`chip ${filter.k === 'tag' && filter.tag === t ? 'on' : ''}`} onClick={() => onPick({ k: 'tag', tag: t })}>
                  <Tag size={11} /> {t}
                </button>
              ))}
            </div>
          </div>
        )}
        <div className="nav-group">
          <button className="nav-item" onClick={() => setViewDlg(open[0]?.id ?? null)} disabled={!open.length}>
            <Bookmark size={14} /> <span className="muted">新建分组…</span>
          </button>
        </div>
      </div>
      <div className="nav-foot">
        <NavBtn icon={Wand2} label="生成密码" on={route.p === 'generator'} onClick={() => onRoute({ p: 'generator' })} />
        <NavBtn icon={MonitorSmartphone} label="设备" on={route.p === 'devices'} onClick={() => onRoute({ p: 'devices' })} />
        <NavBtn icon={ArchiveRestore} label="备份与迁移" on={route.p === 'backup'} onClick={() => onRoute({ p: 'backup' })} />
        <NavBtn icon={ShieldCheck} label="安全检查" on={route.p === 'security'} onClick={() => onRoute({ p: 'security' })} />
        <NavBtn icon={SettingsIcon} label="设置" on={route.p === 'settings'} onClick={() => onRoute({ p: 'settings' })} />
      </div>

      {folderDlg && (
        <Dialog
          title={folderDlg.id ? '重命名文件夹' : '新建文件夹'}
          onClose={() => setFolderDlg(null)}
          footer={
            <>
              <button className="btn" onClick={() => setFolderDlg(null)}>取消</button>
              <button
                className="btn primary"
                disabled={!folderDlg.name.trim()}
                onClick={() =>
                  void run(async () => {
                    await saveFolder(m.vault(folderDlg.vaultId), folderDlg.id, folderDlg.name.trim(), folderDlg.parent);
                    setFolderDlg(null);
                  })
                }
              >
                保存
              </button>
            </>
          }
        >
          <input className="input" autoFocus value={folderDlg.name} placeholder="例如：项目A" onChange={(e) => setFolderDlg({ ...folderDlg, name: e.target.value })} />
        </Dialog>
      )}
      {delFolder && (
        <Confirm
          title={`删除“${delFolder.name}”？`}
          body="里面的条目和子文件夹会上移一层，不会被删除。"
          action="删除文件夹"
          danger
          onCancel={() => setDelFolder(null)}
          onConfirm={() =>
            void run(async () => {
              await deleteFolder(m.vault(delFolder.vaultId), delFolder.id);
              setDelFolder(null);
              onPick({ k: 'vault', vaultId: delFolder.vaultId });
            })
          }
        />
      )}
      {viewDlg && <NewView vaultId={viewDlg} onClose={() => setViewDlg(null)} />}
    </nav>
  );
}

function NewView({ vaultId, onClose }: { vaultId: string; onClose: () => void }) {
  const { m } = useApp();
  const { run } = useAsync();
  const [name, setName] = useState('');
  const [query, setQuery] = useState('');
  return (
    <Dialog
      title="新建分组"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>取消</button>
          <button
            className="btn primary"
            disabled={!name.trim() || !query.trim()}
            onClick={() =>
              void run(async () => {
                await saveView(m.vault(vaultId), undefined, { name: name.trim(), query: query.trim() });
                onClose();
              })
            }
          >
            保存
          </button>
        </>
      }
    >
      <div className="stack">
        <p className="muted small">分组是保存的筛选条件，可以跨文件夹、跨库。</p>
        <div className="field">
          <label htmlFor="vn">名称</label>
          <input id="vn" className="input" value={name} autoFocus placeholder="例如：生产环境服务器" onChange={(e) => setName(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="vq">条件</label>
          <input id="vq" className="input" value={query} spellCheck={false} placeholder="tag:客户A type:server env:production" onChange={(e) => setQuery(e.target.value)} />
          <span className="muted small">可用 tag: type: env: vault: is:fav 和普通关键词组合。</span>
        </div>
      </div>
    </Dialog>
  );
}

function SyncIndicator() {
  const { m } = useApp();
  const s = m.syncStatus;
  const label = {
    idle: `已同步 · ${timeAgo(s.lastSyncAt)}`,
    syncing: '正在同步',
    offline: '离线：修改保存在本机，联网后同步',
    error: `同步出错（${s.error ?? ''}）`,
    alarm: '已停止同步：完整性校验未通过',
    none: '未同步',
  }[s.state];
  return (
    <button className="iconbtn" title={label} aria-label={label} onClick={() => void m.syncNow()}>
      {s.state === 'syncing' ? <RefreshCw size={15} /> : s.state === 'offline' ? <Cloud size={15} /> : <span className={`sync-dot ${s.state}`} />}
    </button>
  );
}

function Alarm() {
  const { m } = useApp();
  const { run } = useAsync();
  const a = m.syncStatus.alarm;
  if (m.revoked) {
    return (
      <div className="banner danger" style={{ margin: 10 }} role="alert">
        <TriangleAlert size={18} />
        <p className="grow">
          <strong>这台设备已被撤销，</strong>云库已清除。重要本地库还能打开：请到“备份与迁移”导出后，再到“设置”擦除这台设备。
        </p>
      </div>
    );
  }
  if (!a) return null;
  return (
    <div className="banner danger" style={{ margin: 10, flexWrap: 'wrap' }} role="alert">
      <TriangleAlert size={18} />
      <div className="grow">
        <strong>已停止同步，本机数据没有被改动。</strong>
        <p>{ALARM_TEXT[a.code] ?? `完整性校验失败（${a.code}）。`} 这可能表示服务器被篡改或恢复过旧备份。确认原因前不要在这台设备上批准新设备。</p>
      </div>
      <button className="btn" onClick={() => void m.acknowledgeAlarm().then(() => m.syncNow())}>已确认，重试</button>
      {a.vaultId && m.isAdmin && (
        <button
          className="btn"
          title="服务器上这个库的日志作废，用这台设备的内容换钥重建"
          onClick={() => void run(() => m.rebuildVault(a.vaultId!), '已用本机内容重建')}
        >
          用本机内容重建
        </button>
      )}
    </div>
  );
}

function Welcome({ vaults }: { vaults: VaultSummary[] }) {
  const local = vaults.filter((v) => v.policy === 'local');
  return (
    <div className="empty welcome">
      <div className="welcome-hole">
        <BlackHoleMark size={220} />
      </div>
      <p>选一个条目，或按 <span className="nw">Ctrl + K</span> 搜索</p>
      {local.length === 0 && <p className="small">重要账号建议放进本地库：到“备份与迁移”创建</p>}
    </div>
  );
}

function UnlockLocal({ vaultId, onClose }: { vaultId: string; onClose: () => void }) {
  const { m } = useApp();
  const { run, busy } = useAsync();
  const [pass, setPass] = useState('');
  const go = () =>
    void run(async () => {
      await new Promise((r) => setTimeout(r, 30));
      await m.unlockLocalVault(vaultId, pass);
      onClose();
    });
  return (
    <Dialog
      title={`解锁“${m.vaultDisplayName(vaultId)}”`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>取消</button>
          <button className="btn primary" disabled={busy || !pass} onClick={go}>{busy ? '正在解锁…' : '解锁'}</button>
        </>
      }
    >
      <p className="muted small" style={{ marginBottom: 10 }}>重要本地库有自己的口令。空闲 {m.prefs.localLockMinutes} 分钟后自动重新锁定。</p>
      <PasswordInput value={pass} onChange={setPass} autoFocus onEnter={go} />
    </Dialog>
  );
}


import { useEffect, useMemo, useState } from 'react';
import {
  ArrowLeft,
  Copy,
  Dices,
  ExternalLink,
  Eye,
  EyeOff,
  FolderInput,
  History,
  Paperclip,
  Pencil,
  Plus,
  RotateCcw,
  Star,
  Trash2,
  TriangleAlert,
  X,
} from 'lucide-react';
import {
  DEFAULT_GEN,
  detectKey,
  isKeyItem,
  ENVIRONMENTS,
  ENV_LABELS,
  ITEM_TEMPLATES,
  flattenFolders,
  folderTree,
  generatePassword,
  getItem,
  listItems,
  newItem,
  parseTotp,
  purgeItem,
  restoreItem,
  restoreVersion,
  saveItem,
  strength,
  totpCode,
  trashItem,
  type AttachmentRef,
  type Field,
  type ItemData,
  type ItemType,
  type Policy,
  type Version,
  MixiaError,
} from '@mixia/core';
import { POLICY_HINT, POLICY_LABEL, Seal } from '../seal';
import { editing, errorText, fullTime, timeAgo, useApp, useAsync } from '../state';
import { Confirm, Dialog, PasswordInput, SecretText, StrengthMeter } from './Common';
import { EnvCopy, KeyDetail, KeyEditorFields } from './Keys';
import type { Route } from './Main';

function useCopy() {
  const { bridge, m, toast } = useApp();
  return (text: string, label: string) => {
    void bridge.copy(text, m.prefs.clipboardSeconds);
    toast(`${label}已复制，${m.prefs.clipboardSeconds} 秒后清除`);
  };
}

function Row({ k, value, secret, mono, onCopy, children }: { k: string; value: string; secret?: boolean; mono?: boolean; onCopy?: () => void; children?: React.ReactNode }) {
  const [show, setShow] = useState(false);
  return (
    <div className="frow">
      <div className="grow">
        <div className="k">{k}</div>
        <div className={`v ${mono ? 'mono' : ''}`}>
          {secret ? (show ? <SecretText text={value} /> : <span className="secret muted">••••••••••••</span>) : value}
        </div>
      </div>
      {children}
      {secret && (
        <button className="iconbtn" aria-label={show ? '隐藏' : '显示'} onClick={() => setShow((s) => !s)}>
          {show ? <EyeOff size={16} /> : <Eye size={16} />}
        </button>
      )}
      {onCopy && (
        <button className="iconbtn" aria-label={`复制${k}`} onClick={onCopy}>
          <Copy size={16} />
        </button>
      )}
    </div>
  );
}

function TotpRow({ secret }: { secret: string }) {
  const copy = useCopy();
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, []);
  const cfg = useMemo(() => {
    try {
      return parseTotp(secret);
    } catch {
      return null;
    }
  }, [secret]);
  if (!cfg) return <Row k="两步验证" value="密钥格式无法识别" />;
  const { code, remaining } = totpCode(cfg, now);
  const shown = `${code.slice(0, code.length / 2)} ${code.slice(code.length / 2)}`;
  return (
    <div className="frow">
      <div className="grow">
        <div className="k">两步验证码</div>
        <div className="totp">{shown}</div>
      </div>
      <span className="muted small mono" aria-label={`${remaining} 秒后刷新`}>{remaining}s</span>
      <button className="iconbtn" aria-label="复制验证码" onClick={() => copy(code, '验证码')}><Copy size={16} /></button>
    </div>
  );
}

export function ItemDetail({ vaultId, id, go }: { vaultId: string; id: string; go: (r: Route) => void }) {
  const { m, bridge, toast } = useApp();
  const { run } = useAsync();
  const copy = useCopy();
  const [ask, setAsk] = useState<'purge' | 'move' | null>(null);
  const [hist, setHist] = useState(false);

  let vault;
  try {
    vault = m.vault(vaultId);
  } catch {
    return <div className="empty"><p>这个库已经锁定</p></div>;
  }
  const it = getItem(vault, id);
  if (!it) return <div className="empty"><p>这个条目已被删除</p></div>;
  const d = it.data;
  const name = m.vaultDisplayName(vaultId);
  const folder = d.folder ? flattenFolders(folderTree(vault)).find((f) => f.id === d.folder) : undefined;
  const ro = vault.readOnly;

  const attach = (a: AttachmentRef) =>
    void run(async () => {
      const fetchRemote = vault.policy === 'cloud' && m.api ? (bid: string) => m.api!.getBlob(vault, bid) : undefined;
      const bytes = await vault.readAttachment(a, fetchRemote);
      await bridge.saveFile(a.name, bytes);
    });

  return (
    <article className="detail">
      <button className="iconbtn only-mobile" aria-label="返回列表" onClick={() => go({ p: 'none' })} style={{ marginBottom: 6 }}>
        <ArrowLeft size={20} />
      </button>
      {d.cloudExposed && (
        <div className="banner">
          <TriangleAlert size={17} />
          <p>这条密码曾存放在云库。移回本地不能抹掉服务器和其他设备的历史副本，要让它“从未上云”，请到原系统改一次密码。</p>
        </div>
      )}
      {it.conflict && <ConflictBanner vaultId={vaultId} id={id} heads={it.heads} />}
      <header className="detail-head">
        <Seal policy={vault.policy} size={44} />
        <div className="grow">
          <h1 className="selectable">{d.title || '未命名'}</h1>
          <div className="detail-sub">
            <span>{name}</span>
            {folder && <span>· {folder.path.join(' / ')}</span>}
            <span>· {ITEM_TEMPLATES[d.type]?.label}</span>
            {d.env && <span className={`chip ${d.env === 'production' ? 'env-production' : ''}`} style={{ height: 20, cursor: 'default' }}>{ENV_LABELS[d.env] ?? d.env}</span>}
          </div>
        </div>
        {!ro && !d.trashedAt && (
          <button
            className="iconbtn"
            aria-label={d.favorite ? '取消收藏' : '收藏'}
            onClick={() => void run(() => saveItem(vault, id, { ...d, favorite: !d.favorite }))}
          >
            <Star size={17} fill={d.favorite ? 'currentColor' : 'none'} />
          </button>
        )}
      </header>

      <div className="card">
        {d.username && <Row k="账号" value={d.username} onCopy={() => copy(d.username!, '账号')} />}
        {d.password && <Row k="密码" value={d.password} secret onCopy={() => copy(d.password!, '密码')} />}
        {d.totp && <TotpRow secret={d.totp} />}
        {(d.urls ?? []).map((u, i) => (
          <Row key={i} k="网址" value={u} onCopy={() => copy(u, '网址')}>
            <button className="iconbtn" aria-label="打开网址" onClick={() => bridge.openExternal(u.includes('://') ? u : `https://${u}`)}>
              <ExternalLink size={16} />
            </button>
          </Row>
        ))}
        {(d.fields ?? []).filter((f) => f.value).map((f, i) => (
          <Row key={i} k={f.name} value={f.value} secret={!!f.secret} mono={!!f.secret} onCopy={() => copy(f.value, f.name)} />
        ))}
      </div>

      {isKeyItem(d) && <KeyDetail data={d} policy={vault.policy} />}

      {d.notes && (
        <div className="section">
          <div className="section-title">备注</div>
          <div className="card"><div className="selectable" style={{ padding: '10px 14px', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{d.notes}</div></div>
        </div>
      )}

      {!!d.attachments?.length && (
        <div className="section">
          <div className="section-title">附件</div>
          <div className="card">
            {d.attachments.map((a) => (
              <div className="frow" key={a.id}>
                <Paperclip size={15} className="muted" />
                <div className="grow truncate">{a.name}</div>
                <span className="muted small">{(a.size / 1024).toFixed(0)} KB</span>
                <button className="btn" onClick={() => attach(a)}>保存到…</button>
              </div>
            ))}
          </div>
          <p className="muted small" style={{ marginTop: 4 }}>保存后的文件在密匣之外，不再受保护。</p>
        </div>
      )}

      {!!d.tags?.length && (
        <div className="section">
          <div className="section-title">标签</div>
          <div className="row" style={{ flexWrap: 'wrap' }}>
            {d.tags.map((t) => <span key={t} className="chip" style={{ cursor: 'default' }}>{t}</span>)}
          </div>
        </div>
      )}

      <p className="muted small section">
        修改于 {timeAgo(d.updatedAt)}
        {d.passwordChangedAt ? ` · 密码更新于 ${timeAgo(d.passwordChangedAt)}` : ''}
      </p>

      <div className="actions section">
        {isKeyItem(d) && !d.trashedAt && <EnvCopy data={d} />}
        {d.trashedAt ? (
          <>
            <button className="btn" onClick={() => void run(() => restoreItem(vault, id), '已恢复')}><RotateCcw size={15} /> 恢复</button>
            <button className="btn danger" onClick={() => setAsk('purge')}><Trash2 size={15} /> 永久删除</button>
          </>
        ) : (
          !ro && (
            <>
              <button className="btn primary" onClick={() => go({ p: 'edit', vaultId, id })}><Pencil size={15} /> 编辑</button>
              <button className="btn" onClick={() => setAsk('move')}><FolderInput size={15} /> 移到其他库</button>
              <button className="btn" onClick={() => setHist(true)}><History size={15} /> 历史</button>
              <button
                className="btn danger"
                onClick={() =>
                  void run(async () => {
                    await trashItem(vault, id);
                    go({ p: 'none' });
                    toast('已移到回收站');
                  })
                }
              >
                <Trash2 size={15} /> 删除
              </button>
            </>
          )
        )}
      </div>

      {ask === 'purge' && (
        <Confirm
          title="永久删除这个条目？"
          body="所有设备上都会删除，历史版本也不再保留。"
          action="永久删除"
          danger
          onCancel={() => setAsk(null)}
          onConfirm={() =>
            void run(async () => {
              await purgeItem(vault, id);
              setAsk(null);
              go({ p: 'none' });
            })
          }
        />
      )}
      {ask === 'move' && <MoveDialog vaultId={vaultId} id={id} go={go} onClose={() => setAsk(null)} />}
      {hist && <HistoryDialog vaultId={vaultId} id={id} onClose={() => setHist(false)} />}
    </article>
  );
}

function ConflictBanner({ vaultId, id, heads }: { vaultId: string; id: string; heads: Version[] }) {
  const { m } = useApp();
  const { run } = useAsync();
  const v = m.vault(vaultId);
  const devices = m.ledger.devices;
  const name = (h: Version) => devices.get(h.device)?.name ?? '未知设备';
  return (
    <div className="banner">
      <TriangleAlert size={17} />
      <div className="grow stack" style={{ gap: 8 }}>
        <p><strong>两台设备同时改了这条记录。</strong>两个版本都保留着，请选一个继续用。</p>
        {heads.map((h) => {
          const d = h.data as ItemData | null;
          return (
            <div className="row" key={h.id} style={{ flexWrap: 'wrap' }}>
              <div className="grow small">
                {h.del ? '已删除' : `${d?.title ?? ''} · ${d?.username ?? '无账号'}`}
                <span className="muted"> — {name(h)}，{fullTime(h.ts)}</span>
              </div>
              <button
                className="btn"
                onClick={() =>
                  void run(async () => {
                    if (h.del) await purgeItem(v, id);
                    else await saveItem(v, id, d!);
                  }, '冲突已解决')
                }
              >
                用这个版本
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function MoveDialog({ vaultId, id, go, onClose }: { vaultId: string; id: string; go: (r: Route) => void; onClose: () => void }) {
  const { m, toast } = useApp();
  const src = m.vault(vaultId);
  const targets = m.vaults().filter((v) => v.id !== vaultId && !v.locked && !v.readOnly);
  const [to, setTo] = useState(targets[0]?.id ?? '');
  const [confirmed, setConfirmed] = useState(false);
  const dst = targets.find((t) => t.id === to);
  const upload = src.policy !== 'cloud' && dst?.policy === 'cloud';
  const fromCloud = src.policy === 'cloud' && dst?.policy !== 'cloud';
  return (
    <Dialog
      title="移到其他库"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>取消</button>
          <button
            className="btn primary"
            disabled={!dst || (upload && !confirmed)}
            onClick={async () => {
              try {
                const nid = await m.moveItem(vaultId, id, to, { confirmUpload: confirmed });
                toast('已移动');
                onClose();
                go({ p: 'item', vaultId: to, id: nid });
              } catch (e) {
                toast(errorText(e), 'err');
              }
            }}
          >
            移动
          </button>
        </>
      }
    >
      <div className="stack">
        {targets.length === 0 && <p className="muted">没有其他已解锁的库。</p>}
        {targets.map((t) => (
          <button key={t.id} className={`choice ${t.id === to ? 'on' : ''}`} onClick={() => setTo(t.id)}>
            <Seal policy={t.policy} size={26} />
            <span>
              <span className="t">{t.name}</span>
              <br />
              <span className="muted small">{POLICY_LABEL[t.policy as Policy]}：{POLICY_HINT[t.policy as Policy]}</span>
            </span>
          </button>
        ))}
        {upload && (
          <label className="row small">
            <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
            我确认要把这条内容的密文上传到云端
          </label>
        )}
        {fromCloud && <p className="muted small">移动后这条记录会标记“曾进入云端”。历史副本无法收回。</p>}
      </div>
    </Dialog>
  );
}

function HistoryDialog({ vaultId, id, onClose }: { vaultId: string; id: string; onClose: () => void }) {
  const { m } = useApp();
  const { run } = useAsync();
  const v = m.vault(vaultId);
  const list = v.graph.history('item', id).filter((x) => x.data);
  const d = getItem(v, id)?.data;
  return (
    <Dialog title="历史版本" onClose={onClose} footer={<button className="btn" onClick={onClose}>关闭</button>}>
      <div className="stack" style={{ gap: 0 }}>
        {list.map((h, i) => (
          <div className="row" key={h.id} style={{ padding: '6px 0', borderBottom: '1px solid var(--line)' }}>
            <div className="grow small">
              {fullTime(h.ts)}
              <span className="muted"> · {m.ledger.devices.get(h.device)?.name ?? '未知设备'}</span>
            </div>
            {i > 0 && <button className="btn" onClick={() => void run(() => restoreVersion(v, id, h.id), '已恢复为这个版本')}>恢复</button>}
          </div>
        ))}
      </div>
      {!!d?.passwordHistory?.length && (
        <>
          <div className="section-title section">换下来的旧值</div>
          {d.passwordHistory.map((p, i) => (
            <div key={i} className="row small" style={{ padding: '4px 0', flexWrap: 'wrap' }}>
              <span className="muted">{p.field ?? '密码'}</span>
              <span className="grow" style={{ minWidth: 0, overflowWrap: 'anywhere' }}><SecretText text={p.value} /></span>
              <span className="muted nw">{timeAgo(p.changedAt)}换下</span>
            </div>
          ))}
        </>
      )}
    </Dialog>
  );
}

export function ItemEditor({
  vaultId,
  id,
  type,
  folder,
  go,
}: {
  vaultId: string;
  id?: string;
  type?: ItemType;
  folder?: string | null;
  go: (r: Route) => void;
}) {
  const { m, bridge } = useApp();
  const { run, busy } = useAsync();
  const writable = m.vaults().filter((v) => !v.locked && !v.readOnly);
  const [target, setTarget] = useState(vaultId);
  const v = m.vault(target);
  const existing = id ? getItem(v, id)?.data : undefined;
  const [d, setD] = useState<ItemData>(() => existing ?? { ...newItem(type ?? 'login'), folder: folder ?? null });
  const [tagText, setTagText] = useState((existing?.tags ?? []).join('，'));
  const [urlText, setUrlText] = useState((existing?.urls ?? []).join('\n'));
  const set = (patch: Partial<ItemData>) => setD((x) => ({ ...x, ...patch }));
  useEffect(() => {
    editing.vaults.add(target);
    return () => {
      editing.vaults.delete(target);
    };
  }, [target]);
  const folders = flattenFolders(folderTree(v));
  const dup = useMemo(() => {
    if (!d.password) return 0;
    return listItems(v).filter((i) => i.id !== id && i.data.password === d.password).length;
  }, [d.password, v, id]);
  const isKey = isKeyItem(d);
  // 密钥类条目没有账号密码，已有的旧数据仍然显示，不让它丢
  const usesPassword = d.type !== 'note' && (!isKey || !!d.password || !!d.username);

  const setField = (i: number, patch: Partial<Field>) => {
    set({ fields: (d.fields ?? []).map((f, j) => (j === i ? { ...f, ...patch } : f)) });
    // 粘贴时认出服务商，省得手填。只补空白，不覆盖用户写的
    const hit = isKey && patch.value ? detectKey(patch.value) : undefined;
    if (hit?.provider) {
      set({ ...(d.provider ? {} : { provider: hit.provider }), ...(d.title.trim() ? {} : { title: hit.provider }) });
    }
  };

  const addAttachment = () =>
    void run(async () => {
      const f = await bridge.openFile(['*']);
      if (!f) return;
      if (f.bytes.length > 10 * 1024 * 1024) throw new MixiaError('attachment_too_big');
      const ref = await v.putAttachment(f.bytes, f.name, '');
      set({ attachments: [...(d.attachments ?? []), ref] });
    });

  const save = () =>
    void run(async () => {
      const data: ItemData = {
        ...d,
        title: d.title.trim() || '未命名',
        urls: urlText.split('\n').map((s) => s.trim()).filter(Boolean),
        tags: tagText.split(/[,，;；\s]+/).map((s) => s.trim()).filter(Boolean),
      };
      const nid = await saveItem(v, id, data);
      go({ p: 'item', vaultId: target, id: nid });
    }, '已保存');

  return (
    <div className="detail">
      <div className="row" style={{ marginBottom: 14 }}>
        <h1 className="grow" style={{ fontSize: 19 }}>{id ? '编辑' : `新建${/^[A-Za-z]/.test(ITEM_TEMPLATES[d.type].label) ? ' ' : ''}${ITEM_TEMPLATES[d.type].label}`}</h1>
        <button className="btn ghost" onClick={() => go(id ? { p: 'item', vaultId, id } : { p: 'none' })}>取消</button>
        <button className="btn primary" disabled={busy} onClick={save}>保存</button>
      </div>
      <div className="stack">
        {!id && (
          <div className="field">
            <span className="field-label">存放在</span>
            <div className="stack" style={{ gap: 6 }}>
              {writable.map((w) => (
                <button key={w.id} className={`choice ${w.id === target ? 'on' : ''}`} style={{ padding: '8px 12px' }} onClick={() => setTarget(w.id)}>
                  <Seal policy={w.policy} size={24} />
                  <span>
                    <span className="t">{w.name}</span>{' '}
                    <span className="muted small">{POLICY_HINT[w.policy]}</span>
                  </span>
                </button>
              ))}
            </div>
          </div>
        )}
        <div className="field">
          <label htmlFor="t">标题</label>
          <input id="t" className="input" autoFocus value={d.title} onChange={(e) => set({ title: e.target.value })} />
        </div>
        {usesPassword && (
          <>
            <div className="field">
              <label htmlFor="u">账号</label>
              <input id="u" className="input" value={d.username ?? ''} autoComplete="off" spellCheck={false} onChange={(e) => set({ username: e.target.value })} />
            </div>
            <div className="field">
              <label htmlFor="p">密码</label>
              <div className="row">
                <div className="grow"><PasswordInput id="p" value={d.password ?? ''} onChange={(password) => set({ password })} /></div>
                <button className="btn" onClick={() => set({ password: generatePassword(DEFAULT_GEN) })}><Dices size={15} /> 生成</button>
              </div>
              {d.password && <StrengthMeter value={d.password} />}
              {dup > 0 && <span className="small" style={{ color: 'var(--warn)' }}>这个库里还有 {dup} 条用了同样的密码</span>}
              {strength(d.password ?? '').score <= 1 && !!d.password && <span className="muted small">建议点“生成”换一个</span>}
            </div>
            <div className="field">
              <label htmlFor="url">网址（每行一个）</label>
              <textarea id="url" className="textarea" rows={2} style={{ minHeight: 40 }} value={urlText} spellCheck={false} onChange={(e) => setUrlText(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="totp">两步验证密钥（可选）</label>
              <input id="totp" className="input code" value={d.totp ?? ''} spellCheck={false} autoComplete="off" placeholder="otpauth://… 或 Base32 密钥" onChange={(e) => set({ totp: e.target.value })} />
            </div>
          </>
        )}
        {isKey && !usesPassword && (
          <div className="field">
            <label htmlFor="url">控制台网址（每行一个）</label>
            <textarea id="url" className="textarea" rows={1} style={{ minHeight: 40 }} value={urlText} spellCheck={false} onChange={(e) => setUrlText(e.target.value)} />
          </div>
        )}
        {(d.fields ?? []).map((f, i) => (
          <div className="field" key={i}>
            <div className="row">
              <input className={`input grow ${d.type === 'env' ? 'code' : ''}`} style={{ minHeight: 28, padding: '2px 8px', fontSize: 12.5 }} value={f.name} aria-label="字段名" placeholder={d.type === 'env' ? '变量名' : '字段名'} onChange={(e) => setField(i, { name: e.target.value })} />
              {isKey && d.type !== 'env' && f.secret && (
                <input className="input code" style={{ minHeight: 28, padding: '2px 8px', fontSize: 12.5, width: '38%' }} value={f.envName ?? ''} aria-label="环境变量名" placeholder="环境变量名" spellCheck={false} autoComplete="off" onChange={(e) => setField(i, { envName: e.target.value || undefined })} />
              )}
              <label className="row small muted nw">
                <input type="checkbox" checked={!!f.secret} onChange={(e) => setField(i, { secret: e.target.checked })} /> 机密
              </label>
              <button className="iconbtn" aria-label="删除字段" onClick={() => set({ fields: d.fields!.filter((_, j) => j !== i) })}><X size={15} /></button>
            </div>
            {/私钥|公钥|证书/.test(f.name) ? (
              <textarea className="textarea code" rows={3} value={f.value} spellCheck={false} onChange={(e) => setField(i, { value: e.target.value })} />
            ) : (
              f.secret ? (
                <PasswordInput value={f.value} onChange={(value) => setField(i, { value })} />
              ) : (
                <input className="input" value={f.value} spellCheck={false} autoComplete="off" onChange={(e) => setField(i, { value: e.target.value })} />
              )
            )}
          </div>
        ))}
        <div className="row">
          <button className="btn" onClick={() => set({ fields: [...(d.fields ?? []), { name: '', value: '', secret: isKey }] })}><Plus size={15} /> {d.type === 'env' ? '添加变量' : '添加字段'}</button>
          <button className="btn" onClick={addAttachment}><Paperclip size={15} /> 添加附件</button>
        </div>
        {(d.attachments ?? []).map((a) => (
          <div className="row small" key={a.id}>
            <Paperclip size={14} /> <span className="grow truncate">{a.name}</span>
            <button className="iconbtn" aria-label="移除附件" onClick={() => set({ attachments: d.attachments!.filter((x) => x.id !== a.id) })}><X size={15} /></button>
          </div>
        ))}
        {isKey && <KeyEditorFields d={d} set={set} policy={v.policy} />}
        <div className="row" style={{ flexWrap: 'wrap', alignItems: 'flex-start' }}>
          <div className="field grow" style={{ minWidth: 180 }}>
            <label htmlFor="fd">文件夹</label>
            <select id="fd" className="select" value={d.folder ?? ''} onChange={(e) => set({ folder: e.target.value || null })}>
              <option value="">不放在文件夹里</option>
              {folders.map((f) => <option key={f.id} value={f.id}>{f.path.join(' / ')}</option>)}
            </select>
          </div>
          <div className="field grow" style={{ minWidth: 140 }}>
            <label htmlFor="env">环境</label>
            <select id="env" className="select" value={d.env ?? ''} onChange={(e) => set({ env: e.target.value })}>
              <option value="">不区分</option>
              {ENVIRONMENTS.map((x) => <option key={x} value={x}>{ENV_LABELS[x]}</option>)}
            </select>
          </div>
        </div>
        <div className="field">
          <label htmlFor="tg">标签（逗号或空格分隔）</label>
          <input id="tg" className="input" value={tagText} onChange={(e) => setTagText(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="nt">备注</label>
          <textarea id="nt" className="textarea" rows={4} value={d.notes ?? ''} onChange={(e) => set({ notes: e.target.value })} />
        </div>
      </div>
    </div>
  );
}

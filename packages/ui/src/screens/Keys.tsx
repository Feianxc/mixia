import { useMemo, useState } from 'react';
import { ArrowLeft, Copy, FileInput, KeyRound, Plus, TriangleAlert } from 'lucide-react';
import {
  ENV_FORMATS,
  ITEM_TEMPLATES,
  KEY_TYPES,
  KNOWN_PROVIDERS,
  detectKey,
  envRows,
  importDotEnv,
  keyHint,
  keyOverview,
  keyStatus,
  parseDotEnv,
  renderEnv,
  saveItem,
  type EnvFormat,
  type ItemData,
  type ItemType,
  type ItemView,
  type Policy,
} from '@mixia/core';
import { POLICY_HINT, Seal } from '../seal';
import { timeAgo, useApp, useAsync } from '../state';
import { Dialog } from './Common';
import type { Route } from './Main';

export function KeyBadge({ data }: { data: ItemData }) {
  const s = keyStatus(data);
  if (s.state === 'ok') return null;
  return <span className={`badge ${s.state === 'expired' ? 'off' : 'warn'}`}>{s.label}</span>;
}

/** 条目详情里的生命周期信息。 */
export function KeyDetail({ data, policy }: { data: ItemData; policy: Policy }) {
  const s = keyStatus(data);
  const changed = data.passwordChangedAt ?? data.createdAt;
  return (
    <>
      {s.state !== 'ok' && (
        <div className={`banner section ${s.state === 'expired' ? 'danger' : ''}`}>
          <TriangleAlert size={17} />
          <p>
            <strong>{s.label}。</strong>
            {data.usedBy?.length ? `换的时候记得更新：${data.usedBy.join('、')}。` : '换完在这里保存新值，旧值会留在历史里。'}
          </p>
        </div>
      )}
      {data.env === 'production' && policy === 'cloud' && (
        <div className="banner section">
          <TriangleAlert size={17} />
          <p>这是生产环境密钥，现在放在云库。建议用“移到其他库”放进重要本地库。</p>
        </div>
      )}
      <div className="section card">
        {data.provider && (
          <div className="frow"><div className="grow"><div className="k">服务商</div><div className="v">{data.provider}</div></div></div>
        )}
        {!!data.expiresAt && (
          <div className="frow"><div className="grow"><div className="k">到期时间</div><div className="v">{new Date(data.expiresAt).toLocaleDateString('zh-CN')}</div></div></div>
        )}
        <div className="frow">
          <div className="grow">
            <div className="k">上次更换</div>
            <div className="v">
              {timeAgo(changed)}
              {data.rotateDays ? `，每 ${data.rotateDays} 天轮换一次` : ''}
            </div>
          </div>
        </div>
        {!!data.usedBy?.length && (
          <div className="frow">
            <div className="grow">
              <div className="k">用在哪里</div>
              <div className="row" style={{ flexWrap: 'wrap', marginTop: 4 }}>
                {data.usedBy.map((u) => <span key={u} className="chip" style={{ cursor: 'default' }}>{u}</span>)}
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
}

/** 复制成能直接粘贴的格式。值按目标语法转义，密钥里的引号不会变成命令。 */
export function EnvCopy({ data }: { data: ItemData }) {
  const { bridge, m, toast } = useApp();
  const [open, setOpen] = useState(false);
  const rows = envRows(data);
  if (rows.length === 0) return null;
  const copy = (f: EnvFormat) => {
    const { text, skipped } = renderEnv(rows, f);
    setOpen(false);
    void bridge.copy(text, m.prefs.clipboardSeconds);
    const n = rows.length - skipped.length;
    toast(
      skipped.length
        ? `已复制 ${n} 个变量，跳过 ${skipped.length} 个名字不合法的`
        : `已复制 ${n} 个变量，${m.prefs.clipboardSeconds} 秒后清除`,
    );
  };
  return (
    <div style={{ position: 'relative' }}>
      <button className="btn" onClick={() => setOpen((s) => !s)}><Copy size={15} /> 复制为环境变量</button>
      {open && (
        <div className="menu" style={{ left: 0, bottom: 40 }} onMouseLeave={() => setOpen(false)}>
          {ENV_FORMATS.map((f) => <button key={f.id} onClick={() => copy(f.id)}>{f.label}</button>)}
        </div>
      )}
    </div>
  );
}

const ROTATE_OPTIONS: [number, string][] = [
  [0, '不提醒'],
  [30, '每 30 天'],
  [90, '每 90 天'],
  [180, '每半年'],
  [365, '每年'],
];

const toDateInput = (ts?: number) => {
  if (!ts) return '';
  const d = new Date(ts);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
};

export function KeyEditorFields({
  d,
  set,
  policy,
}: {
  d: ItemData;
  set: (patch: Partial<ItemData>) => void;
  policy: Policy;
}) {
  const [usedBy, setUsedBy] = useState((d.usedBy ?? []).join('，'));
  const [paste, setPaste] = useState('');
  const parsed = useMemo(() => (paste.trim() ? parseDotEnv(paste) : null), [paste]);
  const addParsed = () => {
    if (!parsed) return;
    const names = new Set(parsed.vars.map((v) => v.name));
    set({
      fields: [
        ...(d.fields ?? []).filter((f) => !names.has(f.name)),
        ...parsed.vars.map((v) => ({ name: v.name, value: v.value, secret: true })),
      ],
    });
    setPaste('');
  };
  return (
    <>
      {d.type === 'env' && (
        <div className="field">
          <label htmlFor="envp">粘贴 .env 内容（可选）</label>
          <textarea id="envp" className="textarea code" rows={3} value={paste} spellCheck={false} autoComplete="off" placeholder={'API_KEY=xxx\nDB_URL=postgres://…'} onChange={(e) => setPaste(e.target.value)} />
          {parsed && (
            <div className="row">
              <span className="muted small grow">
                识别到 {parsed.vars.length} 个变量{parsed.skipped ? `，${parsed.skipped} 行无法识别` : ''}
              </span>
              <button className="btn" disabled={parsed.vars.length === 0} onClick={addParsed}>加入</button>
            </div>
          )}
        </div>
      )}
      <div className="row" style={{ flexWrap: 'wrap', alignItems: 'flex-start' }}>
        <div className="field grow" style={{ minWidth: 150 }}>
          <label htmlFor="prov">服务商</label>
          <input id="prov" className="input" list="mixia-providers" value={d.provider ?? ''} autoComplete="off" onChange={(e) => set({ provider: e.target.value })} />
          <datalist id="mixia-providers">
            {KNOWN_PROVIDERS.map((p) => <option key={p} value={p} />)}
          </datalist>
        </div>
        <div className="field grow" style={{ minWidth: 150 }}>
          <label htmlFor="exp">到期时间（可选）</label>
          <input
            id="exp"
            className="input"
            type="date"
            value={toDateInput(d.expiresAt)}
            onChange={(e) => {
              const v = e.target.value;
              set({ expiresAt: v ? new Date(`${v}T23:59:59`).getTime() : undefined });
            }}
          />
        </div>
        <div className="field grow" style={{ minWidth: 150 }}>
          <label htmlFor="rot">轮换提醒</label>
          <select id="rot" className="select" value={d.rotateDays ?? 0} onChange={(e) => set({ rotateDays: Number(e.target.value) || undefined })}>
            {ROTATE_OPTIONS.map(([v, t]) => <option key={v} value={v}>{t}</option>)}
          </select>
        </div>
      </div>
      <div className="field">
        <label htmlFor="used">用在哪里（逗号分隔，换的时候照着更新）</label>
        <input
          id="used"
          className="input"
          value={usedBy}
          placeholder="例如：订单服务，prod-server-3，GitHub Actions"
          onChange={(e) => {
            setUsedBy(e.target.value);
            set({ usedBy: e.target.value.split(/[,，;；\n]+/).map((s) => s.trim()).filter(Boolean) });
          }}
        />
      </div>
      {d.env === 'production' && policy === 'cloud' && (
        <p className="small" style={{ color: 'var(--warn)' }}>生产环境密钥建议放进重要本地库，云库的内容会同步到所有被批准的设备。</p>
      )}
    </>
  );
}

function Group({ title, hint, items, go, policyOf }: { title: string; hint?: string; items: ItemView[]; go: (r: Route) => void; policyOf: (id: string) => Policy }) {
  if (items.length === 0) return null;
  return (
    <>
      <h2>{title}（{items.length}）</h2>
      {hint && <p className="muted small" style={{ marginBottom: 8 }}>{hint}</p>}
      <div className="listcard">
        {items.map((i) => (
          <button key={i.vaultId + i.id} className="row-item" onClick={() => go({ p: 'item', vaultId: i.vaultId, id: i.id })}>
            <Seal policy={policyOf(i.vaultId)} size={24} />
            <span className="grow">
              <span className="t truncate" style={{ display: 'block' }}>{i.data.title || '未命名'}</span>
              <span className="s truncate" style={{ display: 'block' }}>
                {[i.data.provider, ITEM_TEMPLATES[i.data.type]?.label, keyHint(i.data)].filter(Boolean).join(' · ')}
              </span>
            </span>
            <KeyBadge data={i.data} />
          </button>
        ))}
      </div>
    </>
  );
}

export function KeysOverview({ go, onQuery }: { go: (r: Route) => void; onQuery: (q: string) => void }) {
  const { m } = useApp();
  const [dlg, setDlg] = useState(false);
  const [menu, setMenu] = useState(false);
  const vaults = m.vaults();
  const policyOf = (id: string): Policy => vaults.find((v) => v.id === id)?.policy ?? 'cloud';
  const o = keyOverview(m.allItems(), (id) => policyOf(id) === 'cloud');
  const writable = vaults.filter((v) => !v.locked && !v.readOnly);
  const target = writable.find((v) => v.policy === 'local') ?? writable[0];
  const quiet = !o.expired.length && !o.expiring.length && !o.rotate.length && !o.cloudProduction.length && !o.duplicates.length;

  return (
    <div className="page">
      <button className="iconbtn only-mobile" aria-label="返回" onClick={() => go({ p: 'none' })}><ArrowLeft size={20} /></button>
      <div className="row" style={{ flexWrap: 'wrap' }}>
        <h1 className="grow">密钥与 API</h1>
        <button className="btn" disabled={!writable.length} onClick={() => setDlg(true)}><FileInput size={15} /> 导入 .env</button>
        <div style={{ position: 'relative' }}>
          <button className="btn primary" disabled={!target} onClick={() => setMenu((s) => !s)}><Plus size={15} /> 新建</button>
          {menu && target && (
            <div className="menu" style={{ right: 0, top: 38 }} onMouseLeave={() => setMenu(false)}>
              {KEY_TYPES.map((t: ItemType) => (
                <button key={t} onClick={() => go({ p: 'new', vaultId: target.id, type: t, folder: null })}>{ITEM_TEMPLATES[t].label}</button>
              ))}
            </div>
          )}
        </div>
      </div>
      <p className="lead">
        API Key、令牌、SSH 密钥、证书和各项目的环境变量。到期和该轮换的都在这里；换的时候旧值留在历史里，随时能找回。
      </p>

      {o.total === 0 && (
        <div className="listcard" style={{ padding: 18 }}>
          <div className="row" style={{ alignItems: 'flex-start' }}>
            <KeyRound size={20} className="muted" />
            <div className="grow">
              <p>还没有密钥。</p>
              <p className="muted small">把项目里的 .env 导入进来，或者新建一条。粘贴密钥时会自动认出 OpenAI、Anthropic、GitHub、阿里云等服务商。</p>
            </div>
          </div>
        </div>
      )}
      {o.total > 0 && quiet && <p className="muted">{o.total} 把密钥，都没有需要处理的。</p>}

      <Group title="已过期" items={o.expired} go={go} policyOf={policyOf} />
      <Group title="快到期" hint="30 天内到期。" items={o.expiring} go={go} policyOf={policyOf} />
      <Group title="该轮换了" items={o.rotate} go={go} policyOf={policyOf} />
      <Group title="云库里的生产密钥" hint="云库内容会同步到所有被批准的设备。生产环境的建议移到重要本地库。" items={o.cloudProduction} go={go} policyOf={policyOf} />
      {o.duplicates.length > 0 && (
        <Group title="同一把密钥存了多条" hint="换的时候容易漏掉其中一条。" items={o.duplicates.flat()} go={go} policyOf={policyOf} />
      )}

      {o.providers.length > 0 && (
        <>
          <h2>按服务商</h2>
          <div className="row" style={{ flexWrap: 'wrap' }}>
            {o.providers.map((p) => (
              <button
                key={p.name}
                className="chip"
                onClick={() => onQuery(`provider:"${p.name === '未分类' ? '' : p.name}"`)}
              >
                {p.name} {p.items.length}
              </button>
            ))}
          </div>
        </>
      )}

      {dlg && <ImportEnv go={go} onClose={() => setDlg(false)} />}
    </div>
  );
}

function ImportEnv({ go, onClose }: { go: (r: Route) => void; onClose: () => void }) {
  const { m, bridge } = useApp();
  const { run, busy } = useAsync();
  const writable = m.vaults().filter((v) => !v.locked && !v.readOnly);
  const [text, setText] = useState('');
  const [title, setTitle] = useState('');
  const [to, setTo] = useState((writable.find((v) => v.policy === 'local') ?? writable[0])?.id ?? '');
  const parsed = useMemo(() => importDotEnv(text, title.trim() || '环境变量'), [text, title]);
  const fields = parsed.row.data.fields ?? [];
  const hits = fields.filter((f) => detectKey(f.value)?.provider).length;

  const pick = () =>
    void run(async () => {
      const f = await bridge.openFile(['*']);
      if (!f) return;
      setText(new TextDecoder().decode(f.bytes));
      if (!title) setTitle(f.name.replace(/^\.+/, '') || '环境变量');
    });

  const save = () =>
    void run(async () => {
      const id = await saveItem(m.vault(to), undefined, parsed.row.data);
      onClose();
      go({ p: 'item', vaultId: to, id });
    }, `已保存 ${fields.length} 个变量`);

  return (
    <Dialog
      title="导入 .env"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>取消</button>
          <button className="btn primary" disabled={busy || fields.length === 0 || !to} onClick={save}>保存 {fields.length} 个变量</button>
        </>
      }
    >
      <div className="stack">
        <p className="muted small">解析在本机完成，项目里的 .env 文件不会被改动。值都按机密保存。</p>
        <div className="row">
          <button className="btn" onClick={pick}><FileInput size={15} /> 选择文件</button>
          <span className="muted small">或者直接粘贴</span>
        </div>
        <textarea className="textarea code" rows={5} value={text} spellCheck={false} autoComplete="off" aria-label=".env 内容" onChange={(e) => setText(e.target.value)} />
        {text.trim() !== '' && (
          <p className="small">
            识别到 {fields.length} 个变量
            {hits ? `，其中 ${hits} 个认出了服务商` : ''}
            {parsed.skipped ? `，${parsed.skipped} 行无法识别` : ''}
          </p>
        )}
        <div className="field">
          <label htmlFor="envt">名称</label>
          <input id="envt" className="input" value={title} placeholder="例如：订单服务 生产环境" onChange={(e) => setTitle(e.target.value)} />
        </div>
        <div className="field">
          <span className="field-label">存放在</span>
          {writable.map((v) => (
            <button key={v.id} className={`choice ${v.id === to ? 'on' : ''}`} style={{ padding: '8px 12px' }} onClick={() => setTo(v.id)}>
              <Seal policy={v.policy} size={24} />
              <span><span className="t">{v.name}</span> <span className="muted small">{POLICY_HINT[v.policy]}</span></span>
            </button>
          ))}
        </div>
      </div>
    </Dialog>
  );
}


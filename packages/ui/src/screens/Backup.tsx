import { useState } from 'react';
import { ArrowLeft, FileCheck2, FileDown, FileUp, Plus, Send, Snowflake, Upload } from 'lucide-react';
import {
  detectAndImport,
  exportCsv,
  exportJson,
  flattenFolders,
  folderTree,
  isKeyItem,
  markDuplicates,
  type ImportPreview,
  type ImportRow,
} from '@mixia/core';
import { POLICY_HINT, POLICY_LABEL, Seal } from '../seal';
import { errorText, fullTime, timeAgo, useApp, useAsync } from '../state';
import { Confirm, Dialog, PasswordInput, StrengthMeter } from './Common';
import { RecoveryDeed } from './Setup';
import type { Route } from './Main';

export function BackupPage({ go }: { go: (r: Route) => void }) {
  const { m, bridge, toast } = useApp();
  const { run } = useAsync();
  const [dlg, setDlg] = useState<
    | { k: 'local' }
    | { k: 'cold' }
    | { k: 'coldopen'; bytes: Uint8Array }
    | { k: 'restore'; bytes: Uint8Array }
    | { k: 'verify'; bytes: Uint8Array }
    | { k: 'import'; preview: ImportPreview }
    | { k: 'transfer'; vaultId: string }
    | { k: 'recv'; bytes: Uint8Array }
    | { k: 'plain' }
    | { k: 'name'; vaultId?: string; current: string }
    | { k: 'deed'; code: string; title: string; lead: string }
    | null
  >(null);
  const vaults = m.vaults();
  const unlocked = vaults.filter((v) => !v.locked);

  const saveBackup = (id: string) =>
    void run(async () => {
      const bytes = await m.exportBackup(id);
      const stamp = new Date().toISOString().slice(0, 10);
      const ok = await bridge.saveFile(`mixia-backup-${stamp}.mxpack`, bytes);
      if (ok) toast('备份已保存。建议马上做一次恢复演练');
    });

  const pickPack = (next: (bytes: Uint8Array) => void) =>
    void run(async () => {
      const f = await bridge.openFile(['mxpack', 'mxcold']);
      if (f) {
        m.packInfo(f.bytes);
        next(f.bytes);
      }
    });

  const pickImport = () =>
    void run(async () => {
      const f = await bridge.openFile(['csv', 'json']);
      if (!f) return;
      // Excel 存的中文 CSV 常是 GBK，先按 UTF-8 严格解码，失败再退回
      let text: string;
      try {
        text = new TextDecoder('utf-8', { fatal: true }).decode(f.bytes);
      } catch {
        text = new TextDecoder('gbk').decode(f.bytes);
      }
      setDlg({ k: 'import', preview: detectAndImport(f.name, text) });
    });

  return (
    <div className="page">
      <button className="iconbtn only-mobile" aria-label="返回" onClick={() => go({ p: 'none' })}><ArrowLeft size={20} /></button>
      <h1>备份与迁移</h1>
      <p className="lead">三类库的数据走不同的路。备份文件是加密的，但恢复码要和它分开保管。</p>

      <h2>保险库</h2>
      <div className="listcard">
        {vaults.map((v) => (
          <div className="listrow" key={v.id}>
            <Seal policy={v.policy} size={30} />
            <div className="grow" style={{ minWidth: 180 }}>
              <strong>{v.name}</strong>
              {v.readOnly && <span className="badge" style={{ marginLeft: 6 }}>只读快照</span>}
              <div className="muted small">
                {POLICY_LABEL[v.policy]} · {v.locked ? '已锁定' : `${v.count} 条`}
                {!v.locked && ` · 上次备份：${timeAgo(v.lastBackupAt)}`}
              </div>
            </div>
            {!v.locked && v.policy !== 'cold' && !v.readOnly && (
              <>
                <button className="btn ghost" onClick={() => setDlg({ k: 'name', vaultId: v.id, current: v.name })}>改名</button>
                {v.policy === 'cloud' && m.isAdmin && (
                  <button className="btn ghost" title="生成新一代库密钥并重新加密全部内容" onClick={() => void run(() => m.rotateVault(v.id), '换钥完成')}>换钥</button>
                )}
                <button className="btn" onClick={() => saveBackup(v.id)}><FileDown size={15} /> 备份</button>
              </>
            )}
            {!v.locked && v.policy === 'local' && !v.readOnly && (
              <button className="btn" onClick={() => setDlg({ k: 'transfer', vaultId: v.id })}><Send size={15} /> 发给设备</button>
            )}
            {!v.locked && v.policy === 'cold' && (
              <>
                <button
                  className="btn primary"
                  onClick={() =>
                    void run(async () => {
                      await bridge.saveFile('cold-vault.mxcold', await m.saveColdVault(v.id));
                    }, '已保存到文件')
                  }
                >
                  保存到文件
                </button>
                <button className="btn" onClick={() => m.closeColdVault(v.id)}>关闭</button>
              </>
            )}
          </div>
        ))}
      </div>
      <div className="actions section">
        <button className="btn" onClick={() => setDlg({ k: 'local' })}><Plus size={15} /> 新建重要本地库</button>
        <button className="btn" onClick={() => setDlg({ k: 'cold' })}><Snowflake size={15} /> 新建冷库</button>
        <button className="btn" onClick={() => pickPack((bytes) => setDlg({ k: 'coldopen', bytes }))}>打开冷库文件</button>
      </div>
      {m.isAdmin && (
        <div className="actions section">
          <button className="btn" onClick={() => setDlg({ k: 'name', current: '' })}><Plus size={15} /> 新建云库</button>
        </div>
      )}

      <h2>恢复</h2>
      <p className="muted small" style={{ marginBottom: 8 }}>只有实际解开过，才能说备份可恢复。</p>
      <div className="actions">
        <button className="btn" onClick={() => pickPack((bytes) => setDlg({ k: 'verify', bytes }))}><FileCheck2 size={15} /> 恢复演练</button>
        <button className="btn" onClick={() => pickPack((bytes) => setDlg({ k: 'restore', bytes }))}><FileUp size={15} /> 从备份恢复</button>
        <button className="btn" onClick={() => pickPack((bytes) => setDlg({ k: 'recv', bytes }))}>接收设备快照</button>
      </div>

      <h2>导入旧密码</h2>
      <p className="muted small" style={{ marginBottom: 8 }}>支持 Chrome、Edge、Firefox、KeePassXC 等导出的 CSV、Bitwarden 未加密 JSON，以及密匣自己导出的 JSON（保留密钥类型和文件夹）。解析在本机完成，原文件不会被改动。</p>
      <div className="actions">
        <button className="btn" onClick={pickImport}><Upload size={15} /> 选择文件</button>
        <button className="btn" disabled={!unlocked.length} onClick={() => setDlg({ k: 'plain' })}>导出明文…</button>
      </div>

      {dlg?.k === 'local' && <NewLocal onClose={() => setDlg(null)} onDeed={(code) => setDlg({ k: 'deed', code, title: '重要库的恢复码', lead: '这是这个库自己的恢复码，和账户恢复码互不相通。设备损坏后，要靠它和备份文件才能恢复。这是唯一一次显示。' })} />}
      {dlg?.k === 'cold' && <NewCold onClose={() => setDlg(null)} onDeed={(code) => setDlg({ k: 'deed', code, title: '冷库的恢复码', lead: '打开冷库需要口令和这个恢复码两样都对。把它和冷库文件分开保管。这是唯一一次显示。' })} />}
      {dlg?.k === 'deed' && (
        <div className="overlay">
          <div className="dialog" style={{ width: 'min(600px, 100%)' }}>
            <RecoveryDeed code={dlg.code} title={dlg.title} lead={dlg.lead} onDone={() => setDlg(null)} />
          </div>
        </div>
      )}
      {dlg?.k === 'coldopen' && <OpenCold bytes={dlg.bytes} onClose={() => setDlg(null)} />}
      {dlg?.k === 'verify' && <Verify bytes={dlg.bytes} onClose={() => setDlg(null)} />}
      {dlg?.k === 'restore' && <Restore bytes={dlg.bytes} onClose={() => setDlg(null)} />}
      {dlg?.k === 'recv' && <Receive bytes={dlg.bytes} onClose={() => setDlg(null)} />}
      {dlg?.k === 'transfer' && <Transfer vaultId={dlg.vaultId} onClose={() => setDlg(null)} />}
      {dlg?.k === 'import' && <ImportDialog preview={dlg.preview} onClose={() => setDlg(null)} />}
      {dlg?.k === 'plain' && <PlainExport onClose={() => setDlg(null)} />}
      {dlg?.k === 'name' && <NameDialog vaultId={dlg.vaultId} current={dlg.current} onClose={() => setDlg(null)} />}
    </div>
  );
}

function NameDialog({ vaultId, current, onClose }: { vaultId?: string; current: string; onClose: () => void }) {
  const { m } = useApp();
  const { run, busy } = useAsync();
  const [name, setName] = useState(current);
  const save = () =>
    void run(async () => {
      if (vaultId) await m.renameVault(vaultId, name.trim());
      else await m.createCloudVault(name.trim());
      onClose();
    });
  return (
    <Dialog
      title={vaultId ? '修改库名' : '新建云库'}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>取消</button>
          <button className="btn primary" disabled={busy || !name.trim()} onClick={save}>保存</button>
        </>
      }
    >
      <input className="input" autoFocus value={name} placeholder="例如：工作" onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && name.trim() && save()} />
    </Dialog>
  );
}

function NewLocal({ onClose, onDeed }: { onClose: () => void; onDeed: (code: string) => void }) {
  const { m } = useApp();
  const { run, busy } = useAsync();
  const [name, setName] = useState('重要');
  const [pass, setPass] = useState('');
  return (
    <Dialog
      title="新建重要本地库"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>取消</button>
          <button
            className="btn primary"
            disabled={busy || !name.trim() || pass.length < 10}
            onClick={() =>
              void run(async () => {
                await new Promise((r) => setTimeout(r, 30));
                const r = await m.createLocalVault(name.trim(), pass);
                onDeed(r.recoveryCode);
              })
            }
          >
            创建
          </button>
        </>
      }
    >
      <div className="stack">
        <p className="muted small">{POLICY_HINT.local}。服务器不知道它存在。这台设备坏了就只能靠备份恢复。</p>
        <div className="field"><label htmlFor="ln">名称</label><input id="ln" className="input" value={name} onChange={(e) => setName(e.target.value)} /></div>
        <div className="field">
          <label htmlFor="lp">这个库的口令（至少 10 位，建议和主口令不同）</label>
          <PasswordInput id="lp" value={pass} onChange={setPass} />
          <StrengthMeter value={pass} />
        </div>
      </div>
    </Dialog>
  );
}

function NewCold({ onClose, onDeed }: { onClose: () => void; onDeed: (code: string) => void }) {
  const { m, bridge } = useApp();
  const { run, busy } = useAsync();
  const [name, setName] = useState('冷库');
  const [pass, setPass] = useState('');
  return (
    <Dialog
      title="新建冷库"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>取消</button>
          <button
            className="btn primary"
            disabled={busy || !name.trim() || pass.length < 12}
            onClick={() =>
              void run(async () => {
                await new Promise((r) => setTimeout(r, 30));
                const r = await m.createColdVault(name.trim(), pass);
                await bridge.saveFile('cold-vault.mxcold', r.bytes);
                onDeed(r.recoveryCode);
              })
            }
          >
            创建并保存文件
          </button>
        </>
      }
    >
      <div className="stack">
        <p className="muted small">冷库只在内存里打开，内容不写入这台设备。放根级恢复材料这类极少动用的秘密，把文件存到离线介质上。</p>
        <div className="field"><label htmlFor="cn">名称</label><input id="cn" className="input" value={name} onChange={(e) => setName(e.target.value)} /></div>
        <div className="field">
          <label htmlFor="cp">冷库口令（至少 12 位）</label>
          <PasswordInput id="cp" value={pass} onChange={setPass} />
          <StrengthMeter value={pass} />
        </div>
      </div>
    </Dialog>
  );
}

function CodeInput({ value, onChange, id }: { value: string; onChange: (v: string) => void; id: string }) {
  return <textarea id={id} className="textarea input code" rows={3} value={value} spellCheck={false} autoComplete="off" onChange={(e) => onChange(e.target.value)} />;
}

function OpenCold({ bytes, onClose }: { bytes: Uint8Array; onClose: () => void }) {
  const { m } = useApp();
  const { run, busy } = useAsync();
  const [pass, setPass] = useState('');
  const [code, setCode] = useState('');
  return (
    <Dialog
      title="打开冷库"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>取消</button>
          <button
            className="btn primary"
            disabled={busy || !pass || !code}
            onClick={() =>
              void run(async () => {
                await new Promise((r) => setTimeout(r, 30));
                await m.openColdVault(bytes, pass, code);
                onClose();
              }, '冷库已打开。修改后记得保存到文件')
            }
          >
            打开
          </button>
        </>
      }
    >
      <div className="stack">
        <div className="field"><label htmlFor="op">冷库口令</label><PasswordInput id="op" value={pass} onChange={setPass} autoFocus /></div>
        <div className="field"><label htmlFor="oc">恢复码</label><CodeInput id="oc" value={code} onChange={setCode} /></div>
      </div>
    </Dialog>
  );
}

function Verify({ bytes, onClose }: { bytes: Uint8Array; onClose: () => void }) {
  const { m } = useApp();
  const [code, setCode] = useState('');
  const [res, setRes] = useState<{ name: string; count: number; exportedAt: number } | null>(null);
  const [err, setErr] = useState('');
  return (
    <Dialog
      title="恢复演练"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>关闭</button>
          {!res && (
            <button
              className="btn primary"
              disabled={!code}
              onClick={() => {
                try {
                  setRes(m.verifyBackup(bytes, code));
                  setErr('');
                } catch (e) {
                  setErr(errorText(e));
                }
              }}
            >
              验证
            </button>
          )}
        </>
      }
    >
      {res ? (
        <p>这份备份可以恢复：“{res.name}”，{res.count} 条，备份于 {fullTime(res.exportedAt)}。什么都没有写入。</p>
      ) : (
        <div className="stack">
          <p className="muted small">用恢复码真实解开备份，核对内容。不会写入任何数据。</p>
          <div className="field"><label htmlFor="vc">恢复码</label><CodeInput id="vc" value={code} onChange={setCode} /></div>
          {err && <p className="error" role="alert">{err}</p>}
        </div>
      )}
    </Dialog>
  );
}

function Restore({ bytes, onClose }: { bytes: Uint8Array; onClose: () => void }) {
  const { m, toast } = useApp();
  const { run, busy } = useAsync();
  const [code, setCode] = useState('');
  const [pass, setPass] = useState('');
  return (
    <Dialog
      title="从备份恢复"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>取消</button>
          <button
            className="btn primary"
            disabled={busy || !code || pass.length < 10}
            onClick={() =>
              void run(async () => {
                await new Promise((r) => setTimeout(r, 30));
                const r = await m.restoreBackup(bytes, code, pass);
                toast(`已恢复“${r.name}”，${r.count} 条`);
                onClose();
              })
            }
          >
            恢复为新的本地库
          </button>
        </>
      }
    >
      <div className="stack">
        <p className="muted small">备份恢复成这台设备上的一个新本地库，不覆盖现有数据。备份可能是旧状态，恢复后请核对最近的修改。</p>
        <div className="field"><label htmlFor="rc">恢复码</label><CodeInput id="rc" value={code} onChange={setCode} /></div>
        <div className="field"><label htmlFor="rp">给恢复出的库设一个口令（至少 10 位）</label><PasswordInput id="rp" value={pass} onChange={setPass} /></div>
      </div>
    </Dialog>
  );
}

function Receive({ bytes, onClose }: { bytes: Uint8Array; onClose: () => void }) {
  const { m, toast } = useApp();
  const { run, busy } = useAsync();
  const [pass, setPass] = useState('');
  return (
    <Dialog
      title="接收设备快照"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>取消</button>
          <button
            className="btn primary"
            disabled={busy || pass.length < 10}
            onClick={() =>
              void run(async () => {
                await new Promise((r) => setTimeout(r, 30));
                const r = await m.importTransfer(bytes, pass);
                toast(`已接收“${r.name}”，${r.count} 条（只读）`);
                onClose();
              })
            }
          >
            接收
          </button>
        </>
      }
    >
      <div className="stack">
        <p className="muted small">这个文件是专门封给这台设备的。接收后是只读快照，修改要回到主写设备。</p>
        <div className="field"><label htmlFor="xp">给这份快照设一个口令（至少 10 位）</label><PasswordInput id="xp" value={pass} onChange={setPass} autoFocus /></div>
      </div>
    </Dialog>
  );
}

function Transfer({ vaultId, onClose }: { vaultId: string; onClose: () => void }) {
  const { m, bridge } = useApp();
  const { run } = useAsync();
  const devices = m.devices().filter((d) => d.revokedSeq === undefined && d.deviceId !== m.deviceId);
  const [to, setTo] = useState(devices[0]?.deviceId ?? '');
  return (
    <Dialog
      title="发给其他设备"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>取消</button>
          <button
            className="btn primary"
            disabled={!to}
            onClick={() =>
              void run(async () => {
                const bytes = await m.exportTransfer(vaultId, to);
                await bridge.saveFile('mixia-transfer.mxpack', bytes);
                onClose();
              }, '已生成。用 U 盘或数据线传过去')
            }
          >
            生成文件
          </button>
        </>
      }
    >
      <div className="stack">
        <p className="muted small">生成的文件只有目标设备能解开。用 U 盘或数据线传递，不要上传到网盘：重要库的约定是连密文也不进云端。</p>
        {devices.length === 0 && <p className="muted">没有其他已批准的设备。</p>}
        {devices.map((d) => (
          <label className="row" key={d.deviceId}>
            <input type="radio" checked={to === d.deviceId} onChange={() => setTo(d.deviceId)} /> {d.name}
            <span className="muted small">{d.platform}</span>
          </label>
        ))}
      </div>
    </Dialog>
  );
}

function ImportDialog({ preview, onClose }: { preview: ImportPreview; onClose: () => void }) {
  const { m, toast } = useApp();
  const { run, busy } = useAsync();
  const targets = m.vaults().filter((v) => !v.locked && !v.readOnly);
  const suggested = preview.suggestedVault ? targets.find((t) => t.name === preview.suggestedVault) : undefined;
  const [to, setTo] = useState(suggested?.id ?? targets[0]?.id ?? '');
  const existing = to ? m.allItems().filter((i) => i.vaultId === to) : [];
  const { fresh, dupes } = markDuplicates(preview.rows, existing);
  const folders = new Set(fresh.map((r: ImportRow) => r.folderPath).filter(Boolean));
  return (
    <Dialog
      title="导入预览"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>取消</button>
          <button
            className="btn primary"
            disabled={busy || !to || fresh.length === 0}
            onClick={() =>
              void run(async () => {
                const n = await m.importRows(to, fresh);
                toast(`已导入 ${n} 条`);
                onClose();
              })
            }
          >
            导入 {fresh.length} 条
          </button>
        </>
      }
    >
      <div className="stack">
        <p>{preview.format}：共 {preview.rows.length} 条，其中 {dupes.length} 条重复（跳过），{folders.size} 个文件夹。</p>
        {preview.warnings.map((w) => <p className="muted small" key={w}>{w}</p>)}
        {preview.suggestedVault && (
          <p className={suggested && suggested.id === to ? 'muted small' : 'error'}>
            {suggested
              ? suggested.id === to
                ? `这个文件写明导入到「${preview.suggestedVault}」，已选好。`
                : `这个文件写明导入到「${preview.suggestedVault}」，你现在选的是别的库，请确认。`
              : `这个文件写明导入到「${preview.suggestedVault}」，但没有这个名字的库（或它还锁着）。请先建好或解锁再导入。`}
          </p>
        )}
        <div className="field">
          <span className="field-label">导入到</span>
          {targets.map((t) => (
            <button key={t.id} className={`choice ${t.id === to ? 'on' : ''}`} style={{ padding: '8px 12px' }} onClick={() => setTo(t.id)}>
              <Seal policy={t.policy} size={24} />
              <span><span className="t">{t.name}</span> <span className="muted small">{POLICY_HINT[t.policy]}</span></span>
            </button>
          ))}
        </div>
        <p className="muted small">导入完成后请删除原来的明文文件。</p>
      </div>
    </Dialog>
  );
}

function PlainExport({ onClose }: { onClose: () => void }) {
  const { m, bridge, toast } = useApp();
  const [pass, setPass] = useState('');
  const [fmt, setFmt] = useState<'json' | 'csv'>('json');
  const [ask, setAsk] = useState(false);
  const [err, setErr] = useState('');
  const keyCount = m.allItems().filter((i) => isKeyItem(i.data)).length;
  const go = async () => {
    setAsk(false);
    try {
      // 导出前必须重新验证主口令
      await new Promise((r) => setTimeout(r, 30));
      await m.verifyPassphrase(pass);
      const items = m.allItems();
      const name = (id: string) => m.vaultDisplayName(id);
      const path = (it: (typeof items)[number]) =>
        flattenFolders(folderTree(m.vault(it.vaultId))).find((f) => f.id === it.data.folder)?.path.join('/') ?? '';
      const text = fmt === 'json' ? exportJson(items, name, path) : exportCsv(items, path);
      await bridge.saveFile(`mixia-plain.${fmt}`, new TextEncoder().encode(text));
      toast('已导出。用完请立刻删除这个文件');
      onClose();
    } catch (e) {
      setErr(errorText(e));
    }
  };
  return (
    <Dialog
      title="导出明文"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>取消</button>
          <button className="btn danger" disabled={!pass} onClick={() => setAsk(true)}>导出</button>
        </>
      }
    >
      <div className="stack">
        <div className="banner danger"><span>导出的文件没有任何保护，任何人拿到都能读。只导出当前已解锁的库。</span></div>
        <div className="row">
          <button className={`chip ${fmt === 'json' ? 'on' : ''}`} onClick={() => setFmt('json')}>JSON（完整字段）</button>
          <button className={`chip ${fmt === 'csv' ? 'on' : ''}`} onClick={() => setFmt('csv')}>CSV（基本字段）</button>
        </div>
        {fmt === 'csv' && keyCount > 0 && (
          <p className="small" style={{ color: 'var(--warn)' }}>CSV 不含密钥的值，{keyCount} 条密钥只会留下标题。要导出密钥请选 JSON。</p>
        )}
        <div className="field"><label htmlFor="ep">输入主口令确认</label><PasswordInput id="ep" value={pass} onChange={setPass} /></div>
        {err && <p className="error" role="alert">{err}</p>}
      </div>
      {ask && <Confirm title="确定导出明文？" body="文件里所有密码都是可读的。" action="确定导出" danger onCancel={() => setAsk(false)} onConfirm={() => void go()} />}
    </Dialog>
  );
}

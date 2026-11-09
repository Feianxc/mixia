import { useEffect, useMemo, useState } from 'react';
import { ArrowLeft, Plus, ShieldAlert } from 'lucide-react';
import { deviceFingerprint, fingerprint, b64d, type DeviceInfo, type Level, type PendingDevice, type Role } from '@mixia/core';
import { errorText, fullTime, timeAgo, useApp, useAsync } from '../state';
import { Confirm, Dialog, QrCode } from './Common';
import type { Route } from './Main';

const LEVEL: Record<Level, { label: string; hint: string; cls: string }> = {
  hardware: { label: '硬件保护', hint: '私钥在安全芯片里，无法导出', cls: 'hardware' },
  os: { label: '系统保护', hint: '私钥由系统钥匙串保护，没有硬件绑定', cls: 'warn' },
  software: { label: '软件保护', hint: '没有硬件保护', cls: 'off' },
};

export function DevicesPage({ go }: { go: (r: Route) => void }) {
  const { m } = useApp();
  const { run } = useAsync();
  const [pairing, setPairing] = useState(false);
  const [revoke, setRevoke] = useState<DeviceInfo | null>(null);
  const devices = m.devices();
  const active = devices.filter((d) => d.revokedSeq === undefined);
  const gone = devices.filter((d) => d.revokedSeq !== undefined);
  const needRotate = m.ledger.vaultsNeedingRotation();
  const vaultNames = (ids: string[]) => ids.map((id) => m.vaultDisplayName(id) || '未同步的库').join('、') || '无';

  return (
    <div className="page">
      <button className="iconbtn only-mobile" aria-label="返回" onClick={() => go({ p: 'none' })}><ArrowLeft size={20} /></button>
      <div className="row">
        <h1 className="grow">设备</h1>
        {m.isAdmin && <button className="btn primary" onClick={() => setPairing(true)}><Plus size={15} /> 添加设备</button>}
      </div>
      <p className="lead">只有这里列出的设备能打开你的云库。每台设备都由管理设备亲自批准，记录写在信任账本里，服务器改不了。</p>

      {needRotate.length > 0 && m.isAdmin && (
        <div className="banner">
          <ShieldAlert size={17} />
          <div className="grow">
            <p>有设备被撤销，但 {needRotate.length} 个库还没换钥，旧设备手里的密钥仍能解开这些库的旧数据。</p>
          </div>
          <button className="btn" onClick={() => void run(() => m.finishRotations(), '换钥完成')}>立即换钥</button>
        </div>
      )}

      <div className="listcard">
        {active.map((d) => {
          const me = d.deviceId === m.deviceId;
          const lv = LEVEL[d.level];
          return (
            <div className="listrow" key={d.deviceId}>
              <div className="grow" style={{ minWidth: 200 }}>
                <div className="row" style={{ flexWrap: 'wrap' }}>
                  <strong>{d.name}</strong>
                  {me && <span className="badge">这台设备</span>}
                  <span className="badge">{d.role === 'admin' ? '管理设备' : '普通设备'}</span>
                  <span className={`badge ${lv.cls}`} title={`${lv.hint}（设备自报）`}>{lv.label}</span>
                </div>
                <div className="muted small">{d.platform} · 可打开：{vaultNames(d.vaults)}</div>
                <div className="muted small mono">{deviceFingerprint(d)}</div>
              </div>
              {m.isAdmin && !me && <button className="btn danger" onClick={() => setRevoke(d)}>撤销</button>}
            </div>
          );
        })}
      </div>

      {gone.length > 0 && (
        <>
          <h2>已撤销</h2>
          <div className="listcard">
            {gone.map((d) => (
              <div className="listrow" key={d.deviceId}>
                <div className="grow">
                  <span className="muted">{d.name}</span>
                  <div className="muted small">撤销于 {fullTime(d.revokedAt ?? 0)}{d.revokeReason ? ` · ${d.revokeReason}` : ''}</div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      <h2>信任账本</h2>
      <p className="muted small" style={{ marginBottom: 10 }}>
        所有授权变化都在这里，每条都有签名并串成哈希链。信任根指纹 {fingerprint(new TextEncoder().encode(m.ledger.genesisHash))}。
      </p>
      <p className="muted small" style={{ marginBottom: 10 }}>
        账本位置：第 {m.ledger.seq} 条 · <span className="mono">{fingerprint(new TextEncoder().encode(m.ledger.headHash))}</span>。
        同步之后各设备这里应该一致。不一致说明服务器对不同设备说了不同的话。
      </p>
      <Ledger />

      {pairing && <PairingDialog onClose={() => setPairing(false)} />}
      {revoke && (
        <Confirm
          title={`撤销“${revoke.name}”？`}
          danger
          action="撤销并换钥"
          body={
            <>
              它会立刻失去访问权，所有它能打开的云库都会换新密钥。
              <br /><br />
              <strong>撤销收不回它已经看到的内容。</strong>如果设备是丢了，高权限账号的实际密码也应该改掉。
            </>
          }
          onCancel={() => setRevoke(null)}
          onConfirm={() => {
            const d = revoke;
            setRevoke(null);
            void run(() => m.revokeDevice(d.deviceId, '用户撤销'), '已撤销并完成换钥');
          }}
        />
      )}
    </div>
  );
}

function Ledger() {
  const { m } = useApp();
  const rows = useMemo(() => {
    const names = new Map(m.devices().map((d) => [d.deviceId, d.name]));
    const who = (s: string) => (s === 'root' ? '恢复码（根）' : (names.get(s) ?? '未知设备'));
    return m.book.entries
      .map((e) => JSON.parse(new TextDecoder().decode(b64d(e.body))) as { seq: number; ts: number; signer: string; type: string; data: Record<string, unknown> })
      .reverse()
      .map((b) => {
        const name = names.get(b.data.deviceId as string) ?? '设备';
        const vault = () => m.vaultDisplayName(b.data.vaultId as string) || '一个云库';
        const text: Record<string, () => string> = {
          genesis: () => '创建信任根',
          device_add: () => `批准设备“${name}”`,
          device_revoke: () => `撤销设备“${name}”`,
          grant: () => `调整“${name}”的权限`,
          vault_add: () => `创建云库`,
          vault_rotate: () => `${vault()}换钥，第 ${b.data.gen as number} 代`,
          vault_delete: () => `删除云库`,
          root_rotate: () => '更换恢复码',
        };
        return { seq: b.seq, ts: b.ts, text: (text[b.type] ?? (() => b.type))(), by: who(b.signer) };
      });
  }, [m, m.book.entries.length]);
  return (
    <ol className="ledger">
      {rows.slice(0, 40).map((r) => (
        <li key={r.seq}>
          {r.text}
          <div className="muted small">{fullTime(r.ts)} · 由 {r.by} 签名</div>
        </li>
      ))}
    </ol>
  );
}

function PairingDialog({ onClose }: { onClose: () => void }) {
  const { m, toast } = useApp();
  const [p, setP] = useState<{ code: string; pairId: string; secret: string; expiresAt: number } | null>(null);
  const [dev, setDev] = useState<PendingDevice | null>(null);
  const [err, setErr] = useState('');
  const [role, setRole] = useState<Role>('member');
  const vaults = m.vaults().filter((v) => v.policy === 'cloud');
  const [picked, setPicked] = useState<string[]>(vaults.map((v) => v.id));
  const [matched, setMatched] = useState(false);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    m.startPairing().then(setP, (e) => setErr(errorText(e)));
  }, [m]);

  useEffect(() => {
    if (!p || dev) return;
    const t = window.setInterval(async () => {
      setNow(Date.now());
      try {
        const d = await m.pollPairing(p.pairId, p.secret);
        if (d) setDev(d);
      } catch {
        /* 下一轮再试 */
      }
    }, 2000);
    return () => window.clearInterval(t);
  }, [p, dev, m]);

  const close = () => {
    if (p) void m.cancelPairing(p.pairId);
    onClose();
  };

  const approve = async () => {
    if (!p || !dev) return;
    try {
      await m.approvePairing(p.pairId, p.secret, dev, { role, vaults: picked });
      toast(`已批准“${dev.name}”`);
      onClose();
    } catch (e) {
      setErr(errorText(e));
    }
  };

  const left = p ? Math.max(0, Math.floor((p.expiresAt - now) / 1000)) : 0;

  if (dev) {
    return (
      <Dialog
        title="批准这台设备？"
        onClose={close}
        footer={
          <>
            <button className="btn" onClick={close}>拒绝</button>
            <button className="btn primary" disabled={!matched} onClick={() => void approve()}>批准</button>
          </>
        }
      >
        <div className="stack">
          <div className="listcard">
            <div className="listrow"><span className="muted grow">名称</span><strong>{dev.name}</strong></div>
            <div className="listrow"><span className="muted grow">系统</span>{dev.platform}</div>
            <div className="listrow">
              <span className="muted grow">保护等级</span>
              <span className={`badge ${LEVEL[dev.level].cls}`}>{LEVEL[dev.level].label}（设备自报）</span>
            </div>
          </div>
          <div className="deed"><div className="code" style={{ textAlign: 'center' }}>{dev.fingerprint}</div></div>
          <label className="row"><input type="checkbox" checked={matched} onChange={(e) => setMatched(e.target.checked)} /> 这串指纹和新设备屏幕上的一致</label>
          {role === 'member' ? (
            <div className="field">
              <span className="field-label">可以打开的云库</span>
              {vaults.map((v) => (
                <label className="row" key={v.id}>
                  <input
                    type="checkbox"
                    checked={picked.includes(v.id)}
                    onChange={(e) => setPicked(e.target.checked ? [...picked, v.id] : picked.filter((x) => x !== v.id))}
                  />
                  {v.name}
                </label>
              ))}
            </div>
          ) : (
            <p className="muted small">管理设备能打开全部云库，这样任何一台都能完成撤销和换钥。</p>
          )}
          <div className="field">
            <span className="field-label">设备角色</span>
            <label className="row"><input type="radio" checked={role === 'member'} onChange={() => setRole('member')} /> 普通设备：能用，不能批准别的设备</label>
            <label className="row"><input type="radio" checked={role === 'admin'} onChange={() => setRole('admin')} /> 管理设备：也能批准和撤销设备</label>
          </div>
          {err && <p className="error" role="alert">{err}</p>}
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog title="添加设备" onClose={close} footer={<button className="btn" onClick={close}>取消</button>}>
      {err && <p className="error" role="alert">{err}</p>}
      {p && (
        <div className="stack">
          <p className="muted">在新设备上安装密匣，选“加入已有的密匣”，扫这个二维码或输入配对码。</p>
          <QrCode text={`mixia://pair?s=${encodeURIComponent(m.serverUrl ?? '')}&c=${encodeURIComponent(p.code)}`} />
          <div className="deed"><div className="code" style={{ textAlign: 'center', fontSize: 15 }}>{p.code}</div></div>
          <p className="muted small" style={{ textAlign: 'center' }}>
            等待新设备… {Math.floor(left / 60)}:{String(left % 60).padStart(2, '0')} 后失效 · {timeAgo(now)}
          </p>
        </div>
      )}
    </Dialog>
  );
}

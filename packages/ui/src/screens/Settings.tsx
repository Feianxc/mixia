import { useEffect, useState } from 'react';
import { ArrowLeft } from 'lucide-react';
import { useApp, useAsync } from '../state';
import { Confirm, Dialog, PasswordInput, StrengthMeter } from './Common';
import { RecoveryDeed } from './Setup';
import type { Route } from './Main';

const LEVEL_TEXT = {
  hardware: '硬件保护：设备私钥在安全芯片里，无法导出',
  os: '系统保护：由系统钥匙串保护，没有硬件绑定',
  software: '软件保护：没有硬件绑定，不能存放重要库',
};

export function SettingsPage({ go }: { go: (r: Route) => void }) {
  const { m, bridge } = useApp();
  const { run } = useAsync();
  const [dlg, setDlg] = useState<'pass' | 'wipe' | 'rc' | null>(null);
  const [fillOn, setFillOn] = useState<boolean | null>(null);
  const p = m.prefs;

  useEffect(() => {
    void bridge.autofill?.enabled().then(setFillOn);
  }, [bridge]);

  const num = (label: string, key: 'autoLockMinutes' | 'localLockMinutes' | 'clipboardSeconds', opts: [number, string][]) => (
    <div className="listrow">
      <span className="grow">{label}</span>
      <select className="select" style={{ width: 130 }} value={p[key]} onChange={(e) => void m.setPrefs({ [key]: Number(e.target.value) })}>
        {opts.map(([v, t]) => <option key={v} value={v}>{t}</option>)}
      </select>
    </div>
  );

  return (
    <div className="page">
      <button className="iconbtn only-mobile" aria-label="返回" onClick={() => go({ p: 'none' })}><ArrowLeft size={20} /></button>
      <h1>设置</h1>
      <p className="lead">{LEVEL_TEXT[m.level]}。</p>

      <h2>自动锁定</h2>
      <div className="listcard">
        {num('空闲后锁定全部', 'autoLockMinutes', [[1, '1 分钟'], [5, '5 分钟'], [15, '15 分钟'], [60, '1 小时']])}
        {num('空闲后锁定重要库', 'localLockMinutes', [[1, '1 分钟'], [2, '2 分钟'], [5, '5 分钟']])}
        {num('复制后清除剪贴板', 'clipboardSeconds', [[15, '15 秒'], [30, '30 秒'], [60, '60 秒']])}
        {m.quickAvailable && (
          <div className="listrow">
            <span className="grow">用指纹解锁云库<br /><span className="muted small">重要本地库仍然需要自己的口令</span></span>
            <input
              type="checkbox"
              aria-label="用指纹解锁"
              checked={p.quickUnlock}
              onChange={(e) => {
                // 先取值：await 之后受控复选框已被状态改回去，再读就是旧值
                const on = e.target.checked;
                void run(async () => {
                  if (on) await m.enableQuickUnlock();
                  else await m.disableQuickUnlock();
                  await m.setPrefs({ quickUnlock: on });
                });
              }}
            />
          </div>
        )}
      </div>

      {bridge.autofill && (
        <>
          <h2>自动填充</h2>
          <div className="listcard">
            <div className="listrow">
              <span className="grow">{fillOn ? '已启用，登录框旁会出现“用密匣填充”' : '未启用'}</span>
              {!fillOn && <button className="btn" onClick={() => void bridge.autofill!.openSettings()}>去系统设置开启</button>}
            </div>
          </div>
        </>
      )}

      <h2>账户</h2>
      <div className="listcard">
        <div className="listrow"><span className="grow">服务器</span><span className="muted small">{m.serverUrl ?? '未连接'}</span></div>
        <div className="listrow">
          <span className="grow">主口令</span>
          <button className="btn" onClick={() => setDlg('pass')}>修改</button>
        </div>
        <div className="listrow">
          <span className="grow">恢复码<br /><span className="muted small">怀疑泄露时更换</span></span>
          <button className="btn" onClick={() => setDlg('rc')}>更换</button>
        </div>
      </div>

      <h2>这台设备</h2>
      <div className="listcard">
        <div className="listrow">
          <span className="grow">擦除这台设备<br /><span className="muted small">销毁本机所有数据和硬件密钥</span></span>
          <button className="btn danger" onClick={() => setDlg('wipe')}>擦除</button>
        </div>
      </div>

      <p className="muted small section">密匣 0.1.0 · 协议 v1</p>

      {dlg === 'pass' && <ChangePass onClose={() => setDlg(null)} />}
      {dlg === 'rc' && <RotateRc onClose={() => setDlg(null)} />}
      {dlg === 'wipe' && (
        <Confirm
          title="擦除这台设备？"
          body="本机的全部数据和硬件密钥都会销毁，本地库如果没有备份就永远找不回了。云库的数据还在其他设备和服务器上。"
          action="擦除"
          danger
          onCancel={() => setDlg(null)}
          onConfirm={() => void m.wipeDevice()}
        />
      )}
    </div>
  );
}

function ChangePass({ onClose }: { onClose: () => void }) {
  const { m } = useApp();
  const { run, busy } = useAsync();
  const [a, setA] = useState('');
  const [b, setB] = useState('');
  return (
    <Dialog
      title="修改主口令"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>取消</button>
          <button
            className="btn primary"
            disabled={busy || !a || b.length < 10}
            onClick={() =>
              void run(async () => {
                await new Promise((r) => setTimeout(r, 30));
                await m.changePassphrase(a, b);
              })
            }
          >
            修改并重新锁定
          </button>
        </>
      }
    >
      <div className="stack">
        <p className="muted small">只影响这台设备，其他设备的口令不变。</p>
        <div className="field"><label htmlFor="o">当前口令</label><PasswordInput id="o" value={a} onChange={setA} autoFocus /></div>
        <div className="field"><label htmlFor="n">新口令（至少 10 位）</label><PasswordInput id="n" value={b} onChange={setB} /><StrengthMeter value={b} /></div>
      </div>
    </Dialog>
  );
}

function RotateRc({ onClose }: { onClose: () => void }) {
  const { m } = useApp();
  const { run, busy } = useAsync();
  const [old, setOld] = useState('');
  const [next, setNext] = useState<{ recoveryCode: string; commit: () => Promise<void> } | null>(null);
  if (next) {
    return (
      <div className="overlay">
        <div className="dialog" style={{ width: 'min(600px, 100%)' }}>
          <RecoveryDeed
            code={next.recoveryCode}
            title="新的恢复码"
            lead="先把它抄好。确认后才会生效，生效时旧码作废，云库全部换钥。用旧码做过的云库备份，仍要用旧码才能打开。"
            onDone={() => void run(next.commit, '恢复码已更换').then(onClose)}
          />
        </div>
      </div>
    );
  }
  return (
    <Dialog
      title="更换恢复码"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>取消</button>
          <button
            className="btn primary"
            disabled={busy || !old}
            onClick={() =>
              void run(async () => setNext(m.beginRecoveryRotation(old)))
            }
          >
            更换
          </button>
        </>
      }
    >
      <div className="stack">
        <p className="muted small">需要当前恢复码。如果怀疑已泄露，换码之后还要撤销可疑设备并换钥。</p>
        <div className="field"><label htmlFor="oc">当前恢复码</label><textarea id="oc" className="textarea input code" rows={3} value={old} spellCheck={false} onChange={(e) => setOld(e.target.value)} /></div>
      </div>
    </Dialog>
  );
}

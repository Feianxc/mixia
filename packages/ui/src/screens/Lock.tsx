import { useEffect, useState } from 'react';
import { Fingerprint } from 'lucide-react';
import { Gate } from '../cosmos';
import { errorText, useApp } from '../state';
import { PasswordInput } from './Common';

export function Lock() {
  const { m } = useApp();
  const [pass, setPass] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const quick = m.quickAvailable && m.prefs.quickUnlock;

  const unlock = async () => {
    if (!pass) return;
    setBusy(true);
    setErr('');
    // 让“正在解锁”先绘制出来，Argon2 会占住线程一小段时间
    await new Promise((r) => setTimeout(r, 30));
    try {
      await m.unlock(pass);
      void m.syncNow();
    } catch (e) {
      setErr(errorText(e));
      setPass('');
    } finally {
      // 解锁成功后卡片还要飞进黑洞，按钮保持“正在解锁…”，不跳回去
      if (m.phase !== 'unlocked') setBusy(false);
    }
  };

  const bio = async () => {
    setErr('');
    try {
      await m.quickUnlock();
      void m.syncNow();
    } catch (e) {
      setErr(errorText(e));
    }
  };

  useEffect(() => {
    if (quick) void bio();
    // 只在进入锁屏时自动弹一次
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <Gate variant="hero">
      <div className="gate-card stack">
        <div className="gate-head">
          <h1>密匣</h1>
        </div>
        <PasswordInput value={pass} onChange={setPass} placeholder="主口令" autoFocus onEnter={unlock} name="mixia-unlock" />
        {err && <p className="error" role="alert">{err}</p>}
        <button className="btn primary block" disabled={busy || !pass} onClick={unlock}>
          {busy ? '正在解锁…' : '解锁'}
        </button>
        {quick && (
          <button className="btn block" onClick={bio}>
            <Fingerprint size={17} /> 用指纹解锁
          </button>
        )}
      </div>
    </Gate>
  );
}

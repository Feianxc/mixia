import { useEffect, useRef, useState } from 'react';
import { ArrowLeft, Copy, KeyRound, MonitorSmartphone, Printer, QrCode as QrIcon, ShieldPlus } from 'lucide-react';
import { fingerprint, normalizeCode, type JoinState } from '@mixia/core';
import { BlackHoleMark, Gate } from '../cosmos';
import { errorText, useApp } from '../state';
import { PasswordInput, QrScanner, StrengthMeter } from './Common';

type Mode = 'home' | 'create' | 'join' | 'recover';

export function Setup() {
  const [mode, setMode] = useState<Mode>('home');
  return (
    <Gate variant={mode === 'home' ? 'hero' : 'backdrop'}>
      {mode === 'home' && <Home onPick={setMode} />}
      {mode === 'create' && <Create onBack={() => setMode('home')} />}
      {mode === 'join' && <Join onBack={() => setMode('home')} />}
      {mode === 'recover' && <Recover onBack={() => setMode('home')} />}
    </Gate>
  );
}

function Home({ onPick }: { onPick: (m: Mode) => void }) {
  return (
    <div className="gate-card stack">
      <div className="gate-head">
        <h1>密匣</h1>
        <p className="muted">只有你批准的设备能打开。服务器只保存它读不懂的密文。</p>
      </div>
      <button className="choice" onClick={() => onPick('join')}>
        <MonitorSmartphone size={20} />
        <span>
          <span className="t">加入已有的密匣</span>
          <br />
          <span className="muted small">用另一台设备生成的配对码</span>
        </span>
      </button>
      <button className="choice" onClick={() => onPick('create')}>
        <ShieldPlus size={20} />
        <span>
          <span className="t">第一次使用</span>
          <br />
          <span className="muted small">把这台设备设为第一台管理设备</span>
        </span>
      </button>
      <button className="choice" onClick={() => onPick('recover')}>
        <KeyRound size={20} />
        <span>
          <span className="t">用恢复码找回</span>
          <br />
          <span className="muted small">原来的设备都不在了</span>
        </span>
      </button>
    </div>
  );
}

function Back({ onBack, label }: { onBack: () => void; label: string }) {
  return (
    <div className="row" style={{ marginBottom: 12 }}>
      <button className="iconbtn" aria-label="返回" onClick={onBack}>
        <ArrowLeft size={18} />
      </button>
      <h1 className="display" style={{ fontSize: 20 }}>{label}</h1>
    </div>
  );
}

function PassPair({
  pass,
  setPass,
  again,
  setAgain,
}: {
  pass: string;
  setPass: (v: string) => void;
  again: string;
  setAgain: (v: string) => void;
}) {
  return (
    <>
      <div className="field">
        <label htmlFor="p1">主口令</label>
        <PasswordInput id="p1" value={pass} onChange={setPass} />
        <StrengthMeter value={pass} />
        <span className="muted small">它只在这台设备上用，不会发给服务器，也没有“忘记口令”的后门。</span>
      </div>
      <div className="field">
        <label htmlFor="p2">再输一次</label>
        <PasswordInput id="p2" value={again} onChange={setAgain} />
        {again && pass !== again && <span className="error">两次不一致</span>}
      </div>
    </>
  );
}

const passOk = (p: string, a: string) => p.length >= 10 && p === a;

function Create({ onBack }: { onBack: () => void }) {
  const { m, bridge } = useApp();
  const [server, setServer] = useState(bridge.defaultServer);
  const [token, setToken] = useState('');
  const [name, setName] = useState(bridge.env.info.defaultName);
  const [pass, setPass] = useState('');
  const [again, setAgain] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [code, setCode] = useState('');
  const pending = useRef<(() => void) | null>(null);

  const submit = async () => {
    setBusy(true);
    setErr('');
    await new Promise((r) => setTimeout(r, 30));
    try {
      // createOwner 成功后界面立刻会切到主界面，所以先把恢复码留住
      const r = await m.createOwnerDeferred({ serverUrl: server.trim(), token: token.trim(), passphrase: pass, deviceName: name.trim() });
      pending.current = r.activate;
      setCode(r.recoveryCode);
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  if (code) return <RecoveryDeed code={code} onDone={() => pending.current?.()} />;
  return (
    <div className="gate-card stack">
      <Back onBack={onBack} label="第一次使用" />
      <div className="field">
        <label htmlFor="srv">服务器地址</label>
        <input id="srv" className="input" value={server} spellCheck={false} placeholder="https://mixia.example.com" onChange={(e) => setServer(e.target.value)} />
      </div>
      <div className="field">
        <label htmlFor="tok">一次性初始化令牌</label>
        <input id="tok" className="input code" value={token} spellCheck={false} autoComplete="off" onChange={(e) => setToken(e.target.value)} />
        <span className="muted small">部署服务器时生成，用过一次就永久失效。</span>
      </div>
      <div className="field">
        <label htmlFor="dn">这台设备叫什么</label>
        <input id="dn" className="input" value={name} onChange={(e) => setName(e.target.value)} />
        <span className="muted small">设备名服务器能看到，别写敏感内容。</span>
      </div>
      <PassPair pass={pass} setPass={setPass} again={again} setAgain={setAgain} />
      {err && <p className="error" role="alert">{err}</p>}
      <button className="btn primary block" disabled={busy || !token || !server.trim() || !passOk(pass, again)} onClick={submit}>
        {busy ? '正在创建…' : '创建密匣'}
      </button>
      {!!pass && pass.length < 10 && <span className="muted small">主口令至少 10 位。</span>}
    </div>
  );
}

/** 恢复凭证：用户必须抄写并验证过才能继续，这是唯一一次显示。 */
export function RecoveryDeed({
  code,
  onDone,
  title = '保管好这张恢复凭证',
  lead = '所有设备都丢失时，只有它能找回数据。它是最高权限：拿到它的人可以批准新设备。这是唯一一次显示。',
}: {
  code: string;
  onDone: () => void;
  title?: string;
  lead?: string;
}) {
  const { bridge, toast } = useApp();
  const [check, setCheck] = useState('');
  const ok = normalizeCode(check) === normalizeCode(code);
  return (
    <div className="gate-card wide stack">
      <h1 className="display" style={{ fontSize: 21 }}>{title}</h1>
      <p className="muted">{lead}</p>
      <div className="deed">
        <div className="code">{code.split('-').join(' ')}</div>
        <div className="stamp"><BlackHoleMark size={40} /></div>
      </div>
      <div className="row">
        {bridge.canPrint && <button className="btn" onClick={() => window.print()}><Printer size={15} /> 打印</button>}
        <button
          className="btn"
          onClick={() => {
            void bridge.copy(code, 60);
            toast('已复制，60 秒后自动清除');
          }}
        >
          <Copy size={15} /> 复制
        </button>
      </div>
      <div className="field">
        <label htmlFor="ck">抄好后，把它再输入一遍确认</label>
        <textarea id="ck" className="textarea input code" rows={3} value={check} spellCheck={false} onChange={(e) => setCheck(e.target.value)} />
      </div>
      <button className="btn primary block" disabled={!ok} onClick={onDone}>我已妥善保管</button>
    </div>
  );
}

function Join({ onBack }: { onBack: () => void }) {
  const { m, bridge } = useApp();
  const [server, setServer] = useState(bridge.defaultServer);
  const [code, setCode] = useState('');
  const [scan, setScan] = useState(false);
  const [name, setName] = useState(bridge.env.info.defaultName);
  const [pass, setPass] = useState('');
  const [again, setAgain] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [join, setJoin] = useState<JoinState | null>(null);
  const [fp, setFp] = useState('');

  useEffect(() => {
    if (!join || !fp) return;
    let stop = false;
    let running = false;
    const t = window.setInterval(async () => {
      if (stop || running) return;
      running = true;
      try {
        await m.finishJoin(join);
      } catch (e) {
        setErr(errorText(e));
      } finally {
        running = false;
      }
    }, 2500);
    return () => {
      stop = true;
      window.clearInterval(t);
    };
  }, [join, fp, m]);

  const begin = async () => {
    setBusy(true);
    setErr('');
    try {
      setJoin(await m.beginJoin(server.trim(), code));
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const submit = async () => {
    if (!join) return;
    setBusy(true);
    setErr('');
    await new Promise((r) => setTimeout(r, 30));
    try {
      setFp((await m.submitJoin(join, pass, name.trim())).fingerprint);
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  if (fp) {
    return (
      <div className="gate-card stack">
        <h1 className="display" style={{ fontSize: 20 }}>等待批准</h1>
        <p className="muted">到“{join?.adminName}”上确认下面这串指纹一致，然后选择这台设备能打开哪些库。</p>
        <div className="deed"><div className="code" style={{ textAlign: 'center' }}>{fp}</div></div>
        {err && <p className="error" role="alert">{err}</p>}
      </div>
    );
  }

  if (join) {
    return (
      <div className="gate-card stack">
        <Back onBack={() => setJoin(null)} label="设置这台设备" />
        <p className="muted">配对码有效，来自“{join.adminName}”。信任根指纹 {fingerprint(new TextEncoder().encode(join.genesisHash))}。</p>
        <div className="field">
          <label htmlFor="dn">这台设备叫什么</label>
          <input id="dn" className="input" value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <PassPair pass={pass} setPass={setPass} again={again} setAgain={setAgain} />
        {err && <p className="error" role="alert">{err}</p>}
        <button className="btn primary block" disabled={busy || !passOk(pass, again)} onClick={submit}>
          {busy ? '正在生成设备密钥…' : '申请加入'}
        </button>
      </div>
    );
  }

  return (
    <div className="gate-card stack">
      <Back onBack={onBack} label="加入已有的密匣" />
      <p className="muted">在已批准的管理设备上打开“设备”，点“添加设备”，把配对码填到这里。</p>
      <div className="field">
        <label htmlFor="srv">服务器地址</label>
        <input id="srv" className="input" value={server} spellCheck={false} placeholder="https://mixia.example.com" onChange={(e) => setServer(e.target.value)} />
      </div>
      <div className="field">
        <label htmlFor="pc">配对码</label>
        <div className="row">
          <input id="pc" className="input code grow" value={code} spellCheck={false} autoComplete="off" placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" onChange={(e) => setCode(e.target.value)} />
          <button className="btn" onClick={() => setScan(true)}><QrIcon size={16} /> 扫码</button>
        </div>
      </div>
      {err && <p className="error" role="alert">{err}</p>}
      <button className="btn primary block" disabled={busy || !server.trim() || normalizeCode(code).length !== 24} onClick={begin}>
        {busy ? '正在核对…' : '下一步'}
      </button>
      {scan && (
        <QrScanner
          onClose={() => setScan(false)}
          onResult={(t) => {
            setScan(false);
            const hit = /^mixia:\/\/pair\?s=([^&]+)&c=(.+)$/.exec(t);
            if (hit) {
              setServer(decodeURIComponent(hit[1]!));
              setCode(decodeURIComponent(hit[2]!));
            } else setCode(t);
          }}
        />
      )}
    </div>
  );
}

function Recover({ onBack }: { onBack: () => void }) {
  const { m, bridge } = useApp();
  const [server, setServer] = useState(bridge.defaultServer);
  const [code, setCode] = useState('');
  const [name, setName] = useState(bridge.env.info.defaultName);
  const [pass, setPass] = useState('');
  const [again, setAgain] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    setErr('');
    await new Promise((r) => setTimeout(r, 30));
    try {
      await m.recoverAccount({ serverUrl: server.trim(), recoveryCode: code, passphrase: pass, deviceName: name.trim() });
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="gate-card stack">
      <Back onBack={onBack} label="用恢复码找回" />
      <p className="muted">这台设备会成为新的管理设备。之后请到“设备”里撤销丢失的设备。</p>
      <div className="field">
        <label htmlFor="srv">服务器地址</label>
        <input id="srv" className="input" value={server} spellCheck={false} placeholder="https://mixia.example.com" onChange={(e) => setServer(e.target.value)} />
      </div>
      <div className="field">
        <label htmlFor="rc">恢复码</label>
        <textarea id="rc" className="textarea input code" rows={3} value={code} spellCheck={false} onChange={(e) => setCode(e.target.value)} />
      </div>
      <div className="field">
        <label htmlFor="dn">这台设备叫什么</label>
        <input id="dn" className="input" value={name} onChange={(e) => setName(e.target.value)} />
      </div>
      <PassPair pass={pass} setPass={setPass} again={again} setAgain={setAgain} />
      {err && <p className="error" role="alert">{err}</p>}
      <button className="btn primary block" disabled={busy || !server.trim() || !code || !passOk(pass, again)} onClick={submit}>
        {busy ? '正在恢复…' : '恢复'}
      </button>
    </div>
  );
}

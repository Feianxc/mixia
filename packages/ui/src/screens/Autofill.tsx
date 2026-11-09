import { useEffect, useState } from 'react';
import { phoneFillChoices, search, type FillChoice, type ItemView, type PhoneFillRequest } from '@mixia/core';
import { POLICY_LABEL, Seal } from '../seal';
import { useApp, useAsync } from '../state';
import { Dialog, PasswordInput } from './Common';

/** 手机自动填充：系统把请求交给密匣，用户在这里确认用哪一条。一次只给出这一条。 */
export function AutofillPicker({ req, onDone }: { req: PhoneFillRequest; onDone: () => void }) {
  const { m, bridge } = useApp();
  const [q, setQ] = useState('');
  // 推荐规则和电脑扩展相同；冷库、没有密码的条目不出现，App 来源不推荐
  const { items, suggested } = phoneFillChoices(m.openVaults(), req);
  const hits = q ? new Set(search(items.map((e) => e.item), q)) : null;
  const list = hits ? items.filter((e) => hits.has(e.item)) : suggested;

  const finish = async (i: ItemView) => {
    await bridge.autofill!.finish(i.data.username ?? '', i.data.password ?? '');
    onDone();
  };

  return (
    <Dialog
      title="选择要填充的账号"
      footer={
        <button
          className="btn"
          onClick={() => {
            void bridge.autofill!.cancel();
            onDone();
          }}
        >
          取消
        </button>
      }
    >
      <div className="stack">
        {req.kind === 'web' ? (
          <p className="muted small">网站：<strong>{req.target}</strong>。核对清楚再选，钓鱼页面可能长得很像。</p>
        ) : (
          <div className="banner">
            <p className="small">
              这是应用 <strong>{req.target}</strong> 在请求，不是网站。确认这是你信任的应用，再手动搜索账号。
            </p>
          </div>
        )}
        <input className="input" placeholder="搜索其他账号" value={q} onChange={(e) => setQ(e.target.value)} />
        <div className="listcard">
          {list.slice(0, 30).map(({ item: i, policy }) => (
            <button key={i.vaultId + i.id} className="row-item" onClick={() => void finish(i)}>
              <Seal policy={policy} size={24} title={POLICY_LABEL[policy]} />
              <span className="grow">
                <span className="t truncate" style={{ display: 'block' }}>{i.data.title}</span>
                <span className="s truncate" style={{ display: 'block' }}>{i.data.username}</span>
              </span>
            </button>
          ))}
          {list.length === 0 && <div className="empty" style={{ height: 90 }}>没有匹配的账号</div>}
        </div>
      </div>
    </Dialog>
  );
}

/** 桌面确认框等多久自动拒绝。 */
const CONFIRM_TIMEOUT_MS = 60_000;
/** 弹出后短暂不可点：用户可能正在打字或点别处，不能被一次误触放行。 */
const CONFIRM_ARM_MS = 700;

/** 浏览器扩展要填这一条。站点地址是浏览器报告的，显示 punycode 原文，同形字骗不过去。 */
export function BrowserFillConfirm({
  origin,
  choice,
  onAnswer,
}: {
  origin: string;
  choice: FillChoice;
  onAnswer: (ok: boolean) => void;
}) {
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    const a = window.setTimeout(() => setArmed(true), CONFIRM_ARM_MS);
    const t = window.setTimeout(() => onAnswer(false), CONFIRM_TIMEOUT_MS);
    return () => {
      window.clearTimeout(a);
      window.clearTimeout(t);
    };
  }, [onAnswer]);
  return (
    <Dialog
      title="把这个账号填到网页？"
      onClose={() => onAnswer(false)}
      footer={
        <>
          <button className="btn" onClick={() => onAnswer(false)}>拒绝</button>
          <button className="btn primary" disabled={!armed} onClick={() => onAnswer(true)}>填入</button>
        </>
      }
    >
      <div className="stack">
        {choice.policy === 'local' && (
          <div className="banner">
            <p className="small">这是<strong>重要本地库</strong>的条目，每次填充都要你确认。</p>
          </div>
        )}
        <div>
          <p className="muted small">网站</p>
          <p className="mono" style={{ wordBreak: 'break-all' }}>{origin}</p>
          {choice.match === 'subdomain' && <p className="muted small">这是条目网址的子域名，核对清楚再填。</p>}
          {origin.startsWith('http:') && <p className="muted small">这个页面没有加密，同一网络里的人可能看到填入的内容。</p>}
        </div>
        <div className="row-item" style={{ padding: 0, border: 0, cursor: 'default' }}>
          <Seal policy={choice.policy} size={24} title={POLICY_LABEL[choice.policy]} />
          <span className="grow">
            <span className="t truncate" style={{ display: 'block' }}>{choice.title}</span>
            <span className="s truncate" style={{ display: 'block' }}>{choice.username}</span>
          </span>
        </div>
      </div>
    </Dialog>
  );
}

/** 在桌面上选账号。重要本地库的条目只在这里出现，不进浏览器。 */
export function BrowserFillChoose({
  origin,
  load,
  onAnswer,
}: {
  origin: string;
  load: () => FillChoice[];
  onAnswer: (ref: string | null) => void;
}) {
  const { m } = useApp();
  const { run, busy } = useAsync();
  const [unlockId, setUnlockId] = useState<string | null>(null);
  const [pass, setPass] = useState('');
  useEffect(() => {
    const t = window.setTimeout(() => onAnswer(null), CONFIRM_TIMEOUT_MS);
    return () => window.clearTimeout(t);
  }, [onAnswer]);
  const list = load();
  const locked = m.vaults().filter((v) => v.policy === 'local' && v.locked);
  const unlock = () =>
    void run(async () => {
      await m.unlockLocalVault(unlockId!, pass);
      setUnlockId(null);
      setPass('');
    });
  return (
    <Dialog
      title="选择要填到网页的账号"
      footer={<button className="btn" onClick={() => onAnswer(null)}>取消</button>}
    >
      <div className="stack">
        <div>
          <p className="muted small">网站</p>
          <p className="mono" style={{ wordBreak: 'break-all' }}>{origin}</p>
        </div>
        <div className="listcard">
          {list.slice(0, 30).map((c) => (
            <button key={c.ref} className="row-item" onClick={() => onAnswer(c.ref)}>
              <Seal policy={c.policy} size={24} title={POLICY_LABEL[c.policy]} />
              <span className="grow">
                <span className="t truncate" style={{ display: 'block' }}>{c.title}</span>
                <span className="s truncate" style={{ display: 'block' }}>{c.username}</span>
              </span>
            </button>
          ))}
          {list.length === 0 && <div className="empty" style={{ height: 90 }}>没有这个网站的账号</div>}
        </div>
        {unlockId ? (
          <div className="stack">
            <p className="muted small">解锁“{m.vaultDisplayName(unlockId)}”</p>
            <PasswordInput value={pass} onChange={setPass} autoFocus onEnter={unlock} />
            <button className="btn primary" disabled={busy || !pass} onClick={unlock}>解锁</button>
          </div>
        ) : (
          locked.map((v) => (
            <button key={v.id} className="btn" onClick={() => setUnlockId(v.id)}>解锁“{v.name}”后再选</button>
          ))
        )}
      </div>
    </Dialog>
  );
}

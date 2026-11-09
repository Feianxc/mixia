import { Component, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { BrowserFill, type FillChoice, type Mixia } from '@mixia/core';
import type { Bridge } from './bridge';
import { AppCtx, editing, useMixia } from './state';
import { Setup } from './screens/Setup';
import { Lock } from './screens/Lock';
import { Main } from './screens/Main';
import { BrowserFillChoose, BrowserFillConfirm } from './screens/Autofill';
import { CosmosLayer, SceneProvider, useSceneState } from './cosmos';

export function Root({ m, bridge }: { m: Mixia; bridge: Bridge }) {
  useMixia(m);
  const [toast, setToast] = useState<{ text: string; kind: 'ok' | 'err' } | null>(null);
  const timer = useRef<number | undefined>(undefined);
  const showToast = useCallback((text: string, kind: 'ok' | 'err' = 'ok') => {
    setToast({ text, kind });
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setToast(null), kind === 'err' ? 5000 : 2200);
  }, []);
  const ctx = useMemo(() => ({ m, bridge, toast: showToast }), [m, bridge, showToast]);

  useAutoLock(m, bridge);
  useSyncLoop(m);
  const prompt = useBrowserFill(m, bridge);
  const scene = useSceneState(m);

  return (
    <AppCtx.Provider value={ctx}>
      <SceneProvider value={scene}>
      <CosmosLayer />
      <Boundary>
        {(m.phase === 'fresh' || scene.leaving === 'fresh') && <Setup />}
        {(m.phase === 'locked' || scene.leaving === 'locked') && <Lock />}
        {m.phase === 'unlocked' && scene.mainReady && <Main entering={scene.stage === 'dive'} />}
        {m.phase === 'unlocked' && prompt?.kind === 'confirm' && (
          <BrowserFillConfirm origin={prompt.origin} choice={prompt.choice} onAnswer={prompt.answer} />
        )}
        {m.phase === 'unlocked' && prompt?.kind === 'choose' && (
          <BrowserFillChoose origin={prompt.origin} load={prompt.load} onAnswer={prompt.answer} />
        )}
      </Boundary>
      </SceneProvider>
      {toast && <div className={`toast ${toast.kind === 'err' ? 'err' : ''}`} role="status">{toast.text}</div>}
    </AppCtx.Provider>
  );
}

/** 界面崩溃时给出出路，不留白屏。数据都已落盘，重新载入不会丢。 */
class Boundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  override state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  override render() {
    if (!this.state.failed) return this.props.children;
    return (
      <main className="gate">
        <div className="gate-card stack" style={{ textAlign: 'center' }}>
          <p>界面出了问题。已保存的内容不受影响。</p>
          <button className="btn primary block" onClick={() => location.reload()}>重新载入</button>
        </div>
      </main>
    );
  }
}

type Prompt =
  | { kind: 'confirm'; origin: string; choice: FillChoice; answer: (ok: boolean) => void }
  | { kind: 'choose'; origin: string; load: () => FillChoice[]; answer: (ref: string | null) => void };

/** 回答浏览器扩展的请求。判断都在 BrowserFill 里，这里只把要问用户的事情显示出来。 */
function useBrowserFill(m: Mixia, bridge: Bridge): Prompt | null {
  const [prompt, setPrompt] = useState<Prompt | null>(null);
  const cancel = useRef<(() => void) | null>(null);
  useEffect(() => {
    const fill = bridge.browserFill;
    if (!fill) return;
    const ask = <T,>(make: (answer: (v: T) => void) => Prompt, none: T) =>
      new Promise<T>((resolve) => {
        const answer = (v: T) => {
          cancel.current = null;
          setPrompt(null);
          resolve(v);
        };
        cancel.current = () => answer(none);
        setPrompt(make(answer));
      });
    const service = new BrowserFill(m, {
      confirm: (origin, choice) => ask<boolean>((answer) => ({ kind: 'confirm', origin, choice, answer }), false),
      choose: (origin, load) => ask<string | null>((answer) => ({ kind: 'choose', origin, load, answer }), null),
    });
    fill.onRequest((id, req) => {
      void service.handle(req).then(
        (reply) => fill.reply(id, reply),
        () => fill.reply(id, { ok: false, error: 'denied' }),
      );
    });
    // 窗口锁定时确认框也跟着没了，请求按拒绝处理
    return m.onChange(() => {
      if (m.phase !== 'unlocked') cancel.current?.();
    });
  }, [m, bridge]);
  return prompt;
}

/** 空闲超时、系统锁屏时锁定；本地库的超时更短。 */
function useAutoLock(m: Mixia, bridge: Bridge) {
  const last = useRef(Date.now());
  useEffect(() => {
    const touch = () => {
      last.current = Date.now();
    };
    const events = ['pointerdown', 'keydown', 'wheel', 'touchstart'] as const;
    events.forEach((e) => window.addEventListener(e, touch, { passive: true }));
    bridge.onSystemLock(() => {
      if (m.phase === 'unlocked') m.lock();
    });
    const t = window.setInterval(() => {
      if (m.phase !== 'unlocked') return;
      const idle = (Date.now() - last.current) / 60000;
      if (idle >= m.prefs.autoLockMinutes) {
        m.lock();
        return;
      }
      if (idle >= m.prefs.localLockMinutes) {
        // 正在编辑的库不在这里锁：不能让人写到一半内容丢失。全局超时依然生效。
        for (const v of m.vaults()) {
          if (v.policy === 'local' && !v.locked && !editing.vaults.has(v.id)) m.lockLocalVault(v.id);
        }
      }
    }, 5000);
    return () => {
      events.forEach((e) => window.removeEventListener(e, touch));
      window.clearInterval(t);
    };
  }, [m, bridge]);
}

/** 解锁期间定期同步，本地写入后稍等一下也同步。 */
function useSyncLoop(m: Mixia) {
  useEffect(() => {
    let debounce: number | undefined;
    const off = m.onChange(() => {
      // 离线或出错时交给 60 秒的定时重试，不要在这里形成重试风暴
      const st = m.syncStatus.state;
      if (m.phase !== 'unlocked' || st === 'syncing' || st === 'offline' || st === 'error' || st === 'alarm') return;
      void m.pendingCount().then((n) => {
        if (n > 0) {
          window.clearTimeout(debounce);
          debounce = window.setTimeout(() => void m.syncNow(), 1500);
        }
      });
    });
    const t = window.setInterval(() => {
      if (m.phase === 'unlocked' && !m.revoked) void m.syncNow();
    }, 60000);
    return () => {
      off();
      window.clearInterval(t);
      window.clearTimeout(debounce);
    };
  }, [m]);
}

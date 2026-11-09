import { useCallback, useEffect, useState } from 'react';
import { ArrowLeft, Copy, RefreshCw } from 'lucide-react';
import { DEFAULT_GEN, generatePassphrase, generatePassword, strength, type GenOptions } from '@mixia/core';
import { useApp } from '../state';
import { SecretText } from './Common';
import type { Route } from './Main';

export function GeneratorPage({ go }: { go: (r: Route) => void }) {
  const { bridge, m, toast } = useApp();
  const [mode, setMode] = useState<'chars' | 'words'>('chars');
  const [o, setO] = useState<GenOptions>(DEFAULT_GEN);
  const [words, setWords] = useState(6);
  const [out, setOut] = useState('');

  const roll = useCallback(() => {
    try {
      setOut(mode === 'words' ? generatePassphrase(words) : generatePassword(o));
    } catch {
      setOut('');
    }
  }, [mode, o, words]);
  useEffect(roll, [roll]);

  const s = strength(out);
  const opt = (k: keyof GenOptions, label: string) => (
    <label className="row">
      <input type="checkbox" checked={!!o[k]} onChange={(e) => setO({ ...o, [k]: e.target.checked })} /> {label}
    </label>
  );

  return (
    <div className="page">
      <button className="iconbtn only-mobile" aria-label="返回" onClick={() => go({ p: 'none' })}><ArrowLeft size={20} /></button>
      <h1>生成密码</h1>
      <p className="lead">用系统安全随机数在本机生成，不经过网络。</p>
      <div className="deed stack">
        <div style={{ fontSize: 18, minHeight: 56 }}>{out ? <SecretText text={out} /> : <span className="muted">至少选一种字符</span>}</div>
        <div className="row">
          <span className="muted small grow">约 {s.bits} 位熵 · {s.label}</span>
          <button className="btn" onClick={roll}><RefreshCw size={15} /> 换一个</button>
          <button
            className="btn primary"
            disabled={!out}
            onClick={() => {
              void bridge.copy(out, m.prefs.clipboardSeconds);
              toast(`已复制，${m.prefs.clipboardSeconds} 秒后清除`);
            }}
          >
            <Copy size={15} /> 复制
          </button>
        </div>
      </div>
      <h2>方式</h2>
      <div className="row">
        <button className={`chip ${mode === 'chars' ? 'on' : ''}`} onClick={() => setMode('chars')}>随机字符</button>
        <button className={`chip ${mode === 'words' ? 'on' : ''}`} onClick={() => setMode('words')}>单词短语</button>
      </div>
      {mode === 'chars' ? (
        <div className="stack section">
          <div className="field">
            <label htmlFor="len">长度 {o.length}</label>
            <input id="len" type="range" min={8} max={64} value={o.length} onChange={(e) => setO({ ...o, length: Number(e.target.value) })} />
          </div>
          {opt('lower', '小写字母')}
          {opt('upper', '大写字母')}
          {opt('digits', '数字')}
          {opt('symbols', '符号')}
          {opt('unambiguous', '去掉容易看错的字符（0 O 1 l I）')}
        </div>
      ) : (
        <div className="field section">
          <label htmlFor="wc">单词数 {words}</label>
          <input id="wc" type="range" min={4} max={12} value={words} onChange={(e) => setWords(Number(e.target.value))} />
        </div>
      )}
    </div>
  );
}

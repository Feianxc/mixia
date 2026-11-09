import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Eye, EyeOff } from 'lucide-react';
import qrcode from 'qrcode-generator';
import { strength } from '@mixia/core';

export function Dialog({
  title,
  children,
  onClose,
  footer,
}: {
  title: string;
  children: ReactNode;
  onClose?: () => void;
  footer?: ReactNode;
}) {
  useEffect(() => {
    if (!onClose) return;
    const k = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', k);
    return () => window.removeEventListener('keydown', k);
  }, [onClose]);
  return (
    <div className="overlay" onPointerDown={(e) => e.target === e.currentTarget && onClose?.()}>
      <div className="dialog" role="dialog" aria-modal="true" aria-label={title}>
        <h2>{title}</h2>
        {children}
        {footer && <div className="foot">{footer}</div>}
      </div>
    </div>
  );
}

/** 需要确认的破坏性操作统一走这里，界面不用系统弹窗。 */
export function Confirm({
  title,
  body,
  action,
  danger,
  onCancel,
  onConfirm,
}: {
  title: string;
  body: ReactNode;
  action: string;
  danger?: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <Dialog
      title={title}
      onClose={onCancel}
      footer={
        <>
          <button className="btn" onClick={onCancel}>取消</button>
          <button className={`btn ${danger ? 'danger' : 'primary'}`} onClick={onConfirm}>{action}</button>
        </>
      }
    >
      <div className="muted">{body}</div>
    </Dialog>
  );
}

export function PasswordInput({
  value,
  onChange,
  placeholder,
  autoFocus,
  id,
  onEnter,
  name,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  autoFocus?: boolean;
  id?: string;
  onEnter?: () => void;
  name?: string;
}) {
  const [show, setShow] = useState(false);
  return (
    <div className="row" style={{ position: 'relative' }}>
      <input
        id={id}
        name={name}
        className="input"
        type={show ? 'text' : 'password'}
        value={value}
        placeholder={placeholder}
        autoFocus={autoFocus}
        autoComplete="off"
        spellCheck={false}
        style={{ paddingRight: 40 }}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => e.key === 'Enter' && onEnter?.()}
      />
      <button
        type="button"
        className="iconbtn"
        style={{ position: 'absolute', right: 3 }}
        aria-label={show ? '隐藏' : '显示'}
        onClick={() => setShow((s) => !s)}
      >
        {show ? <EyeOff size={16} /> : <Eye size={16} />}
      </button>
    </div>
  );
}

export function StrengthMeter({ value }: { value: string }) {
  const s = strength(value);
  return (
    <div className="row small">
      <div className={`meter grow s${s.score}`}>
        <i style={{ width: `${(s.score + 1) * 20}%` }} />
      </div>
      <span className="muted nw">{value ? s.label : ''}</span>
    </div>
  );
}

/** 数字和符号用不同颜色，抄写时容易分辨 0 和 O。 */
export function SecretText({ text }: { text: string }) {
  return (
    <span className="secret">
      {[...text].map((c, i) => (
        <span key={i} className={/\d/.test(c) ? 'd' : /[^\p{L}\p{N}]/u.test(c) ? 'y' : undefined}>
          {c}
        </span>
      ))}
    </span>
  );
}

export function QrCode({ text, size = 200 }: { text: string; size?: number }) {
  const svg = useMemo(() => {
    const q = qrcode(0, 'M');
    q.addData(text);
    q.make();
    const n = q.getModuleCount();
    const parts: string[] = [];
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) if (q.isDark(r, c)) parts.push(`M${c} ${r}h1v1h-1z`);
    }
    return { n, d: parts.join('') };
  }, [text]);
  return (
    <div className="qr">
      <svg width={size} height={size} viewBox={`0 0 ${svg.n} ${svg.n}`} shapeRendering="crispEdges" role="img" aria-label="配对二维码">
        <path d={svg.d} fill="#101818" />
      </svg>
    </div>
  );
}

/** 摄像头扫码，纯本地解码。 */
export function QrScanner({ onResult, onClose }: { onResult: (text: string) => void; onClose: () => void }) {
  const video = useRef<HTMLVideoElement>(null);
  const [err, setErr] = useState('');
  useEffect(() => {
    let stream: MediaStream | undefined;
    let stop = false;
    const canvas = document.createElement('canvas');
    (async () => {
      try {
        const { default: jsQR } = await import('jsqr');
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
        if (stop || !video.current) return;
        video.current.srcObject = stream;
        await video.current.play();
        const tick = () => {
          if (stop || !video.current) return;
          const w = video.current.videoWidth;
          const h = video.current.videoHeight;
          if (w && h) {
            canvas.width = w;
            canvas.height = h;
            const g = canvas.getContext('2d', { willReadFrequently: true })!;
            g.drawImage(video.current, 0, 0, w, h);
            const code = jsQR(g.getImageData(0, 0, w, h).data, w, h);
            if (code?.data) {
              onResult(code.data);
              return;
            }
          }
          requestAnimationFrame(tick);
        };
        tick();
      } catch {
        setErr('打不开摄像头。请直接输入配对码');
      }
    })();
    return () => {
      stop = true;
      stream?.getTracks().forEach((t) => t.stop());
    };
  }, [onResult]);
  return (
    <Dialog title="扫描配对码" onClose={onClose} footer={<button className="btn" onClick={onClose}>取消</button>}>
      {err ? <p className="error">{err}</p> : <video ref={video} playsInline muted style={{ width: '100%', borderRadius: 8 }} />}
    </Dialog>
  );
}

/** 到 native host 的连接。用的时候才连，闲置后断开，这样 Service Worker 能休眠。 */
import type { Native, NativeReply, NativeRequest } from './controller';

const HOST = 'online.feian.mixia';
const IDLE_MS = 30_000;
// 桌面确认框 60 秒自动拒绝，这里留余量
const INTERACTIVE_MS = 100_000;
const QUICK_MS = 6_000;

type Pending = { done: (r: NativeReply) => void; timer: ReturnType<typeof setTimeout> };

export class NativeClient implements Native {
  private port: chrome.runtime.Port | undefined;
  private seq = 0;
  private pending = new Map<number, Pending>();
  private idle: ReturnType<typeof setTimeout> | undefined;

  private connect(): chrome.runtime.Port {
    if (this.port) return this.port;
    const port = chrome.runtime.connectNative(HOST);
    port.onMessage.addListener((m: NativeReply & { id?: number }) => {
      const p = m.id === undefined ? undefined : this.pending.get(m.id);
      if (!p) return;
      this.pending.delete(m.id!);
      clearTimeout(p.timer);
      p.done(m);
      this.touch();
    });
    port.onDisconnect.addListener(() => {
      void chrome.runtime.lastError; // 读掉，否则控制台报未处理错误
      this.port = undefined;
      for (const p of this.pending.values()) {
        clearTimeout(p.timer);
        p.done({ ok: false, error: 'desktop_unavailable' });
      }
      this.pending.clear();
    });
    this.port = port;
    return port;
  }

  private touch(): void {
    clearTimeout(this.idle);
    this.idle = setTimeout(() => {
      if (this.pending.size === 0) {
        this.port?.disconnect();
        this.port = undefined;
      }
    }, IDLE_MS);
  }

  request(req: NativeRequest): Promise<NativeReply> {
    return new Promise((done) => {
      const id = ++this.seq;
      const ms = req.op === 'fill' || req.op === 'pick' ? INTERACTIVE_MS : QUICK_MS;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        // host 串行处理，超时后这个连接已经不可用
        this.port?.disconnect();
        this.port = undefined;
        done({ ok: false, error: 'timeout' });
      }, ms);
      this.pending.set(id, { done, timer });
      try {
        this.connect().postMessage({ id, ...req });
      } catch {
        this.pending.delete(id);
        clearTimeout(timer);
        this.port = undefined;
        done({ ok: false, error: 'desktop_unavailable' });
      }
    });
  }
}

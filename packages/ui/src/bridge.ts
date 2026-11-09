/**
 * 平台桥：界面需要的所有系统能力。Electron 和 Capacitor 各实现一份，界面代码不感知平台。
 */
import { IdbKV, SoftwareKeys, MemoryKV, type PlatformEnv, type Transport } from '@mixia/core';

export interface OpenedFile {
  name: string;
  bytes: Uint8Array;
}

export interface Bridge {
  env: PlatformEnv;
  /** 复制到剪贴板，尽量排除系统历史和云剪贴板，到时自动清除。 */
  copy(text: string, clearAfterSeconds: number): Promise<void>;
  saveFile(suggestedName: string, bytes: Uint8Array): Promise<boolean>;
  openFile(extensions: string[]): Promise<OpenedFile | null>;
  /** 系统锁屏、休眠、切后台时回调。 */
  onSystemLock(cb: () => void): void;
  openExternal(url: string): void;
  /** Android WebView 的 window.print 什么都不做，手机上不显示打印按钮。 */
  canPrint?: boolean;
  /** 手机返回键。 */
  onBack?(cb: () => void): void;
  exitApp?(): void;
  /** 手机才有：自动填充请求进来时，界面需要让用户选条目。 */
  autofill?: AutofillBridge;
  /** 桌面才有：浏览器扩展的请求，由界面逐条回答。 */
  browserFill?: BrowserFillBridge;
  defaultServer: string;
}

export interface BrowserFillBridge {
  onRequest(cb: (id: number, req: unknown) => void): void;
  reply(id: number, reply: unknown): Promise<void>;
}

export interface AutofillRequest {
  target: string;
  /** web 域名或 Android 包名。 */
  kind: 'web' | 'app';
}

export interface AutofillBridge {
  pending(): Promise<AutofillRequest | null>;
  finish(username: string, password: string): Promise<void>;
  cancel(): Promise<void>;
  onRequest(cb: (r: AutofillRequest) => void): void;
  openSettings(): Promise<void>;
  enabled(): Promise<boolean>;
}

/** 浏览器开发预览：没有硬件保护，只用于看界面，等级是 software。 */
export function devBridge(): Bridge {
  const http: Transport = async (r) => {
    const url = r.url.replace(/^https?:\/\/[^/]+/, '/mx');
    const res = await fetch(url, {
      method: r.method,
      headers: r.headers,
      ...(r.body ? { body: r.body as BodyInit } : {}),
    });
    return { status: res.status, body: new Uint8Array(await res.arrayBuffer()) };
  };
  const hwKv = IdbKV.open('mixia-dev-hw');
  return {
    env: {
      hw: new SoftwareKeys(hwKv),
      http,
      openKV: (n) => IdbKV.open(`mixia-dev-${n}`),
      info: { platform: 'web-dev', defaultName: '开发预览', kdfMem: 64 * 1024 * 1024 },
    },
    copy: (t) => navigator.clipboard.writeText(t),
    saveFile: async (name, bytes) => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([bytes as BlobPart]));
      a.download = name;
      a.click();
      return true;
    },
    openFile: (ext) =>
      new Promise((resolve) => {
        const i = document.createElement('input');
        i.type = 'file';
        i.accept = ext.map((e) => `.${e}`).join(',');
        i.onchange = async () => {
          const f = i.files?.[0];
          resolve(f ? { name: f.name, bytes: new Uint8Array(await f.arrayBuffer()) } : null);
        };
        i.click();
      }),
    onSystemLock: () => undefined,
    openExternal: (u) => window.open(u, '_blank', 'noopener'),
    defaultServer: 'http://127.0.0.1:8096',
  };
}

export { MemoryKV };

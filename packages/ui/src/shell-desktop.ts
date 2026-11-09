/** Electron 外壳桥。所有系统能力都走 preload 暴露的最小接口，渲染进程没有 Node。 */
import { IdbKV, b64d, b64e, type HardwareKeys, type Level, type Transport } from '@mixia/core';
import type { Bridge, OpenedFile } from './bridge';

interface DesktopApi {
  hw(cmd: string, args: Record<string, unknown>): Promise<Record<string, string>>;
  hwStatus(): Promise<{ level: Level; provider: string }>;
  http(req: { method: string; url: string; headers: Record<string, string>; body?: Uint8Array }): Promise<{ status: number; body: Uint8Array }>;
  pinServer(url: string): Promise<void>;
  unpinServer(): Promise<void>;
  copy(text: string, seconds: number): Promise<void>;
  saveFile(name: string, bytes: Uint8Array): Promise<boolean>;
  openFile(ext: string[]): Promise<OpenedFile | null>;
  openExternal(url: string): void;
  onSystemLock(cb: () => void): void;
  onBrowserRequest(cb: (id: number, req: unknown) => void): void;
  browserReply(id: number, reply: unknown): Promise<void>;
  hostname: string;
  platform: string;
}

const api = () => (window as unknown as { mixiaDesktop: DesktopApi }).mixiaDesktop;

function hardware(level: Level): HardwareKeys {
  const a = api();
  return {
    level,
    create: async (name) => b64d((await a.hw('create', { name })).authPub!),
    sign: async (name, msg) => b64d((await a.hw('sign', { name, data: b64e(msg) })).sig!),
    seal: async (name, data) => {
      const r = await a.hw('seal', { name, data: b64e(data) });
      // 封存算法写进 blob 前缀，解封时原样带回
      return new TextEncoder().encode(`${r.alg}:${r.blob}`);
    },
    unseal: async (name, blob) => {
      const text = new TextDecoder().decode(blob);
      const i = text.indexOf(':');
      const r = await a.hw('unseal', { name, alg: text.slice(0, i), blob: text.slice(i + 1) });
      return b64d(r.data!);
    },
    destroy: async (name) => {
      await a.hw('delete', { name });
    },
  };
}

export async function desktopBridge(): Promise<Bridge> {
  const a = api();
  const { level } = await a.hwStatus();
  const http: Transport = (r) => a.http(r);
  return {
    env: {
      hw: hardware(level),
      http,
      openKV: (n) => IdbKV.open(`mixia-${n}`),
      info: { platform: a.platform, defaultName: a.hostname, kdfMem: 256 * 1024 * 1024 },
      pinServer: (u) => a.pinServer(u),
      unpinServer: () => a.unpinServer(),
    },
    canPrint: true,
    copy: (t, s) => a.copy(t, s),
    saveFile: (n, b) => a.saveFile(n, b),
    openFile: (e) => a.openFile(e),
    onSystemLock: (cb) => a.onSystemLock(cb),
    openExternal: (u) => a.openExternal(u),
    browserFill: { onRequest: (cb) => a.onBrowserRequest(cb), reply: (id, r) => a.browserReply(id, r) },
    // 自己部署时可在构建时写入 VITE_MIXIA_DEFAULT_SERVER；公开发布的包留空，第一次使用时填写
    defaultServer: import.meta.env.VITE_MIXIA_DEFAULT_SERVER ?? '',
  };
}

/** Capacitor 外壳桥。硬件密钥、联网、自动填充都在 Kotlin 插件里，WebView 本身不能联网。 */
import { registerPlugin } from '@capacitor/core';
import { IdbKV, b64d, b64e, type HardwareKeys, type Level, type QuickUnlock, type Transport } from '@mixia/core';
import type { AutofillRequest, Bridge } from './bridge';

interface Native {
  hwLevel(): Promise<{ level: Level; strongbox: boolean }>;
  hwCreate(a: { name: string }): Promise<{ authPub: string }>;
  hwSign(a: { name: string; data: string }): Promise<{ sig: string }>;
  hwSeal(a: { name: string; data: string }): Promise<{ blob: string }>;
  hwUnseal(a: { name: string; blob: string }): Promise<{ data: string }>;
  hwDestroy(a: { name: string }): Promise<void>;
  quickAvailable(): Promise<{ value: boolean }>;
  quickEnroll(a: { name: string; data: string }): Promise<void>;
  quickRetrieve(a: { name: string }): Promise<{ data: string }>;
  quickClear(a: { name: string }): Promise<void>;
  http(a: { method: string; url: string; headers: Record<string, string>; body?: string }): Promise<{ status: number; body: string }>;
  pinServer(a: { url: string }): Promise<void>;
  unpinServer(): Promise<void>;
  copy(a: { text: string; seconds: number }): Promise<void>;
  saveFile(a: { name: string; data: string }): Promise<{ saved: boolean }>;
  openFile(a: { types: string[] }): Promise<{ name?: string; data?: string }>;
  openExternal(a: { url: string }): Promise<void>;
  deviceInfo(): Promise<{ model: string; sdk: number }>;
  autofillPending(): Promise<{ target?: string; kind?: 'web' | 'app' }>;
  autofillFinish(a: { username: string; password: string }): Promise<void>;
  autofillCancel(): Promise<void>;
  autofillEnabled(): Promise<{ value: boolean }>;
  autofillSettings(): Promise<void>;
  exitApp(): Promise<void>;
  addListener(ev: string, cb: (d: AutofillRequest) => void): Promise<unknown>;
}

const plugin = registerPlugin<Native>('MixiaNative');

export async function mobileBridge(): Promise<Bridge> {
  const n = plugin;
  const { level } = await n.hwLevel();
  const info = await n.deviceInfo();
  const quick: QuickUnlock = {
    available: async () => (await n.quickAvailable()).value,
    enroll: (name, secret) => n.quickEnroll({ name, data: b64e(secret) }),
    retrieve: async (name) => b64d((await n.quickRetrieve({ name })).data),
    clear: (name) => n.quickClear({ name }),
  };
  const hw: HardwareKeys = {
    level,
    create: async (name) => b64d((await n.hwCreate({ name })).authPub),
    sign: async (name, msg) => b64d((await n.hwSign({ name, data: b64e(msg) })).sig),
    seal: async (name, data) => b64d((await n.hwSeal({ name, data: b64e(data) })).blob),
    unseal: async (name, blob) => b64d((await n.hwUnseal({ name, blob: b64e(blob) })).data),
    destroy: (name) => n.hwDestroy({ name }),
    ...((await quick.available()) ? { quick } : {}),
  };
  const http: Transport = async (r) => {
    const res = await n.http({
      method: r.method,
      url: r.url,
      headers: r.headers,
      ...(r.body ? { body: b64e(r.body) } : {}),
    });
    return { status: res.status, body: b64d(res.body) };
  };
  return {
    env: {
      hw,
      http,
      openKV: (name) => IdbKV.open(`mixia-${name}`),
      // 手机内存紧张时 256 MiB 可能被杀，这里取 128 MiB
      info: { platform: `Android ${info.sdk}`, defaultName: info.model, kdfMem: 128 * 1024 * 1024 },
      pinServer: (url) => n.pinServer({ url }),
      unpinServer: () => n.unpinServer(),
      // 自动填充窗口是第二个实例，只读不同步，否则两个实例的计数器会互相覆盖
      noSync: !!(await n.autofillPending()).target,
    },
    copy: (text, seconds) => n.copy({ text, seconds }),
    saveFile: async (name, bytes) => (await n.saveFile({ name, data: b64e(bytes) })).saved,
    openFile: async (ext) => {
      const r = await n.openFile({ types: ext });
      return r.data ? { name: r.name ?? 'file', bytes: b64d(r.data) } : null;
    },
    onSystemLock: (cb) => {
      void n.addListener('systemLock', cb);
    },
    openExternal: (url) => void n.openExternal({ url }),
    onBack: (cb) => {
      void n.addListener('backButton', cb);
    },
    exitApp: () => void n.exitApp(),
    autofill: {
      pending: async () => {
        const r = await n.autofillPending();
        return r.target ? { target: r.target, kind: r.kind ?? 'app' } : null;
      },
      finish: (username, password) => n.autofillFinish({ username, password }),
      cancel: () => n.autofillCancel(),
      onRequest: (cb) => {
        void n.addListener('autofillRequest', cb);
      },
      enabled: async () => (await n.autofillEnabled()).value,
      openSettings: () => n.autofillSettings(),
    },
    // 自己部署时可在构建时写入 VITE_MIXIA_DEFAULT_SERVER；公开发布的包留空，第一次使用时填写
    defaultServer: import.meta.env.VITE_MIXIA_DEFAULT_SERVER ?? '',
  };
}

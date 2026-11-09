import { contextBridge, ipcRenderer } from 'electron';

/**
 * 渲染进程能碰到的全部系统能力。没有 Node、没有文件系统、没有任意 IPC。
 * 主进程还会校验每次调用的来源页面。
 */
contextBridge.exposeInMainWorld('mixiaDesktop', {
  hw: (cmd: string, args: Record<string, unknown>) => ipcRenderer.invoke('hw', cmd, args),
  hwStatus: () => ipcRenderer.invoke('hw-status'),
  http: (req: unknown) => ipcRenderer.invoke('http', req),
  pinServer: (url: string) => ipcRenderer.invoke('pin-server', url),
  unpinServer: () => ipcRenderer.invoke('unpin-server'),
  copy: (text: string, seconds: number) => ipcRenderer.invoke('copy', text, seconds),
  saveFile: (name: string, bytes: Uint8Array) => ipcRenderer.invoke('save-file', name, bytes),
  openFile: (ext: string[]) => ipcRenderer.invoke('open-file', ext),
  openExternal: (url: string) => ipcRenderer.send('open-external', url),
  onSystemLock: (cb: () => void) => {
    ipcRenderer.on('system-lock', () => cb());
  },
  onBrowserRequest: (cb: (id: number, req: unknown) => void) => {
    ipcRenderer.on('browser-request', (_e, id: number, req: unknown) => cb(id, req));
  },
  browserReply: (id: number, reply: unknown) => ipcRenderer.invoke('browser-reply', id, reply),
  hostname: ipcRenderer.sendSync('hostname') as string,
  platform: process.platform === 'win32' ? 'Windows' : process.platform === 'darwin' ? 'macOS' : 'Linux',
});

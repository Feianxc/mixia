import { readFile, rm, stat, writeFile } from 'node:fs/promises';
import { existsSync, readFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { extname, join, normalize, sep } from 'node:path';
import {
  BrowserWindow,
  Menu,
  app,
  clipboard,
  dialog,
  ipcMain,
  net,
  powerMonitor,
  protocol,
  session,
  shell,
  type IpcMainEvent,
  type IpcMainInvokeEvent,
  type Session,
  nativeTheme,
} from 'electron';
import { BrowserBridge } from './browser-bridge';
import { openHardware, type HwBackend } from './hw';
import type { BrowserRequest } from '../../../packages/core/src/autofill';

/** 服务器不可信，界面代码只来自本机安装包，这里是 Web 路线不具备的那条边界。 */
const ORIGIN = 'app://mixia';
const CSP =
  "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; " +
  "font-src 'self'; img-src 'self' data: blob:; media-src 'self' blob: mediastream:; " +
  "connect-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'";

// 放在 Local 而不是 Roaming：不随域漫游，也不容易被同步盘的目录重定向带走
const testDataDir = app.isPackaged ? undefined : process.env.MIXIA_DATA_DIR;
if (testDataDir) app.setPath('userData', testDataDir);
else if (process.platform === 'win32' && process.env.LOCALAPPDATA) {
  app.setPath('userData', join(process.env.LOCALAPPDATA, 'Mixia'));
}

// 正式包不接受远程调试开关，否则同用户进程可以附加到渲染进程执行代码
if (app.isPackaged && ['remote-debugging-port', 'inspect', 'inspect-brk'].some((s) => app.commandLine.hasSwitch(s))) {
  app.exit(1);
}

protocol.registerSchemesAsPrivileged([
  { scheme: 'app', privileges: { standard: true, secure: true, supportFetchAPI: true } },
]);

if (!app.requestSingleInstanceLock()) app.quit();

let win: BrowserWindow | undefined;
let hw: HwBackend | undefined;
let browserBridge: BrowserBridge | undefined;
/** 还没到时间的剪贴板清除。退出时不能把它们弄丢。 */
const pendingClears = new Set<() => Promise<void>>();

// 界面打在 asar 里，受完整性校验保护
const uiDir = () => join(app.getAppPath(), 'ui');

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.woff2': 'font/woff2',
  '.wasm': 'application/wasm',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
};

async function serve(request: Request): Promise<Response> {
  const url = new URL(request.url);
  if (url.host !== 'mixia') return new Response(null, { status: 404 });
  const root = normalize(uiDir());
  const rel = decodeURIComponent(url.pathname === '/' ? '/index.html' : url.pathname);
  const file = normalize(join(root, rel));
  if (!file.startsWith(root + sep)) return new Response(null, { status: 403 });
  try {
    const body = await readFile(file);
    return new Response(body, {
      headers: {
        'content-type': MIME[extname(file)] ?? 'application/octet-stream',
        'content-security-policy': CSP,
        'x-content-type-options': 'nosniff',
      },
    });
  } catch {
    return new Response(null, { status: 404 });
  }
}

/** 所有 IPC 都要来自我们自己的页面主框架。 */
function trusted(e: IpcMainInvokeEvent | IpcMainEvent): void {
  const frame = e.senderFrame;
  if (!frame || frame !== e.sender.mainFrame || !frame.url.startsWith(`${ORIGIN}/`)) {
    throw new Error('untrusted_sender');
  }
}

const pinFile = () => join(app.getPath('userData'), 'server-origin');

function pinnedOrigin(): string | undefined {
  const f = pinFile();
  return existsSync(f) ? readFileSync(f, 'utf8').trim() : undefined;
}

/** 钉住之后只连这一台；钉住之前只允许 HTTPS，本机回环除外（测试用）。 */
function assertAllowed(u: URL): void {
  const pin = pinnedOrigin();
  if (pin) {
    if (u.origin !== pin) throw new Error('server_not_pinned');
    return;
  }
  const loopback = u.hostname === '127.0.0.1' || u.hostname === 'localhost';
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && loopback)) throw new Error('https_required');
}

/** 等用户确认的时间比界面的 60 秒自动拒绝长一点，这里只是界面挂死时的兜底。 */
const BROWSER_WAIT_MS = 95_000;
const BROWSER_QUICK_MS = 4_000;
const browserPending = new Map<number, (reply: unknown) => void>();
let browserSeq = 0;

/** 确认框要让用户看见。Windows 不让后台进程抢焦点，先置顶再取消。 */
function surface(): void {
  if (!win) return;
  if (win.isMinimized()) win.restore();
  win.show();
  win.setAlwaysOnTop(true);
  win.focus();
  win.setAlwaysOnTop(false);
}

function askRenderer(req: BrowserRequest): Promise<unknown> {
  if (!win) return Promise.resolve({ ok: false, error: 'locked' });
  const interactive = req.op === 'fill' || req.op === 'pick';
  if (interactive) surface();
  return new Promise((resolve) => {
    const id = ++browserSeq;
    const timer = setTimeout(() => {
      browserPending.delete(id);
      resolve({ ok: false, error: 'timeout' });
    }, interactive ? BROWSER_WAIT_MS : BROWSER_QUICK_MS);
    browserPending.set(id, (reply) => {
      clearTimeout(timer);
      browserPending.delete(id);
      resolve(reply);
    });
    win!.webContents.send('browser-request', id, req);
  });
}

interface HttpReq {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: Uint8Array;
}

function registerIpc(): void {
  ipcMain.handle('hw-status', (e) => {
    trusted(e);
    return { level: hw!.level, provider: hw!.provider };
  });
  ipcMain.handle('hw', (e, cmd: string, args: Record<string, unknown>) => {
    trusted(e);
    if (!['create', 'sign', 'seal', 'unseal', 'delete'].includes(cmd)) throw new Error('bad_command');
    return hw!.call(cmd, args);
  });
  ipcMain.handle('http', async (e, req: HttpReq) => {
    trusted(e);
    const u = new URL(req.url);
    assertAllowed(u);
    const res = await net.fetch(u.toString(), {
      method: req.method,
      headers: req.headers,
      redirect: 'error',
      cache: 'no-store',
      credentials: 'omit',
      // 卡死的请求不能让同步永远挂住；附件可能很慢，给足时间
      signal: AbortSignal.timeout(u.pathname.includes('/blobs/') ? 15 * 60_000 : 90_000),
      ...(req.body ? { body: Buffer.from(req.body) } : {}),
    });
    return { status: res.status, body: new Uint8Array(await res.arrayBuffer()) };
  });
  ipcMain.handle('pin-server', async (e, url: string) => {
    trusted(e);
    await writeFile(pinFile(), new URL(url).origin);
  });
  ipcMain.handle('unpin-server', async (e) => {
    trusted(e);
    await rm(pinFile(), { force: true });
  });
  ipcMain.handle('copy', async (e, text: string, seconds: number) => {
    trusted(e);
    const seq = await copySecret(text);
    const clear = async () => {
      pendingClears.delete(clear);
      if (seq !== undefined && hw) {
        // 按系统序列号判断：期间用户复制过别的内容就不动
        await hw.call('clipclear', { seq }).catch(() => undefined);
      } else if (clipboard.readText() === text) {
        clipboard.clear();
      }
    };
    pendingClears.add(clear);
    setTimeout(() => void clear(), Math.max(5, Math.min(seconds, 300)) * 1000);
  });
  ipcMain.handle('save-file', async (e, name: string, bytes: Uint8Array) => {
    trusted(e);
    const r = await dialog.showSaveDialog(win!, { defaultPath: name });
    if (r.canceled || !r.filePath) return false;
    await writeFile(r.filePath, bytes);
    return true;
  });
  ipcMain.handle('open-file', async (e, ext: string[]) => {
    trusted(e);
    const filters = ext[0] === '*' ? [] : [{ name: '文件', extensions: ext }];
    const r = await dialog.showOpenDialog(win!, { properties: ['openFile'], filters });
    const path = r.filePaths[0];
    if (r.canceled || !path) return null;
    if ((await stat(path)).size > 512 * 1024 * 1024) throw new Error('file_too_large');
    const bytes = await readFile(path);
    return { name: path.split(/[\\/]/).pop(), bytes: new Uint8Array(bytes) };
  });
  ipcMain.on('open-external', (e, url: string) => {
    trusted(e);
    const u = new URL(url);
    if (u.protocol === 'https:' || u.protocol === 'http:') void shell.openExternal(u.toString());
  });
  ipcMain.handle('browser-reply', (e, id: number, reply: unknown) => {
    trusted(e);
    browserPending.get(id)?.(reply);
  });
  ipcMain.on('hostname', (e) => {
    e.returnValue = hostname();
  });
}

/** Windows 上排除剪贴板历史和云剪贴板，由 TPM 助手一次写入，其他平台普通写入。 */
async function copySecret(text: string): Promise<number | undefined> {
  if (process.platform === 'win32' && hw?.level === 'hardware') {
    try {
      const r = (await hw.call('clip', { text })) as unknown as { seq: number };
      return r.seq;
    } catch {
      /* 退回普通写入 */
    }
  }
  clipboard.writeText(text);
  return undefined;
}

/**
 * 后台验收：窗口放到屏幕外、显示时不抢焦点，关掉遮挡检测和后台节流，画面照常渲染。
 * 用户在前台玩游戏或做别的事时跑测试用。正式包不读这个变量。
 */
const quietTest = !app.isPackaged && process.env.MIXIA_E2E_QUIET === '1';
if (quietTest) app.commandLine.appendSwitch('disable-features', 'CalculateNativeWinOcclusion');

function createWindow(ui: Session): void {
  // 界面只有深色，标题栏也要跟上
  nativeTheme.themeSource = 'dark';
  win = new BrowserWindow({
    width: 1200,
    height: 780,
    minWidth: 420,
    minHeight: 560,
    title: '密匣',
    show: false,
    ...(quietTest ? { x: -12000, y: -12000, skipTaskbar: true, focusable: true } : {}),
    autoHideMenuBar: true,
    backgroundColor: '#05060d',
    webPreferences: {
      preload: join(__dirname, 'preload.cjs'),
      session: ui,
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      webviewTag: false,
      spellcheck: false,
      devTools: !app.isPackaged,
      ...(quietTest ? { backgroundThrottling: false } : {}),
    },
  });
  // 屏幕录制和截图看不到密码。开发和验收可用环境变量关闭，正式包不读这个变量。
  win.setContentProtection(app.isPackaged || !process.env.MIXIA_ALLOW_CAPTURE);
  win.once('ready-to-show', () => (quietTest ? win?.showInactive() : win?.show()));
  win.webContents.on('will-navigate', (e) => e.preventDefault());
  win.webContents.on('will-attach-webview', (e) => e.preventDefault());
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  void win.loadURL(`${ORIGIN}/index.html`);
}

function startBrowserBridge(): void {
  const exe = app.isPackaged
    ? join(process.resourcesPath, 'mixia-nmhost.exe')
    : join(app.getAppPath(), 'native', 'nmhost', 'dist', 'mixia-nmhost.exe');
  if (process.platform !== 'win32' || !existsSync(exe)) return;
  browserBridge = new BrowserBridge(exe, askRenderer);
  browserBridge.start();
}

function lockAll(): void {
  win?.webContents.send('system-lock');
}

app.on('second-instance', () => {
  if (win?.isMinimized()) win.restore();
  win?.focus();
});

app.on('window-all-closed', () => app.quit());

let quitting = false;
app.on('will-quit', (e) => {
  if (quitting) return;
  quitting = true;
  e.preventDefault();
  void Promise.allSettled([...pendingClears].map((c) => c())).then(() => {
    browserBridge?.stop();
    hw?.stop();
    // 没有待清除的剪贴板时这里在微任务里就跑到了，Electron 还没退出 will-quit，这时 quit 是空操作，进程会留着
    setImmediate(() => app.quit());
  });
});

void app.whenReady().then(async () => {
  Menu.setApplicationMenu(null);
  // 界面用独立 session：这里除本地协议外什么都连不上。受控传输走主进程的默认 session。
  const ui = session.fromPartition('persist:mixia');
  ui.setPermissionRequestHandler((_w, _p, cb) => cb(false));
  ui.setPermissionCheckHandler(() => false);
  ui.webRequest.onBeforeRequest((d, cb) => {
    const ok =
      d.url.startsWith(`${ORIGIN}/`) ||
      d.url.startsWith('devtools://') ||
      d.url.startsWith('data:') ||
      d.url.startsWith('blob:');
    cb({ cancel: !ok });
  });
  ui.protocol.handle('app', serve);
  hw = await openHardware();
  registerIpc();
  startBrowserBridge();
  powerMonitor.on('lock-screen', lockAll);
  powerMonitor.on('suspend', lockAll);
  createWindow(ui);
});

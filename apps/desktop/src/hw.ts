/**
 * 硬件密钥。Windows 走 TPM 助手（mixia-hwkey.exe），私钥在芯片里不可导出。
 * 没有 TPM 或非 Windows 时退回系统钥匙串（safeStorage），等级标为 os，界面如实显示。
 */
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { app, safeStorage } from 'electron';

type Args = Record<string, unknown>;
type Result = Record<string, string>;

const b64url = (b: Buffer) => b.toString('base64url');

class HelperProcess {
  private child: ChildProcessWithoutNullStreams | undefined;
  private seq = 0;
  private pending = new Map<number, { ok: (r: Result) => void; fail: (e: Error) => void }>();
  private buffer = '';

  constructor(private exe: string) {}

  private start(): ChildProcessWithoutNullStreams {
    if (this.child) return this.child;
    const c = spawn(this.exe, [], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    c.stdout.setEncoding('utf8');
    c.stdout.on('data', (d: string) => {
      this.buffer += d;
      let i: number;
      while ((i = this.buffer.indexOf('\n')) >= 0) {
        const line = this.buffer.slice(0, i);
        this.buffer = this.buffer.slice(i + 1);
        if (!line.trim()) continue;
        const msg = JSON.parse(line) as { id: number; ok: boolean; result?: Result; error?: string };
        const p = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (!p) continue;
        if (msg.ok) p.ok(msg.result ?? {});
        else p.fail(new Error(msg.error ?? 'failed'));
      }
    });
    c.on('exit', () => {
      this.child = undefined;
      for (const p of this.pending.values()) p.fail(new Error('helper_exit'));
      this.pending.clear();
    });
    c.on('error', () => undefined);
    this.child = c;
    return c;
  }

  call(cmd: string, args: Args): Promise<Result> {
    const id = ++this.seq;
    const c = this.start();
    return new Promise((ok, fail) => {
      this.pending.set(id, { ok, fail });
      c.stdin.write(`${JSON.stringify({ id, cmd, args })}\n`);
    });
  }

  stop() {
    this.child?.stdin.end();
  }
}

/** 系统钥匙串退路：密钥可被同一系统用户的进程解开，没有硬件绑定。 */
class OsKeys {
  private dir = join(app.getPath('userData'), 'oskeys');
  private file = (name: string) => join(this.dir, `${name.replace(/[^\w-]/g, '')}.bin`);

  async call(cmd: string, a: Args): Promise<Result> {
    const name = a.name as string;
    switch (cmd) {
      case 'create': {
        const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
        const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
        await mkdir(this.dir, { recursive: true });
        await writeFile(this.file(name), safeStorage.encryptString(pem));
        return { authPub: this.pub(pem) };
      }
      case 'sign': {
        const pem = await this.pem(name);
        const sig = sign('sha256', Buffer.from(a.data as string, 'base64url'), {
          key: createPrivateKey(pem),
          dsaEncoding: 'ieee-p1363',
        });
        return { sig: b64url(sig) };
      }
      case 'seal':
        return { blob: b64url(safeStorage.encryptString(a.data as string)), alg: 'os' };
      case 'unseal':
        return { data: safeStorage.decryptString(Buffer.from(a.blob as string, 'base64url')) };
      case 'delete':
        await rm(this.file(name), { force: true });
        return {};
      default:
        throw new Error('bad_command');
    }
  }

  private async pem(name: string) {
    return safeStorage.decryptString(await readFile(this.file(name)));
  }

  private pub(pem: string): string {
    const der = createPublicKey(createPrivateKey(pem)).export({ type: 'spki', format: 'der' });
    return b64url(der.subarray(der.length - 65));
  }
}

export interface HwBackend {
  level: 'hardware' | 'os' | 'software';
  provider: string;
  call(cmd: string, args: Args): Promise<Result>;
  stop(): void;
}

function helperPath(): string {
  return app.isPackaged
    ? join(process.resourcesPath, 'mixia-hwkey.exe')
    : join(app.getAppPath(), 'native', 'hwkey', 'dist', 'mixia-hwkey.exe');
}

export async function openHardware(): Promise<HwBackend> {
  const exe = helperPath();
  if (process.platform === 'win32' && existsSync(exe)) {
    const h = new HelperProcess(exe);
    try {
      const st = (await h.call('status', {})) as unknown as { available: boolean; provider: string };
      if (st.available) {
        return { level: 'hardware', provider: st.provider, call: (c, a) => h.call(c, a), stop: () => h.stop() };
      }
    } catch {
      /* 落到系统钥匙串 */
    }
    h.stop();
  }
  const os = new OsKeys();
  return {
    level: safeStorage.isEncryptionAvailable() ? 'os' : 'software',
    provider: 'safeStorage',
    call: (c, a) => os.call(c, a),
    stop: () => undefined,
  };
}

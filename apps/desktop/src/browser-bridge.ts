/**
 * 浏览器扩展到界面的这一段。mixia-nmhost --serve 持有命名管道，这里读它的 stdout，
 * 校验之后转给渲染进程，库和判断都在渲染进程里。
 * 管道不在 Node 里建：Node 建的管道默认 Everyone 可读，也拿不到对端进程。
 */
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { parseBrowserRequest, type BrowserRequest } from '../../../packages/core/src/autofill';

interface Wire {
  conn: number;
  msg: { id?: unknown } & Record<string, unknown>;
}

export type Forward = (req: BrowserRequest) => Promise<unknown>;

export class BrowserBridge {
  private child: ChildProcessWithoutNullStreams | undefined;
  private buffer = '';

  constructor(
    private exe: string,
    private forward: Forward,
  ) {}

  start(): void {
    const c = spawn(this.exe, ['--serve'], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    c.stdout.setEncoding('utf8');
    c.stdout.on('data', (d: string) => this.read(d));
    c.stdin.on('error', () => undefined);
    c.on('error', () => undefined);
    c.on('exit', () => {
      this.child = undefined;
    });
    this.child = c;
  }

  private read(chunk: string): void {
    this.buffer += chunk;
    let i: number;
    while ((i = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, i);
      this.buffer = this.buffer.slice(i + 1);
      if (line.trim()) void this.handle(line);
    }
  }

  private async handle(line: string): Promise<void> {
    let w: Wire;
    try {
      w = JSON.parse(line) as Wire;
    } catch {
      return;
    }
    const { id, ...rest } = w.msg ?? {};
    if (typeof w.conn !== 'number' || typeof id !== 'number') return;
    const req = parseBrowserRequest(rest);
    const reply = req ? await this.forward(req).catch(() => ({ ok: false, error: 'timeout' })) : { ok: false, error: 'bad_request' };
    this.child?.stdin.write(`${JSON.stringify({ conn: w.conn, msg: { id, ...(reply as object) } })}\n`);
  }

  stop(): void {
    this.child?.stdin.end();
  }
}

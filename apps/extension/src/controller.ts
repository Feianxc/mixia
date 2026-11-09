/**
 * 扩展后台的全部逻辑。chrome.* 由 background.ts 接进来，这里可以脱离浏览器测试。
 *
 * 消息里除了 ref 没有任何参数：origin 和目标框架都由这里从浏览器报告的信息算出来。
 * 密码只在 fill 这一步经过，收到后转给发起请求的那个文档，不落盘、不缓存。
 */
import { isContent, isPopup, judgeFrame, type FrameRecord, type Sender, type Verdict } from './policy';

export interface Browser {
  frames(tabId: number): Promise<FrameRecord[] | null>;
  /** 只发给这一个文档：导航之后旧 documentId 收不到。 */
  send(tabId: number, documentId: string, msg: unknown): Promise<unknown>;
  activeTab(): Promise<number | undefined>;
  openPopup(): Promise<boolean>;
  badge(tabId: number, text: string): void;
}

export type NativeRequest = { op: 'status' } | { op: 'list' | 'pick'; origin: string } | { op: 'fill'; origin: string; ref: string };

export interface NativeReply {
  ok: boolean;
  error?: string;
  state?: string;
  items?: { ref: string; title: string; username: string }[];
  username?: string;
  password?: string;
}

export interface Native {
  request(req: NativeRequest): Promise<NativeReply>;
}

interface Session {
  tabId: number;
  frameId: number;
  documentId: string;
  topDocumentId: string;
  origin: string;
}

export class Controller {
  /** 用户在页面里点过图标、等弹窗接手的框架。 */
  private armed = new Map<number, Session>();
  /** 弹窗正在服务的会话。用一次就清掉。 */
  private current: Session | undefined;
  private filling = false;

  constructor(
    private extensionId: string,
    private browser: Browser,
    private native: Native,
  ) {}

  async handle(msg: unknown, sender: Sender): Promise<unknown> {
    const t = (msg as { t?: unknown } | null)?.t;
    if (isContent(sender, this.extensionId)) {
      if (t === 'can-fill') return this.canFill(sender);
      if (t === 'arm') return this.arm(sender);
      if (t === 'offer') return this.offer(sender);
    } else if (isPopup(sender, this.extensionId)) {
      if (t === 'open') return this.open();
      if (t === 'ping') return {};
      if (t === 'fill') {
        const ref = (msg as { ref?: unknown }).ref;
        return typeof ref === 'string' ? this.fill(ref) : { error: 'bad_request' };
      }
      if (t === 'pick') return this.fill();
    }
    return { error: 'forbidden' };
  }

  private async judge(sender: Sender): Promise<{ v: Verdict; frames: FrameRecord[] | null }> {
    const frames = await this.browser.frames(sender.tab!.id!);
    if (!frames) return { v: { ok: false, reason: 'no_frames' }, frames };
    return { v: judgeFrame(frames, sender.frameId!, sender.origin, sender.documentId), frames };
  }

  private async canFill(sender: Sender) {
    return { allowed: (await this.judge(sender)).v.ok };
  }

  private session(tabId: number, frameId: number, documentId: string, origin: string, frames: FrameRecord[]): Session | undefined {
    const topDocumentId = frames.find((f) => f.frameId === 0)?.documentId;
    return topDocumentId ? { tabId, frameId, documentId, topDocumentId, origin } : undefined;
  }

  /** 把这个框架登记为填充目标。origin 来自浏览器填的 sender，不看内容脚本说了什么。 */
  private async offer(sender: Sender) {
    const { v, frames } = await this.judge(sender);
    if (!v.ok) return { error: v.reason };
    const s = this.session(sender.tab!.id!, sender.frameId!, sender.documentId!, v.origin, frames!);
    if (!s) return { error: 'stale_document' };
    this.armed.set(s.tabId, s);
    return { ok: true };
  }

  private async arm(sender: Sender) {
    const r = await this.offer(sender);
    return 'error' in r ? r : { popup: await this.browser.openPopup() };
  }

  private take(tabId: number): Session | undefined {
    const s = this.armed.get(tabId);
    this.armed.delete(tabId);
    return s;
  }

  /** 工具栏点开时没有经过 arm：请每个框架里有登录框的内容脚本走一遍 offer，这样 origin 还是浏览器给的。 */
  private async probe(tabId: number): Promise<Session | undefined> {
    for (const f of (await this.browser.frames(tabId)) ?? []) {
      if (!f.documentId) continue;
      await this.browser.send(tabId, f.documentId, { t: 'probe' }).catch(() => null);
      const s = this.take(tabId);
      if (s) return s;
    }
    return undefined;
  }

  private async open() {
    const tabId = await this.browser.activeTab();
    if (tabId === undefined) return { error: 'no_form' };
    const armed = this.take(tabId);
    this.current = armed && (await this.stillThere(armed)) ? armed : await this.probe(tabId);
    if (!this.current) {
      const st = await this.native.request({ op: 'status' });
      return { error: 'no_form', state: st.ok ? st.state : st.error };
    }
    const r = await this.native.request({ op: 'list', origin: this.current.origin });
    return r.ok ? { origin: this.current.origin, items: r.items ?? [] } : { origin: this.current.origin, error: r.error };
  }

  /** 文档没换、框架判断还成立。documentId 不变时文档的 origin 也不会变。 */
  private async stillThere(s: Session): Promise<boolean> {
    const frames = await this.browser.frames(s.tabId);
    if (!frames) return false;
    const v = judgeFrame(frames, s.frameId, s.origin, s.documentId);
    return v.ok && v.origin === s.origin && frames.find((f) => f.frameId === 0)?.documentId === s.topDocumentId;
  }

  private async fill(ref?: string) {
    const s = this.current;
    if (!s) return { error: 'no_session' };
    if (this.filling) return { error: 'busy' };
    this.filling = true;
    this.current = undefined;
    try {
      const r = await this.native.request(ref === undefined ? { op: 'pick', origin: s.origin } : { op: 'fill', origin: s.origin, ref });
      if (!r.ok) return this.finish(s, r.error ?? 'failed');
      if (typeof r.password !== 'string') return this.finish(s, 'bad_reply');
      // 等确认的这段时间页面可能已经跳走：密码只给发起请求的那个文档
      if (!(await this.stillThere(s))) return this.finish(s, 'page_changed');
      const done = (await this.browser
        .send(s.tabId, s.documentId, { t: 'fill', username: r.username ?? '', password: r.password })
        .catch(() => null)) as { ok?: boolean; reason?: string } | null;
      return this.finish(s, done?.ok ? undefined : (done?.reason ?? 'page_changed'));
    } finally {
      this.filling = false;
    }
  }

  private finish(s: Session, error: string | undefined) {
    this.browser.badge(s.tabId, error ? '!' : '✓');
    return error ? { error } : { ok: true };
  }
}

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Controller, type Browser, type NativeReply, type NativeRequest } from '../src/controller';
import type { FrameRecord, Sender } from '../src/policy';

const ID = 'ikicghdoopckcolomkneepiooaengmep';
const A = 'https://a.example.com';
const B = 'https://evil.example.net';
const TAB = 7;
const popup: Sender = { id: ID, url: `chrome-extension://${ID}/popup.html` };
const page = (frameId: number, origin: string, documentId: string, extra: Partial<Sender> = {}): Sender => ({
  id: ID,
  url: `${origin}/login`,
  origin,
  tab: { id: TAB },
  frameId,
  documentId,
  ...extra,
});

/** 假浏览器：框架树可以中途改，记录所有发到页面的消息。 */
function setup(reply: (r: NativeRequest) => NativeReply | Promise<NativeReply> = () => ({ ok: true, items: [] })) {
  const state = {
    frames: [{ frameId: 0, parentFrameId: -1, url: `${A}/login`, documentId: 'top' }] as FrameRecord[] | null,
    sent: [] as { tabId: number; documentId: string; msg: { t: string; username?: string; password?: string } }[],
    requests: [] as NativeRequest[],
    popups: 0,
    badges: [] as string[],
    onProbe: undefined as undefined | ((documentId: string) => Promise<void>),
    fillAnswer: { ok: true } as unknown,
  };
  const browser: Browser = {
    frames: async () => state.frames,
    send: async (tabId, documentId, msg) => {
      const m = msg as { t: string };
      state.sent.push({ tabId, documentId, msg: m });
      if (m.t === 'probe') return state.onProbe?.(documentId);
      return state.fillAnswer;
    },
    activeTab: async () => TAB,
    openPopup: async () => {
      state.popups++;
      return true;
    },
    badge: (_t, text) => state.badges.push(text),
  };
  const c = new Controller(ID, browser, {
    request: async (r) => {
      state.requests.push(r);
      return reply(r);
    },
  });
  return { c, state };
}

const fills = (s: ReturnType<typeof setup>['state']) => s.sent.filter((x) => x.msg.t === 'fill');

describe('后台', () => {
  let t: ReturnType<typeof setup>;
  beforeEach(() => {
    t = setup((r) => {
      if (r.op === 'list') return { ok: true, items: [{ ref: 'v/i', title: 't', username: 'u' }] };
      if (r.op === 'status') return { ok: true, state: 'ready' };
      return { ok: true, username: 'user', password: 'SECRET' };
    });
  });

  it('点选到填入：origin 只来自浏览器', async () => {
    const { c, state } = t;
    expect(await c.handle({ t: 'arm', origin: B, url: B }, page(0, A, 'top'))).toEqual({ popup: true });
    expect(await c.handle({ t: 'open', origin: B }, popup)).toEqual({ origin: A, items: [{ ref: 'v/i', title: 't', username: 'u' }] });
    expect(await c.handle({ t: 'fill', ref: 'v/i', origin: B }, popup)).toEqual({ ok: true });
    expect(state.requests).toEqual([
      { op: 'list', origin: A },
      { op: 'fill', origin: A, ref: 'v/i' },
    ]);
    expect(fills(state)).toEqual([{ tabId: TAB, documentId: 'top', msg: { t: 'fill', username: 'user', password: 'SECRET' } }]);
  });

  it('跨源 iframe 不能发起', async () => {
    const { c, state } = t;
    state.frames!.push({ frameId: 3, parentFrameId: 0, url: `${B}/frame`, documentId: 'evil' });
    expect(await c.handle({ t: 'arm' }, page(3, B, 'evil'))).toEqual({ error: 'cross_origin_frame' });
    expect(await c.handle({ t: 'can-fill' }, page(3, B, 'evil'))).toEqual({ allowed: false });
    expect(state.popups).toBe(0);
    expect(await c.handle({ t: 'fill', ref: 'v/i' }, popup)).toEqual({ error: 'no_session' });
    expect(state.requests).toEqual([]);
  });

  it('同源 iframe 可以，密码只给那个框架', async () => {
    const { c, state } = t;
    state.frames!.push({ frameId: 3, parentFrameId: 0, url: `${A}/frame`, documentId: 'inner' });
    expect(await c.handle({ t: 'can-fill' }, page(3, A, 'inner'))).toEqual({ allowed: true });
    await c.handle({ t: 'arm' }, page(3, A, 'inner'));
    await c.handle({ t: 'open' }, popup);
    await c.handle({ t: 'fill', ref: 'v/i' }, popup);
    expect(fills(state).map((s) => s.documentId)).toEqual(['inner']);
  });

  it('内容脚本不能调弹窗的操作', async () => {
    const { c, state } = t;
    await c.handle({ t: 'arm' }, page(0, A, 'top'));
    await c.handle({ t: 'open' }, popup);
    for (const msg of [{ t: 'open' }, { t: 'fill', ref: 'v/i' }, { t: 'pick' }]) {
      expect(await c.handle(msg, page(0, A, 'top'))).toEqual({ error: 'forbidden' });
    }
    expect(state.requests).toEqual([{ op: 'list', origin: A }]);
  });

  it('弹窗不能调内容脚本的操作，来路不明的都拒绝', async () => {
    const { c, state } = t;
    expect(await c.handle({ t: 'arm' }, popup)).toEqual({ error: 'forbidden' });
    expect(await c.handle({ t: 'open' }, { ...popup, id: 'other' })).toEqual({ error: 'forbidden' });
    expect(await c.handle({ t: 'open' }, { ...popup, tab: { id: TAB } })).toEqual({ error: 'forbidden' });
    expect(await c.handle({ t: 'open' }, { id: ID, url: `chrome-extension://${ID}/x.html` })).toEqual({ error: 'forbidden' });
    expect(await c.handle({ t: 'exec', cmd: 'calc' }, popup)).toEqual({ error: 'forbidden' });
    expect(await c.handle({ t: 'ping' }, popup)).toEqual({});
    expect(await c.handle({ t: 'ping' }, page(0, A, 'top'))).toEqual({ error: 'forbidden' });
    expect(await c.handle(null, popup)).toEqual({ error: 'forbidden' });
    expect(state.requests).toEqual([]);
  });

  it('工具栏打开：由浏览器 sender 决定框架，内容脚本的回答不算数', async () => {
    const { c, state } = t;
    state.frames!.push({ frameId: 3, parentFrameId: 0, url: `${B}/frame`, documentId: 'evil' });
    const senders: Record<string, Sender> = { top: page(0, A, 'top'), evil: page(3, B, 'evil') };
    const seen: string[] = [];
    state.onProbe = async (doc) => {
      seen.push(doc);
      if (doc === 'evil') await c.handle({ t: 'offer', origin: A }, senders.evil!);
    };
    // 顶层没有登录框，跨源 iframe 有：不能填
    expect(await c.handle({ t: 'open' }, popup)).toEqual({ error: 'no_form', state: 'ready' });
    expect(seen).toEqual(['top', 'evil']);
    expect(state.requests).toEqual([{ op: 'status' }]);
    state.onProbe = async (doc) => {
      if (doc === 'top') await c.handle({ t: 'offer' }, senders.top!);
    };
    expect(await c.handle({ t: 'open' }, popup)).toMatchObject({ origin: A });
  });

  it('页面没有登录框时说明桌面端状态', async () => {
    const x = setup((r) => (r.op === 'status' ? { ok: false, error: 'desktop_unavailable' } : { ok: true }));
    expect(await x.c.handle({ t: 'open' }, popup)).toEqual({ error: 'no_form', state: 'desktop_unavailable' });
  });

  it('一次会话只换一次', async () => {
    const { c, state } = t;
    await c.handle({ t: 'arm' }, page(0, A, 'top'));
    await c.handle({ t: 'open' }, popup);
    expect(await c.handle({ t: 'fill', ref: 'v/i' }, popup)).toEqual({ ok: true });
    expect(await c.handle({ t: 'fill', ref: 'v/i' }, popup)).toEqual({ error: 'no_session' });
    expect(fills(state).length).toBe(1);
  });

  it('桌面拒绝不发密码', async () => {
    const x = setup((r) => (r.op === 'list' ? { ok: true, items: [] } : { ok: false, error: 'denied' }));
    await x.c.handle({ t: 'arm' }, page(0, A, 'top'));
    await x.c.handle({ t: 'open' }, popup);
    expect(await x.c.handle({ t: 'fill', ref: 'v/i' }, popup)).toEqual({ error: 'denied' });
    expect(fills(x.state)).toEqual([]);
    expect(x.state.badges).toEqual(['!']);
  });

  it('桌面回复没有密码就不发', async () => {
    const x = setup((r) => (r.op === 'list' ? { ok: true, items: [] } : { ok: true }));
    await x.c.handle({ t: 'arm' }, page(0, A, 'top'));
    await x.c.handle({ t: 'open' }, popup);
    expect(await x.c.handle({ t: 'fill', ref: 'v/i' }, popup)).toEqual({ error: 'bad_reply' });
    expect(fills(x.state)).toEqual([]);
  });

  it('等确认时页面跳到别的站点，密码不发出去', async () => {
    const x = setup((r) => {
      if (r.op === 'list') return { ok: true, items: [] };
      x.state.frames = [{ frameId: 0, parentFrameId: -1, url: `${B}/phish`, documentId: 'next' }];
      return { ok: true, username: 'u', password: 'SECRET' };
    });
    await x.c.handle({ t: 'arm' }, page(0, A, 'top'));
    await x.c.handle({ t: 'open' }, popup);
    expect(await x.c.handle({ t: 'fill', ref: 'v/i' }, popup)).toEqual({ error: 'page_changed' });
    expect(fills(x.state)).toEqual([]);
  });

  it('等确认时同站点换了文档，也不发', async () => {
    const x = setup((r) => {
      if (r.op === 'list') return { ok: true, items: [] };
      x.state.frames = [{ frameId: 0, parentFrameId: -1, url: `${A}/other`, documentId: 'next' }];
      return { ok: true, username: 'u', password: 'SECRET' };
    });
    await x.c.handle({ t: 'arm' }, page(0, A, 'top'));
    await x.c.handle({ t: 'open' }, popup);
    expect(await x.c.handle({ t: 'fill', ref: 'v/i' }, popup)).toEqual({ error: 'page_changed' });
    expect(fills(x.state)).toEqual([]);
  });

  it('等确认时顶层换了，框架文档号碰巧还在也不发', async () => {
    const x = setup((r) => {
      if (r.op === 'list') return { ok: true, items: [] };
      x.state.frames = [
        { frameId: 0, parentFrameId: -1, url: `${A}/other`, documentId: 'next' },
        { frameId: 3, parentFrameId: 0, url: `${A}/frame`, documentId: 'inner' },
      ];
      return { ok: true, username: 'u', password: 'SECRET' };
    });
    x.state.frames!.push({ frameId: 3, parentFrameId: 0, url: `${A}/frame`, documentId: 'inner' });
    await x.c.handle({ t: 'arm' }, page(3, A, 'inner'));
    await x.c.handle({ t: 'open' }, popup);
    expect(await x.c.handle({ t: 'fill', ref: 'v/i' }, popup)).toEqual({ error: 'page_changed' });
    expect(fills(x.state)).toEqual([]);
  });

  it('等确认时 iframe 换了文档，顶层没变也不发', async () => {
    const x = setup((r) => {
      if (r.op === 'list') return { ok: true, items: [] };
      x.state.frames = [
        { frameId: 0, parentFrameId: -1, url: `${A}/login`, documentId: 'top' },
        { frameId: 3, parentFrameId: 0, url: `${B}/phish`, documentId: 'swapped' },
      ];
      return { ok: true, username: 'u', password: 'SECRET' };
    });
    x.state.frames!.push({ frameId: 3, parentFrameId: 0, url: `${A}/frame`, documentId: 'inner' });
    await x.c.handle({ t: 'arm' }, page(3, A, 'inner'));
    await x.c.handle({ t: 'open' }, popup);
    expect(await x.c.handle({ t: 'fill', ref: 'v/i' }, popup)).toEqual({ error: 'page_changed' });
    expect(fills(x.state)).toEqual([]);
  });

  it('标签页已关闭', async () => {
    const x = setup((r) => {
      if (r.op === 'list') return { ok: true, items: [] };
      x.state.frames = null;
      return { ok: true, username: 'u', password: 'SECRET' };
    });
    await x.c.handle({ t: 'arm' }, page(0, A, 'top'));
    await x.c.handle({ t: 'open' }, popup);
    expect(await x.c.handle({ t: 'fill', ref: 'v/i' }, popup)).toEqual({ error: 'page_changed' });
    expect(fills(x.state)).toEqual([]);
  });

  it('打开弹窗前页面已经换了，旧的 arm 作废', async () => {
    const { c, state } = t;
    await c.handle({ t: 'arm' }, page(0, A, 'top'));
    state.frames = [{ frameId: 0, parentFrameId: -1, url: `${B}/phish`, documentId: 'next' }];
    expect(await c.handle({ t: 'open' }, popup)).toEqual({ error: 'no_form', state: 'ready' });
    expect(state.requests.some((r) => r.op === 'list')).toBe(false);
  });

  it('已有填充在等确认时再点拿到 busy', async () => {
    let release: (r: NativeReply) => void = () => undefined;
    const x = setup((r) => (r.op === 'list' ? { ok: true, items: [] } : new Promise((ok) => (release = ok))));
    await x.c.handle({ t: 'arm' }, page(0, A, 'top'));
    await x.c.handle({ t: 'open' }, popup);
    const first = x.c.handle({ t: 'fill', ref: 'v/i' }, popup);
    await vi.waitFor(() => expect(x.state.requests.length).toBe(2));
    await x.c.handle({ t: 'arm' }, page(0, A, 'top'));
    await x.c.handle({ t: 'open' }, popup);
    expect(await x.c.handle({ t: 'fill', ref: 'v/i' }, popup)).toEqual({ error: 'busy' });
    release({ ok: true, username: 'u', password: 'SECRET' });
    expect(await first).toEqual({ ok: true });
  });

  it('本地库走 pick，扩展看不到候选', async () => {
    const { c, state } = t;
    await c.handle({ t: 'arm' }, page(0, A, 'top'));
    await c.handle({ t: 'open' }, popup);
    expect(await c.handle({ t: 'pick' }, popup)).toEqual({ ok: true });
    expect(state.requests.at(-1)).toEqual({ op: 'pick', origin: A });
  });

  it('字段不见了，报页面说的原因', async () => {
    const { c, state } = t;
    state.fillAnswer = { ok: false, reason: 'no_field' };
    await c.handle({ t: 'arm' }, page(0, A, 'top'));
    await c.handle({ t: 'open' }, popup);
    expect(await c.handle({ t: 'fill', ref: 'v/i' }, popup)).toEqual({ error: 'no_field' });
  });

  it('ref 不是字符串', async () => {
    const { c } = t;
    await c.handle({ t: 'arm' }, page(0, A, 'top'));
    await c.handle({ t: 'open' }, popup);
    expect(await c.handle({ t: 'fill', ref: { a: 1 } }, popup)).toEqual({ error: 'bad_request' });
  });
});

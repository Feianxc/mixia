import { describe, expect, it } from 'vitest';
import { isContent, isPopup, judgeFrame, webOrigin, type FrameRecord } from '../src/policy';

const A = 'https://a.example.com';
const B = 'https://evil.example.net';
const frame = (frameId: number, parentFrameId: number, url: string, documentId = `doc-${frameId}`): FrameRecord => ({
  frameId,
  parentFrameId,
  url,
  documentId,
});

describe('框架判断', () => {
  const tree = [frame(0, -1, `${A}/login`), frame(1, 0, `${A}/inner`), frame(2, 0, `${B}/ad`), frame(3, 2, `${A}/framed`), frame(4, 1, `${A}/deep`)];

  it('顶层页面', () => {
    expect(judgeFrame(tree, 0, A, 'doc-0')).toEqual({ ok: true, origin: A });
  });

  it('同源 iframe，整条链都同源', () => {
    expect(judgeFrame(tree, 1, A, 'doc-1')).toEqual({ ok: true, origin: A });
    expect(judgeFrame(tree, 4, A, 'doc-4')).toEqual({ ok: true, origin: A });
  });

  it('跨源 iframe 不填', () => {
    expect(judgeFrame(tree, 2, B, 'doc-2')).toEqual({ ok: false, reason: 'cross_origin_frame' });
  });

  it('跨源 iframe 里自称同源也没用', () => {
    // sender.origin 由浏览器给，这里模拟被攻破的渲染进程只改得了 URL 记录以外的东西
    expect(judgeFrame(tree, 2, A, 'doc-2')).toEqual({ ok: false, reason: 'cross_origin_ancestor' });
  });

  it('同源页面被嵌在跨源框架里不填', () => {
    expect(judgeFrame(tree, 3, A, 'doc-3')).toEqual({ ok: false, reason: 'cross_origin_ancestor' });
  });

  it('沙箱 iframe：URL 同源但浏览器报告不透明来源', () => {
    expect(judgeFrame(tree, 1, 'null', 'doc-1')).toEqual({ ok: false, reason: 'cross_origin_frame' });
  });

  it('没有 sender.origin 不填', () => {
    expect(judgeFrame(tree, 0, undefined, 'doc-0')).toEqual({ ok: false, reason: 'cross_origin_frame' });
  });

  it('文档已经换了不填', () => {
    expect(judgeFrame(tree, 0, A, 'doc-old')).toEqual({ ok: false, reason: 'stale_document' });
    expect(judgeFrame(tree, 0, A, undefined)).toEqual({ ok: false, reason: 'stale_document' });
  });

  it('顶层不是网页不填', () => {
    for (const url of ['about:blank', 'chrome://settings', 'file:///c:/x.html', 'data:text/html,x', 'chrome-extension://abc/page.html']) {
      expect(judgeFrame([frame(0, -1, url)], 0, 'null', 'doc-0')).toEqual({ ok: false, reason: 'top_not_web' });
    }
  });

  it('框架树不完整不填', () => {
    expect(judgeFrame([], 0, A, 'doc-0')).toEqual({ ok: false, reason: 'no_top_frame' });
    expect(judgeFrame([frame(0, -1, A)], 9, A, 'doc-9')).toEqual({ ok: false, reason: 'unknown_frame' });
    expect(judgeFrame([frame(0, -1, A), frame(5, 7, A)], 5, A, 'doc-5')).toEqual({ ok: false, reason: 'broken_chain' });
    // 预渲染和 fenced frame 的 parentFrameId 是 -1，走不到顶层
    expect(judgeFrame([frame(0, -1, A), frame(6, -1, A)], 6, A, 'doc-6')).toEqual({ ok: false, reason: 'broken_chain' });
  });

  it('成环的框架树不填，也不死循环', () => {
    expect(judgeFrame([frame(0, -1, A), frame(1, 2, A), frame(2, 1, A)], 1, A, 'doc-1')).toEqual({ ok: false, reason: 'broken_chain' });
  });

  it('端口和协议都算 origin', () => {
    const t = [frame(0, -1, 'https://a.example.com/'), frame(1, 0, 'https://a.example.com:8443/'), frame(2, 0, 'http://a.example.com/')];
    expect(judgeFrame(t, 1, 'https://a.example.com:8443', 'doc-1').ok).toBe(false);
    expect(judgeFrame(t, 2, 'http://a.example.com', 'doc-2').ok).toBe(false);
  });

  it('webOrigin 只认网页', () => {
    expect(webOrigin('https://a.example.com:8443/x?y#z')).toBe('https://a.example.com:8443');
    expect(webOrigin('blob:https://a.example.com/uuid')).toBe(null);
    expect(webOrigin('nonsense')).toBe(null);
  });
});

describe('消息来源', () => {
  const ID = 'ikicghdoopckcolomkneepiooaengmep';
  const popup = `chrome-extension://${ID}/popup.html`;

  it('内容脚本', () => {
    expect(isContent({ id: ID, tab: { id: 3 }, frameId: 0 }, ID)).toBe(true);
    expect(isContent({ id: ID, tab: { id: 3 } }, ID)).toBe(false);
    expect(isContent({ id: ID, tab: {}, frameId: 0 }, ID)).toBe(false);
    expect(isContent({ id: ID, frameId: 0 }, ID)).toBe(false);
    expect(isContent({ id: 'other', tab: { id: 3 }, frameId: 0 }, ID)).toBe(false);
  });

  it('弹窗', () => {
    expect(isPopup({ id: ID, url: popup }, ID)).toBe(true);
    expect(isPopup({ id: ID, url: popup, tab: { id: 3 } }, ID)).toBe(false);
    expect(isPopup({ id: ID, url: `chrome-extension://${ID}/other.html` }, ID)).toBe(false);
    expect(isPopup({ id: 'other', url: popup }, ID)).toBe(false);
    expect(isPopup({ id: ID }, ID)).toBe(false);
  });
});

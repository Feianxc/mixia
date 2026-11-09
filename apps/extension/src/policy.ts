/**
 * 谁能发什么、哪个框架能填。这里的输入全部来自浏览器进程（sender、webNavigation），
 * 内容脚本说什么都不算数。
 */

export interface FrameRecord {
  frameId: number;
  parentFrameId: number;
  url: string;
  documentId?: string;
}

export interface Sender {
  id?: string;
  url?: string;
  origin?: string;
  tab?: { id?: number };
  frameId?: number;
  documentId?: string;
}

export type Verdict = { ok: true; origin: string } | { ok: false; reason: string };

const deny = (reason: string): Verdict => ({ ok: false, reason });

export function webOrigin(url: string): string | null {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.origin : null;
  } catch {
    return null;
  }
}

/**
 * 这个框架能不能填。顶层页面决定 origin；框架自身和它到顶层之间的每一层都必须与顶层同源：
 * 跨源 iframe 不填，同源页面被嵌在别人的框架里也不填。
 *
 * senderOrigin 是浏览器按文档算的 origin。沙箱 iframe 的 URL 看着同源，这里是 "null"，所以不能只看 URL。
 */
export function judgeFrame(
  frames: FrameRecord[],
  frameId: number,
  senderOrigin: string | undefined,
  documentId: string | undefined,
): Verdict {
  const byId = new Map(frames.map((f) => [f.frameId, f]));
  const top = byId.get(0);
  if (!top) return deny('no_top_frame');
  const origin = webOrigin(top.url);
  if (!origin) return deny('top_not_web');
  const self = byId.get(frameId);
  if (!self) return deny('unknown_frame');
  if (!documentId || self.documentId !== documentId) return deny('stale_document');
  if (senderOrigin !== origin) return deny('cross_origin_frame');
  const seen = new Set<number>();
  for (let f: FrameRecord | undefined = self; ; f = byId.get(f.parentFrameId)) {
    // 断链或成环都说明这棵树不可信
    if (!f || seen.has(f.frameId)) return deny('broken_chain');
    seen.add(f.frameId);
    if (webOrigin(f.url) !== origin) return deny('cross_origin_ancestor');
    if (f.frameId === 0) return { ok: true, origin };
  }
}

/** 内容脚本的消息：浏览器填的 sender.tab 证明它来自页面，只能调内容脚本那两个操作。 */
export function isContent(s: Sender, extensionId: string): boolean {
  return s.id === extensionId && s.tab?.id !== undefined && typeof s.frameId === 'number';
}

/** 弹窗的消息。把 popup.html 当普通标签页打开时有 sender.tab，不算弹窗。 */
export function isPopup(s: Sender, extensionId: string): boolean {
  return s.id === extensionId && s.tab === undefined && s.url === `chrome-extension://${extensionId}/popup.html`;
}

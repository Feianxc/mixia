/**
 * 内容脚本：认出登录框，放一个小图标，把后台发来的账号密码写进字段。
 * 这里没有任何判断权：页面能不能填由后台按浏览器报告的信息决定。
 * 脚本跑在隔离环境，页面拿不到这里的变量，图标放在 closed shadow 里。
 */

interface Fields {
  password: HTMLInputElement;
  username: HTMLInputElement | null;
}

/** 看不见的字段不填：隐藏表单是偷填充的常见手法。祖先透明同样算看不见。 */
function visible(el: HTMLElement): boolean {
  if (!el.isConnected) return false;
  const r = el.getBoundingClientRect();
  if (r.width < 8 || r.height < 8) return false;
  if (r.right + scrollX <= 0 || r.bottom + scrollY <= 0) return false;
  for (let e: HTMLElement | null = el; e; e = e.parentElement) {
    const s = getComputedStyle(e);
    if (s.display === 'none' || s.visibility === 'hidden' || Number(s.opacity) < 0.1) return false;
  }
  return true;
}

const USER_TYPES = new Set(['text', 'email', 'tel', '']);

/** 密码框前面最近的那个可见文本框。 */
function usernameFor(password: HTMLInputElement): HTMLInputElement | null {
  const scope: ParentNode = password.form ?? document;
  let last: HTMLInputElement | null = null;
  for (const el of scope.querySelectorAll('input')) {
    if (el === password) break;
    if (USER_TYPES.has(el.getAttribute('type')?.toLowerCase() ?? '') && !el.readOnly && !el.disabled && visible(el)) last = el;
  }
  return last;
}

function findFields(): Fields | null {
  const all = [...document.querySelectorAll<HTMLInputElement>('input[type=password]')].filter((el) => !el.disabled && !el.readOnly && visible(el));
  const password = all.find((el) => el === document.activeElement) ?? all[0];
  return password ? { password, username: usernameFor(password) } : null;
}

/** 走这个隔离环境里干净的 setter，再发事件，React 这类框架才看得到改动。 */
function put(el: HTMLInputElement, value: string): void {
  const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
  el.focus();
  set.call(el, value);
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
}

let target: Fields | null = null;

function fill(username: string, password: string): { ok: boolean; reason?: string } {
  const t = target;
  target = null;
  if (!t || !visible(t.password)) return { ok: false, reason: 'no_field' };
  if (username && t.username && visible(t.username)) put(t.username, username);
  put(t.password, password);
  return { ok: true };
}

chrome.runtime.onMessage.addListener((msg: { t?: string; username?: string; password?: string }, sender, reply) => {
  // 只听自己后台的：没有 tab 的才是后台，别的内容脚本发不到这里
  if (sender.id !== chrome.runtime.id || sender.tab) return;
  if (msg.t === 'probe') {
    target = findFields();
    if (!target) return void reply({});
    // 回一条新消息而不是直接回答：这样后台拿到的是浏览器填的 sender
    void chrome.runtime.sendMessage({ t: 'offer' }).finally(() => reply({}));
    return true;
  }
  if (msg.t === 'fill') reply(fill(msg.username ?? '', msg.password ?? ''));
  return undefined;
});

// —— 图标 ——

let host: HTMLElement | undefined;
let anchored: Fields | null = null;

function makeIcon(): HTMLElement {
  const el = document.createElement('div');
  el.setAttribute('data-mixia', '');
  el.style.cssText = 'all:initial;position:fixed;z-index:2147483647;width:22px;height:22px;display:none';
  const b = document.createElement('button');
  b.type = 'button';
  b.title = '用密匣填充';
  b.textContent = '匣';
  b.style.cssText =
    // 一个小黑洞：黑色视界、金色光环，和密匣的标志一致
    'all:initial;display:block;width:22px;height:22px;border-radius:50%;' +
    'background:radial-gradient(circle,#000 0 52%,#1b1330 78%,#2a1a3a);color:#f6cf98;' +
    'box-shadow:0 0 0 1px rgba(243,197,138,.8),0 0 9px rgba(255,170,90,.5);' +
    'font:600 12px/22px "Microsoft YaHei",sans-serif;text-align:center;cursor:pointer';
  b.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (!anchored) return;
    target = anchored;
    void chrome.runtime.sendMessage({ t: 'arm' }).then((r: { popup?: boolean; error?: string } | undefined) => {
      if (r?.popup === false) b.title = '点浏览器工具栏上的密匣图标';
    });
  });
  el.attachShadow({ mode: 'closed' }).append(b);
  document.documentElement.append(el);
  return el;
}

function place(): void {
  if (!host) return;
  const f = anchored;
  if (!f || !visible(f.password)) {
    host.style.display = 'none';
    return;
  }
  const r = f.password.getBoundingClientRect();
  host.style.left = `${r.right - 26}px`;
  host.style.top = `${r.top + (r.height - 22) / 2}px`;
  host.style.display = 'block';
}

let allowed: boolean | undefined;

async function scan(): Promise<void> {
  if (allowed === false) return;
  const f = findFields();
  if (!f) {
    anchored = null;
    place();
    return;
  }
  // 只有真的看到密码框才去问后台，普通页面不唤醒 Service Worker
  if (allowed === undefined) {
    const r = (await chrome.runtime.sendMessage({ t: 'can-fill' }).catch(() => null)) as { allowed?: boolean } | null;
    allowed = !!r?.allowed;
  }
  if (!allowed) return;
  anchored = f;
  host ??= makeIcon();
  place();
}

let queued = false;
const later = () => {
  if (queued) return;
  queued = true;
  setTimeout(() => {
    queued = false;
    void scan();
  }, 250);
};

void scan();
new MutationObserver(later).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['style', 'class', 'type', 'hidden'] });
addEventListener('scroll', place, { passive: true, capture: true });
addEventListener('resize', place, { passive: true });
addEventListener('focusin', later, { passive: true });

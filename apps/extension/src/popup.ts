/**
 * 弹窗是浏览器自己的窗口：页面盖不住、嵌不进去，这是不把选择层做成页内 iframe 的原因。
 * 弹窗失去焦点就会关闭，所以等确认和填入都在后台做，这里只负责选。
 */

interface Item {
  ref: string;
  title: string;
  username: string;
}

interface Opened {
  origin?: string;
  items?: Item[];
  error?: string;
  state?: string;
}

const TEXT: Record<string, string> = {
  desktop_unavailable: '连不上密匣桌面端。确认它已安装并正在运行。',
  locked: '密匣已锁定。到桌面窗口解锁后再试。',
  no_form: '这个页面没有可以填充的登录框。跨域 iframe 里的表单不会填。',
  busy: '桌面端还在等你确认上一次请求。',
  denied: '已取消。',
  no_match: '这个账号不属于当前网站。',
  page_changed: '页面已经变了，没有填入。',
  no_field: '登录框已经不在页面上了。',
  timeout: '桌面端没有响应。',
};
const textOf = (code: string) => TEXT[code] ?? `操作失败（${code}）`;

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const site = $('site');
const search = $<HTMLInputElement>('search');
const list = $('list');
const note = $('note');
const desk = $<HTMLButtonElement>('desk');

function say(text: string): void {
  note.textContent = text;
  note.hidden = !text;
}

async function run(msg: unknown): Promise<void> {
  search.disabled = true;
  desk.disabled = true;
  list.replaceChildren();
  say('请到密匣桌面窗口确认…');
  const r = (await chrome.runtime.sendMessage(msg)) as { ok?: boolean; error?: string };
  if (r?.ok) window.close();
  else say(textOf(r?.error ?? 'failed'));
}

function render(items: Item[]): void {
  const q = search.value.trim().toLowerCase();
  const shown = q ? items.filter((i) => `${i.title}\n${i.username}`.toLowerCase().includes(q)) : items;
  list.replaceChildren(
    ...shown.map((i) => {
      const b = document.createElement('button');
      b.className = 'row';
      const t = document.createElement('span');
      t.className = 't';
      t.textContent = i.title;
      const s = document.createElement('span');
      s.className = 's';
      s.textContent = i.username;
      b.append(t, s);
      b.addEventListener('click', () => void run({ t: 'fill', ref: i.ref }));
      return b;
    }),
  );
  say(shown.length ? '' : items.length ? '没有符合的账号' : '云库里没有这个网站的账号。重要本地库的账号请到桌面端选择。');
}

async function start(): Promise<void> {
  const r = (await chrome.runtime.sendMessage({ t: 'open' })) as Opened;
  site.textContent = r.origin ?? '';
  if (r.error) {
    // 没有登录框时顺带说明桌面端的状态，免得用户以为只是页面的问题
    const extra = r.state && r.state !== 'ready' ? `\n${textOf(r.state)}` : '';
    say(`${textOf(r.error)}${extra}`);
    return;
  }
  const items = r.items ?? [];
  search.hidden = false;
  desk.hidden = false;
  search.addEventListener('input', () => render(items));
  desk.addEventListener('click', () => void run({ t: 'pick' }));
  render(items);
  search.focus();
}

// Service Worker 闲置 30 秒就会被停掉，会话在它的内存里。用户在弹窗里慢慢选的时候要让它活着
setInterval(() => void chrome.runtime.sendMessage({ t: 'ping' }), 20_000);

void start();

/**
 * 桌面端处理浏览器扩展请求。这里是拿到密码之前的最后一道判断：
 * 请求里的 origin 由浏览器报告，但条目能不能给它、用户有没有点头，都在这里重新算一遍。
 */
import { bestMatch, parseBrowserRequest, type SiteMatch } from './autofill';
import { listItems, type ItemView } from './model';
import type { Policy, Vault } from './vault';

/** 列给扩展看的最多条数。native messaging 单条回复有 1 MB 上限。 */
const LIST_LIMIT = 50;

export interface FillChoice {
  ref: string;
  title: string;
  username: string;
  policy: Policy;
  match: Exclude<SiteMatch, null>;
}

export interface BrowserFillUi {
  /** 用户亲自确认这一条。 */
  confirm(origin: string, choice: FillChoice): Promise<boolean>;
  /** 在桌面上选账号。选之前可能要先解锁本地库，所以传函数不传列表。 */
  choose(origin: string, load: () => FillChoice[]): Promise<string | null>;
}

export type BrowserError = 'bad_request' | 'locked' | 'no_match' | 'denied' | 'busy';

export type BrowserReply =
  | { ok: true; state: 'ready' | 'locked' }
  | { ok: true; items: { ref: string; title: string; username: string }[] }
  | { ok: true; username: string; password: string }
  | { ok: false; error: BrowserError };

const fail = (error: BrowserError): BrowserReply => ({ ok: false, error });

interface Candidate extends FillChoice {
  item: ItemView;
}

export class BrowserFill {
  private busy = false;

  constructor(
    private m: { phase: string; openVaults(): Vault[] },
    private ui: BrowserFillUi,
  ) {}

  private get unlocked(): boolean {
    return this.m.phase === 'unlocked';
  }

  /** 冷库不参与。按库自己的策略判断，不靠条目上的标记。 */
  private candidates(origin: string): Candidate[] {
    const out: Candidate[] = [];
    for (const v of this.m.openVaults()) {
      if (v.policy === 'cold') continue;
      for (const item of listItems(v)) {
        if (!item.data.password) continue;
        const match = bestMatch(item.data.urls, origin);
        if (!match) continue;
        out.push({
          ref: `${v.id}/${item.id}`,
          title: item.data.title,
          username: item.data.username ?? '',
          policy: v.policy,
          match,
          item,
        });
      }
    }
    return out;
  }

  async handle(raw: unknown): Promise<BrowserReply> {
    const req = parseBrowserRequest(raw);
    if (!req) return fail('bad_request');
    if (req.op === 'status') return { ok: true, state: this.unlocked ? 'ready' : 'locked' };
    if (!this.unlocked) return fail('locked');
    if (req.op === 'list') {
      // 本地库的条目不提前给扩展看：标题和用户名也不离开桌面窗口
      const items = this.candidates(req.origin)
        .filter((c) => c.policy === 'cloud')
        .slice(0, LIST_LIMIT)
        .map(({ ref, title, username }) => ({ ref, title, username }));
      return { ok: true, items };
    }
    if (this.busy) return fail('busy');
    this.busy = true;
    try {
      const { origin } = req;
      const ref = req.op === 'fill' ? req.ref : await this.ui.choose(origin, () => this.choices(origin));
      if (!ref) return fail('denied');
      const chosen = this.candidates(origin).find((c) => c.ref === ref);
      if (!chosen) return fail('no_match');
      // 扩展只能点云库条目，本地库必须在桌面上选
      if (req.op === 'fill' && chosen.policy !== 'cloud') return fail('no_match');
      if (!(await this.ui.confirm(origin, this.choice(chosen)))) return fail('denied');
      // 等用户的这段时间可能已经锁定，或条目被改了网址
      if (!this.unlocked) return fail('locked');
      const now = this.candidates(origin).find((c) => c.ref === ref);
      if (!now) return fail('no_match');
      return { ok: true, username: now.item.data.username ?? '', password: now.item.data.password ?? '' };
    } finally {
      this.busy = false;
    }
  }

  private choice({ ref, title, username, policy, match }: Candidate): FillChoice {
    return { ref, title, username, policy, match };
  }

  private choices(origin: string): FillChoice[] {
    return this.candidates(origin).map((c) => this.choice(c));
  }
}

/**
 * 手机自动填充的候选。系统把请求交给密匣，用户在选择框里确认用哪一条；这里决定哪些条目能出现、哪些被推荐。
 * 站点规则和电脑扩展是同一套（autofill.ts），手机只是拿不到协议和端口。
 */
import { bestMatch, phoneOrigin, type SiteMatch } from './autofill';
import { listItems, type ItemView } from './model';
import type { Policy, Vault } from './vault';

export interface PhoneFillRequest {
  /** 网站域名，或发起请求的 App 包名。 */
  target: string;
  /** web 只在请求来自白名单浏览器的 https 页面时才有，由 Android 端判断。 */
  kind: 'web' | 'app';
}

export interface PhoneFillEntry {
  item: ItemView;
  policy: Policy;
  match: SiteMatch;
}

export interface PhoneFillChoices {
  /** 能填的全部条目，手动搜索就在这里面搜。 */
  items: PhoneFillEntry[];
  /** 推荐给这个网站的条目。 */
  suggested: PhoneFillEntry[];
}

/** 冷库按库自己的策略排除，不靠按 ID 去库列表里查：查不到时不能当成云库放行。 */
export function phoneFillChoices(vaults: readonly Vault[], req: PhoneFillRequest): PhoneFillChoices {
  // 普通 App 自报的网站不可信，不推荐，让用户自己搜
  const origin = req.kind === 'web' ? phoneOrigin(req.target) : null;
  const items: PhoneFillEntry[] = [];
  for (const v of vaults) {
    if (v.policy === 'cold') continue;
    for (const item of listItems(v)) {
      if (!item.data.password) continue;
      items.push({ item, policy: v.policy, match: origin ? bestMatch(item.data.urls, origin) : null });
    }
  }
  return { items, suggested: items.filter((e) => e.match) };
}

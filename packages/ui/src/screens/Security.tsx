import { ArrowLeft } from 'lucide-react';
import { keyOverview, securityReport, type ItemView } from '@mixia/core';
import { useApp } from '../state';
import type { Route } from './Main';

export function SecurityPage({ go }: { go: (r: Route) => void }) {
  const { m } = useApp();
  const r = securityReport(m.allItems());
  const vaults = m.vaults();
  const k = keyOverview(m.allItems(), (id) => vaults.find((v) => v.id === id)?.policy === 'cloud');
  const openItem = (i: ItemView) => go({ p: 'item', vaultId: i.vaultId, id: i.id });
  const Group = ({ title, hint, items }: { title: string; hint: string; items: ItemView[] }) =>
    items.length === 0 ? null : (
      <>
        <h2>{title}（{items.length}）</h2>
        <p className="muted small" style={{ marginBottom: 8 }}>{hint}</p>
        <div className="listcard">
          {items.slice(0, 50).map((i) => (
            <button key={i.vaultId + i.id} className="row-item" onClick={() => openItem(i)}>
              <span className="grow truncate">{i.data.title}</span>
              <span className="muted small">{m.vaultDisplayName(i.vaultId)}</span>
            </button>
          ))}
        </div>
      </>
    );
  const clean =
    !r.weak.length &&
    !r.reused.length &&
    !r.stale.length &&
    !r.noTotp.length &&
    !r.exposed.length &&
    !k.expired.length &&
    !k.expiring.length &&
    !k.rotate.length &&
    !k.cloudProduction.length &&
    !k.duplicates.length;
  return (
    <div className="page">
      <button className="iconbtn only-mobile" aria-label="返回" onClick={() => go({ p: 'none' })}><ArrowLeft size={20} /></button>
      <h1>安全检查</h1>
      <p className="lead">全部在本机计算，只覆盖已解锁的库，不查询任何外部泄露库。</p>
      {clean && <p>没有发现需要处理的问题。</p>}
      <Group title="已过期的密钥" hint="依赖它们的服务可能已经出问题了。" items={k.expired} />
      <Group title="快到期的密钥" hint="30 天内到期。" items={k.expiring} />
      <Group title="该轮换的密钥" hint="超过了你设的轮换周期。" items={k.rotate} />
      <Group title="云库里的生产密钥" hint="建议移到重要本地库。" items={k.cloudProduction} />
      <Group title="重复保存的密钥" hint="换的时候容易漏掉其中一条。" items={k.duplicates.flat()} />
      <Group title="曾进入云端" hint="这些条目从云库移回了本地。到原系统改一次密码，才算真正离开云端。" items={r.exposed} />
      <Group title="弱密码" hint="容易被猜中，建议换成生成的密码。" items={r.weak} />
      <Group title="重复使用的密码" hint="一个站点泄露会牵连其他站点。" items={r.reused.flat()} />
      <Group title="生产环境未开两步验证" hint="标记为生产环境的登录项没有保存两步验证。" items={r.noTotp} />
      <Group title="超过一年没换" hint="长期不换的密码，建议轮换。" items={r.stale} />
    </div>
  );
}

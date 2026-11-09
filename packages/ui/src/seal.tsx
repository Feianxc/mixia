import type { Policy } from '@mixia/core';
import { SEAL_GLYPHS } from './seal-glyphs';

/**
 * 星印：三类库的标记。圆形是轨道，承载真实信息——这条数据归哪个安全域。
 *
 * 云库是一圈轨道带一颗卫星：数据会在你批准的设备之间往返；
 * 本地库是实心的恒星，分量最重，哪儿也不去；
 * 冷库是双层封环，封存不动。
 */
const CHAR: Record<Policy, string> = { cloud: '云', local: '本', cold: '冷' };
export const POLICY_LABEL: Record<Policy, string> = {
  cloud: '云同步库',
  local: '重要本地库',
  cold: '离线冷库',
};
export const POLICY_HINT: Record<Policy, string> = {
  cloud: '加密后同步到你批准的设备',
  local: '只留在这台设备，绝不上云',
  cold: '只存在你保管的离线文件里',
};

/** 圆心 60、半径 r 的一段圆弧，角度单位是度，0 度朝右、顺时针 */
function arc(r: number, from: number, to: number) {
  const p = (a: number) => [60 + r * Math.cos((a * Math.PI) / 180), 60 + r * Math.sin((a * Math.PI) / 180)].map((n) => n.toFixed(2)).join(' ');
  return `M ${p(from)} A ${r} ${r} 0 ${to - from > 180 ? 1 : 0} 1 ${p(to)}`;
}
const ORBIT = arc(51, -24, 270 + 3);
const MOON = { x: 60 + 51 * Math.cos((-55 * Math.PI) / 180), y: 60 + 51 * Math.sin((-55 * Math.PI) / 180) };

export function Seal({ policy, size = 22, title }: { policy: Policy; size?: number; title?: string }) {
  const color = `var(--${policy})`;
  const glyph = SEAL_GLYPHS[CHAR[policy]]!;
  return (
    <svg
      className="seal"
      width={size}
      height={size}
      viewBox="0 0 120 120"
      role="img"
      aria-label={title ?? POLICY_LABEL[policy]}
    >
      <title>{title ?? POLICY_LABEL[policy]}</title>
      {policy === 'local' && <circle cx="60" cy="60" r="56" fill={color} />}
      {policy === 'cloud' && (
        <>
          <path d={ORBIT} fill="none" stroke={color} strokeWidth="8" strokeLinecap="round" />
          <circle cx={MOON.x} cy={MOON.y} r="10" fill={color} />
        </>
      )}
      {policy === 'cold' && (
        <>
          <circle cx="60" cy="60" r="53" fill="none" stroke={color} strokeWidth="6" />
          <circle cx="60" cy="60" r="42" fill="none" stroke={color} strokeWidth="2.6" />
        </>
      )}
      <g transform={policy === 'cold' ? 'translate(31 31) scale(.58)' : policy === 'local' ? 'translate(22 22) scale(.76)' : 'translate(25 25) scale(.7)'}>
        <path d={glyph} fill={policy === 'local' ? 'var(--seal-on)' : color} />
      </g>
    </svg>
  );
}

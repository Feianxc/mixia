import type { View } from './engine';

/**
 * 镜头：每个阶段在第 t 毫秒时相机在哪、看到什么。纯函数，场景层和验收工具共用。
 */

export type Stage = 'intro' | 'idle' | 'dive' | 'emerge' | 'off';
export type Variant = 'hero' | 'backdrop';
/** 镜头取景：主视觉页还要知道卡片上方留出了多高的空间 */
export interface Shot {
  kind: Variant;
  room: number;
}

export const INTRO_MS = 3300;
export const EMERGE_MS = 1150;
export const DIVE_MS = 820;
/** 坠入后再等主界面的入场动画放完，才卸掉入口页 */
export const DIVE_TOTAL_MS = 1600;
/** 主界面在坠入途中挂载，画面已经开始变暗，首帧渲染的卡顿看不出来 */
export const MAIN_AT_MS = 420;

export const clamp01 = (x: number) => Math.min(1, Math.max(0, x));
export const seg = (t: number, a: number, b: number) => clamp01((t - a) / (b - a));
export const lerp = (a: number, b: number, k: number) => a + (b - a) * k;
export const outCubic = (k: number) => 1 - (1 - k) ** 3;
export const inCubic = (k: number) => k * k * k;
export const inOut = (k: number) => (k < 0.5 ? 4 * k * k * k : 1 - (-2 * k + 2) ** 3 / 2);

export interface Frame {
  dist: number;
  fov: number;
  shiftX: number;
  shiftY: number;
  exposure: number;
  incl: number;
}

/**
 * 黑洞在画面上的位置和大小。
 * 主视觉页：放在卡片上方空出来的那块正中，尽量大，但光环不碰到卡片、吸积盘不出屏幕两边。
 * 表单页：宽屏让到卡片左边；竖屏退到卡片后面变暗。
 */
export function framing(w: number, h: number, shot: Shot): Frame {
  const portrait = h > w * 1.15;
  const short = Math.min(w, h);
  const at = (fromTop: number) => ((0.5 - fromTop) * h) / (0.5 * short);
  const variant = shot.kind;
  if (variant === 'hero' && shot.room > 80) {
    // 实测：距离 28 时光环上下各占约 0.154 弧度，吸积盘左右各占约 0.316 弧度
    const half = 0.5 * short;
    const fitV = (0.154 * half * 2 * 1.18) / shot.room;
    const fitW = (0.316 * half) / (0.47 * w);
    const fov = Math.min(0.62, Math.max(0.34, fitV, fitW));
    return { dist: 28, fov, shiftX: 0, shiftY: (0.5 * h - shot.room * 0.5) / half, exposure: 1, incl: 0.13 };
  }
  if (variant === 'backdrop') {
    // 宽屏上黑洞让到卡片左边，镜头从首页滑过去；竖屏放不下，就退到卡片后面变暗
    if (!portrait && w > 1000) {
      const x = ((Math.max(0.16, 0.5 - (560 / 2 + 40) / w - 0.12) - 0.5) * w) / (0.5 * short);
      return { dist: 30, fov: 0.46, shiftX: x, shiftY: at(0.36), exposure: 0.85, incl: 0.15 };
    }
    return { dist: 34, fov: portrait ? 0.5 : 0.42, shiftX: 0, shiftY: at(portrait ? 0.3 : 0.38), exposure: 0.62, incl: 0.16 };
  }
  return { dist: 28, fov: portrait ? 0.47 : 0.44, shiftX: 0, shiftY: at(portrait ? 0.25 : 0.3), exposure: 1, incl: 0.13 };
}

/** 虫洞时间点（毫秒）：边缘扫过屏幕、穿过喉部、换成黑洞 */
const RIM_MS = 1350;
const THROAT_MS = 1800;
const SWAP_MS = 1900;

function bump(t: number, at: number, width: number) {
  return Math.exp(-(((t - at) / width) ** 2));
}

export function shot(stage: Stage, t: number, f: Frame): View {
  const v: View = {
    dist: f.dist,
    incl: f.incl,
    yaw: 0,
    roll: 0,
    shiftX: f.shiftX,
    shiftY: f.shiftY,
    fov: f.fov,
    streak: 0,
    worm: 0,
    wl: 9,
    aberr: 0,
    ripple: -1,
    fade: 0,
    exposure: f.exposure,
  };
  if (stage === 'intro') {
    // 虫洞：一开场就在冲向它，球迅速变大；边缘扫过屏幕时扭曲最猛；然后冲过喉部
    if (t < RIM_MS) v.wl = lerp(6.5, 2.2, inOut(seg(t, 0, RIM_MS)));
    else if (t < THROAT_MS) v.wl = lerp(2.2, 0, inCubic(seg(t, RIM_MS, THROAT_MS)) * 0.6 + seg(t, RIM_MS, THROAT_MS) * 0.4);
    else v.wl = lerp(0, -4, outCubic(seg(t, THROAT_MS, SWAP_MS + 500)));
    v.worm = 1 - inOut(seg(t, SWAP_MS, SWAP_MS + 380));
    // 推拉变焦：冲向喉部时视野猛地变宽，背景被拉长，像空间被拽开
    v.fov = f.fov * (1 + 0.95 * bump(t, (RIM_MS + THROAT_MS) / 2 + 60, 300));
    // 镜头绕视线拧一下，穿过喉部时最大，出来以后摆正
    v.roll = 0.42 * Math.sin(Math.PI * seg(t, 0, SWAP_MS + 300));
    v.aberr = bump(t, (RIM_MS + THROAT_MS) / 2, 320);
    v.ripple = t > RIM_MS && t < RIM_MS + 1100 ? (t - RIM_MS) / 1100 : -1;
    v.streak = t < THROAT_MS ? 0.25 + 0.75 * inCubic(seg(t, 0, THROAT_MS)) : 1 - outCubic(seg(t, THROAT_MS, 2900));
    // 黑洞：穿出来就看见它，从远处拉近，最后挪到卡片上方
    v.dist = lerp(60, f.dist, outCubic(seg(t, SWAP_MS - 100, INTRO_MS - 100)));
    // 卡片出现前黑洞要已经升到位，不能和标题叠在一起
    const center = inOut(seg(t, SWAP_MS + 150, INTRO_MS - 450));
    v.shiftX = lerp(0, f.shiftX, center);
    v.shiftY = lerp(0, f.shiftY, center);
    v.exposure = f.exposure * lerp(0.9, 1, seg(t, SWAP_MS, SWAP_MS + 600)) * (1 + 0.35 * bump(t, THROAT_MS, 180));
    v.fade = 1 - seg(t, 0, 250);
  } else if (stage === 'emerge') {
    const k = outCubic(seg(t, 0, EMERGE_MS));
    const center = inOut(seg(t, 250, EMERGE_MS));
    v.fade = 1 - outCubic(seg(t, 0, 460));
    v.dist = lerp(2.6, f.dist, k);
    v.streak = 0.85 * (1 - seg(t, 120, 1000));
    v.aberr = 0.6 * (1 - seg(t, 100, 700));
    v.shiftX = lerp(0, f.shiftX, center);
    v.shiftY = lerp(0, f.shiftY, center);
  } else if (stage === 'dive') {
    const k = inCubic(seg(t, 0, DIVE_MS - 60));
    const center = inOut(seg(t, 0, 520));
    v.dist = lerp(f.dist, 1.9, k);
    v.shiftX = lerp(f.shiftX, 0, center);
    v.shiftY = lerp(f.shiftY, 0, center);
    v.streak = 0.9 * inCubic(seg(t, 120, DIVE_MS - 60));
    v.exposure = f.exposure * (1 + 0.5 * seg(t, 180, 600));
    v.fade = inCubic(seg(t, 430, DIVE_MS));
    // 越靠近视界，光被弯得越厉害，红蓝分开
    v.aberr = 0.7 * inCubic(seg(t, 250, DIVE_MS - 60));
    v.roll = 0.12 * inCubic(seg(t, 200, DIVE_MS));
  }
  return v;
}

export const durationOf = (stage: Stage) => (stage === 'intro' ? INTRO_MS : stage === 'emerge' ? EMERGE_MS : stage === 'dive' ? DIVE_MS : 0);

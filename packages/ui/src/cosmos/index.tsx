import { createContext, useContext, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import type { Mixia } from '@mixia/core';
import { BlackHole, type View } from './engine';
import {
  DIVE_MS,
  DIVE_TOTAL_MS,
  MAIN_AT_MS,
  durationOf,
  framing,
  lerp,
  outCubic,
  shot,
  type Frame,
  type Shot,
  type Stage,
  type Variant,
} from './camera';

export type { Shot, Stage, Variant } from './camera';
import markSvg from './mark.svg?raw';

/**
 * 星空与黑洞。密码越过事件视界，外面就再也看不见。
 *
 * 冷启动：我们这边的宇宙里悬着一个虫洞，球里透出另一个宇宙。镜头冲进去，四周的星云被拉成弧圈、
 * 时空起伏，穿过喉部后到了另一边，远处是黑洞，镜头减速停在它面前（锁屏）。
 * 解锁：镜头坠向黑洞，视界铺满画面，在黑暗里浮现出密匣的内部（主界面）。
 * 锁定：从视界里退出来，回到黑洞面前。
 *
 * 工作界面不跑这个场景，只铺一层静止的星空，看密码时不分心，也不耗电。
 */

const reducedMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/* ---------- 场景状态：Root 持有，入口页和主界面读取 ---------- */

interface Scene {
  stage: Stage;
  since: number;
  /** 正在退场的入口页：解锁瞬间不立刻卸掉，让卡片被吸进黑洞 */
  leaving: 'fresh' | 'locked' | null;
  mainReady: boolean;
  variant: Shot;
  setVariant(v: Shot): void;
  skip(): void;
}

const SceneCtx = createContext<Scene>({
  stage: 'off',
  since: 0,
  leaving: null,
  mainReady: true,
  variant: { kind: 'hero', room: 0 },
  setVariant: () => undefined,
  skip: () => undefined,
});
export const useScene = () => useContext(SceneCtx);

export function useSceneState(m: Mixia): Scene {
  const still = useMemo(reducedMotion, []);
  const [s, setS] = useState(() => ({
    stage: (m.phase === 'unlocked' ? 'off' : still ? 'idle' : 'intro') as Stage,
    since: performance.now(),
    leaving: null as Scene['leaving'],
    mainReady: m.phase === 'unlocked',
  }));
  const [variant, setVariantRaw] = useState<Shot>({ kind: 'hero', room: 0 });
  // 只在真的变了时更新，量出来的高度抖一两个像素不重新渲染
  const setVariant = useMemo(
    () => (v: Shot) => setVariantRaw((x) => (x.kind === v.kind && Math.abs(x.room - v.room) < 3 ? x : v)),
    [],
  );
  const prev = useRef(m.phase);
  const timers = useRef<number[]>([]);

  useEffect(() => {
    const clear = () => {
      timers.current.forEach((t) => window.clearTimeout(t));
      timers.current = [];
    };
    // 和核心的状态变化在同一批更新里，入口页不会先被卸掉再重新挂上
    const off = m.onChange(() => {
      const was = prev.current;
      const now = m.phase;
      if (was === now) return;
      prev.current = now;
      clear();
      const at = performance.now();
      if (now === 'unlocked') {
        if (still || reducedMotion()) {
          setS({ stage: 'off', since: at, leaving: null, mainReady: true });
          return;
        }
        setS({ stage: 'dive', since: at, leaving: was === 'fresh' ? 'fresh' : 'locked', mainReady: false });
        timers.current.push(
          window.setTimeout(() => setS((x) => ({ ...x, mainReady: true })), MAIN_AT_MS),
          window.setTimeout(() => setS((x) => ({ ...x, stage: 'off', leaving: null })), DIVE_TOTAL_MS),
        );
      } else {
        // 锁定或擦除：入口页立刻出现，主界面立刻卸掉，动画只在场景里
        setS({ stage: still || reducedMotion() ? 'idle' : 'emerge', since: at, leaving: null, mainReady: false });
      }
    });
    return () => {
      off();
      clear();
    };
  }, [m, still]);

  return useMemo(
    () => ({
      ...s,
      variant,
      setVariant,
      skip: () => setS((x) => (x.stage === 'intro' || x.stage === 'emerge' ? { ...x, stage: 'idle', since: performance.now() } : x)),
    }),
    [s, variant, setVariant],
  );
}

export function SceneProvider({ value, children }: { value: Scene; children: ReactNode }) {
  return <SceneCtx.Provider value={value}>{children}</SceneCtx.Provider>;
}

/* ---------- 镜头 ---------- */

/** 窗口没焦点或两分钟没人动时，整片星空停下来。锁屏可能一开一整天，不该一直耗电。 */
function useResting(): boolean {
  const [resting, setResting] = useState(false);
  useEffect(() => {
    let timer = 0;
    const wake = () => {
      setResting(false);
      window.clearTimeout(timer);
      timer = window.setTimeout(() => setResting(true), 120_000);
    };
    const sleep = () => {
      window.clearTimeout(timer);
      setResting(true);
    };
    const events = ['pointermove', 'pointerdown', 'keydown', 'focus'] as const;
    events.forEach((e) => window.addEventListener(e, wake, { passive: true }));
    window.addEventListener('blur', sleep);
    wake();
    return () => {
      window.clearTimeout(timer);
      events.forEach((e) => window.removeEventListener(e, wake));
      window.removeEventListener('blur', sleep);
    };
  }, []);
  return resting;
}

/** 系统“减少动效”的开关可能在运行中被切换，要跟着变 */
function useReducedMotion(): boolean {
  const [still, setStill] = useState(reducedMotion);
  useEffect(() => {
    const q = window.matchMedia('(prefers-reduced-motion: reduce)');
    const on = () => setStill(q.matches);
    q.addEventListener('change', on);
    return () => q.removeEventListener('change', on);
  }, []);
  return still;
}

/* ---------- 场景层 ---------- */

export function CosmosLayer() {
  const scene = useScene();
  const ref = useRef<HTMLCanvasElement>(null);
  const engine = useRef<BlackHole | null>(null);
  const [broken, setBroken] = useState(false);
  const maxScaleRef = useRef(1);
  const [gone, setGone] = useState(scene.stage === 'off');
  const resting = useResting();
  const still = useReducedMotion();
  const live = useRef({
    scene,
    frame: null as Frame | null,
    px: 0,
    py: 0,
    tx: 0,
    ty: 0,
    last: null as View | null,
    from: null as View | null,
    fromAt: 0,
    stage: scene.stage,
  });
  live.current.scene = scene;
  // 换阶段（尤其是跳过虫洞）时，从上一帧的镜头平滑过渡过去，不跳切
  if (live.current.stage !== scene.stage) {
    live.current.stage = scene.stage;
    live.current.from = live.current.last;
    live.current.fromAt = performance.now();
  }

  // 引擎只建一次，锁定、解锁反复使用同一个 WebGL 上下文
  useEffect(() => {
    const c = ref.current;
    if (!c) return;
    try {
      const coarse = window.matchMedia('(pointer: coarse)').matches;
      engine.current = new BlackHole(c, coarse ? 'low' : 'high');
      engine.current.scale = coarse ? 0.5 : 0.8;
      maxScaleRef.current = coarse ? 0.6 : 1;
    } catch {
      setBroken(true);
      return;
    }
    const lost = (e: Event) => {
      e.preventDefault();
      engine.current = null;
      setBroken(true);
    };
    c.addEventListener('webglcontextlost', lost);
    const move = (e: PointerEvent) => {
      if (e.pointerType !== 'mouse') return;
      live.current.tx = (e.clientX / innerWidth) * 2 - 1;
      live.current.ty = (e.clientY / innerHeight) * 2 - 1;
    };
    window.addEventListener('pointermove', move, { passive: true });
    return () => {
      c.removeEventListener('webglcontextlost', lost);
      window.removeEventListener('pointermove', move);
      engine.current?.dispose();
      engine.current = null;
    };
  }, []);

  useEffect(() => {
    if (scene.stage === 'off') {
      setGone(true);
      return;
    }
    setGone(false);
    const c = ref.current;
    const bh = engine.current;
    if (!c || !bh) return;

    /** 返回画布是否改了尺寸。改尺寸会清空缓冲，调用方要补画一帧 */
    const fit = () => {
      // 打印或被隐藏时尺寸是 0，这时改画布会把缓冲清空，回来后一直是黑的
      if (!c.clientWidth || !c.clientHeight) return false;
      // 手机像素密度高，画布用 1.5 倍足够细，后处理的开销小一半
      const dpr = Math.min(window.devicePixelRatio || 1, maxScaleRef.current < 1 ? 1.5 : 2);
      const w = Math.round(c.clientWidth * dpr);
      const h = Math.round(c.clientHeight * dpr);
      if (c.width === w && c.height === h) return false;
      c.width = w;
      c.height = h;
      return true;
    };
    const draw = (now: number, snap = false) => {
      const L = live.current;
      const { stage, since, variant } = L.scene;
      const t = now - since;
      if (!c.clientWidth || !c.clientHeight) return;
      const target = framing(c.clientWidth, c.clientHeight, variant);
      // 换页时镜头滑过去，不跳
      const f = L.frame ?? target;
      const k = still || snap ? 1 : 0.06;
      L.frame = {
        dist: lerp(f.dist, target.dist, k),
        fov: lerp(f.fov, target.fov, k),
        shiftX: lerp(f.shiftX, target.shiftX, k),
        shiftY: lerp(f.shiftY, target.shiftY, k),
        exposure: lerp(f.exposure, target.exposure, k),
        incl: lerp(f.incl, target.incl, k),
      };
      let v = shot(stage, t, L.frame);
      if (L.from && now - L.fromAt < 420 && !still) {
        const b = outCubic((now - L.fromAt) / 420);
        const a = L.from;
        v = {
          dist: lerp(a.dist, v.dist, b),
          incl: v.incl,
          yaw: v.yaw,
          shiftX: lerp(a.shiftX, v.shiftX, b),
          shiftY: lerp(a.shiftY, v.shiftY, b),
          fov: lerp(a.fov, v.fov, b),
          streak: lerp(a.streak, v.streak, b),
          roll: lerp(a.roll, v.roll, b),
          worm: lerp(a.worm, v.worm, b),
          wl: v.wl,
          aberr: lerp(a.aberr, v.aberr, b),
          ripple: v.ripple,
          fade: lerp(a.fade, v.fade, b),
          exposure: lerp(a.exposure, v.exposure, b),
        };
      }
      L.last = { ...v };
      // 鼠标带一点视差，星空和光环的相对位置跟着变，才看得出纵深
      L.px = lerp(L.px, L.tx, 0.04);
      L.py = lerp(L.py, L.ty, 0.04);
      const sec = now / 1000;
      v.yaw += L.px * 0.07 + Math.sin(sec * 0.031) * 0.05;
      v.incl += L.py * 0.03 + Math.sin(sec * 0.047) * 0.012;
      bh.render(still ? 3 : sec, v);
      // 给验收脚本数帧用，挂在元素对象上，不写 DOM
      (c as HTMLCanvasElement & { frames?: number }).frames = ((c as HTMLCanvasElement & { frames?: number }).frames ?? 0) + 1;
    };

    fit();
    // 手机上弹出、收起键盘都会改尺寸；场景暂停时没人重画，必须在这里补一帧，否则一直是黑的
    const ro = new ResizeObserver(() => {
      if (fit()) draw(performance.now(), true);
    });
    ro.observe(c);
    // 从后台切回来时系统可能已经丢掉了画面
    const back = () => {
      if (document.visibilityState === 'visible') draw(performance.now(), true);
    };
    document.addEventListener('visibilitychange', back);
    if (still) {
      draw(performance.now());
      return () => {
        ro.disconnect();
        document.removeEventListener('visibilitychange', back);
      };
    }

    let raf = 0;
    let last = 0;
    let acc = 0;
    let n = 0;
    // 手机上场景分辨率封顶：画面已经够细，再高只是耗电
    const maxScale = maxScaleRef.current;
    const frame = (now: number) => {
      raf = requestAnimationFrame(frame);
      // 高刷屏上也只画 60 帧
      if (now - last < 15.5) return;
      const dt = last ? now - last : 16.7;
      last = now;
      const { stage, since } = live.current.scene;
      const t = now - since;
      if (stage === 'dive' && t > DIVE_MS + 40) {
        setGone(true);
        cancelAnimationFrame(raf);
        return;
      }
      if (resting && t > durationOf(stage)) return;
      // 按帧间隔调场景分辨率：掉帧就降，宽裕就慢慢升。
      // 只在画面静止时调：转场途中改分辨率要重新分配纹理，会卡一下。
      // 后台回来的第一帧间隔很长，不算进去
      if (dt < 100 && t > durationOf(stage)) {
        acc += dt;
        n += 1;
      }
      if (n === 30) {
        const avg = acc / n;
        const next = avg > 21 ? bh.scale * 0.82 : avg < 17.4 ? bh.scale * 1.06 : bh.scale;
        // 按 0.05 取整，小幅波动不触发重新分配
        bh.scale = Math.min(maxScale, Math.max(0.28, Math.round(next * 20) / 20));
        acc = 0;
        n = 0;
      }
      draw(now);
    };
    raf = requestAnimationFrame(frame);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      document.removeEventListener('visibilitychange', back);
    };
  }, [scene.stage, scene.since, scene.variant, resting, still]);

  // 冷启动的虫洞可以跳过：点一下或按任意键
  useEffect(() => {
    if (scene.stage !== 'intro' && scene.stage !== 'emerge') return;
    const skip = () => scene.skip();
    window.addEventListener('pointerdown', skip, { once: true });
    window.addEventListener('keydown', skip, { once: true });
    return () => {
      window.removeEventListener('pointerdown', skip);
      window.removeEventListener('keydown', skip);
    };
  }, [scene]);

  return (
    <div className={`cosmos ${gone ? 'gone' : ''} ${scene.stage} ${broken ? 'broken' : ''}`} aria-hidden="true">
      {broken ? <BlackHoleMark size={240} className="cosmos-fallback" /> : <canvas ref={ref} />}
    </div>
  );
}

/* ---------- 入口页布局 ---------- */

export function Gate({ children, variant = 'backdrop' }: { children: ReactNode; variant?: Variant }) {
  const scene = useScene();
  const { setVariant } = scene;
  const ref = useRef<HTMLElement>(null);
  const leaving = scene.leaving !== null;
  // 量卡片上方剩多少空间：键盘弹出、窗口变矮时黑洞跟着挪
  useLayoutEffect(() => {
    if (leaving) return;
    const el = ref.current;
    if (variant !== 'hero' || !el) {
      setVariant({ kind: variant, room: 0 });
      return;
    }
    const measure = () => {
      const card = el.querySelector<HTMLElement>('.gate-card');
      if (!card) return;
      // offsetTop 不受入场动画的位移影响
      setVariant({ kind: 'hero', room: card.offsetTop - (document.scrollingElement?.scrollTop ?? 0) - 6 });
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    window.addEventListener('resize', measure);
    return () => {
      ro.disconnect();
      window.removeEventListener('resize', measure);
    };
  });
  // 入场动画只在刚打开或刚锁定时等镜头；之后在页面之间切换，卡片直接淡入
  const [arrive] = useState(() => (scene.stage === 'intro' ? 'arrive-intro' : scene.stage === 'emerge' ? 'arrive-emerge' : ''));
  const [arriving, setArriving] = useState(arrive !== '');
  useEffect(() => {
    if (!arriving) return;
    const t = window.setTimeout(() => setArriving(false), arrive === 'arrive-intro' ? 3500 : 1300);
    return () => window.clearTimeout(t);
  }, [arriving, arrive]);
  useEffect(() => {
    if (scene.stage === 'idle') setArriving(false);
  }, [scene.stage]);
  return (
    <main ref={ref} className={`gate ${variant} ${arriving ? arrive : ''} ${leaving ? 'leaving' : ''}`} aria-hidden={leaving || undefined}>
      {children}
    </main>
  );
}

/* ---------- 标志 ---------- */

export function BlackHoleMark({ size = 28, className = '' }: { size?: number; className?: string }) {
  // 同屏可能有多个标志，渐变 id 各用各的，隐藏其中一个不影响其余
  const id = useId().replace(/[^a-zA-Z0-9]/g, '');
  const html = useMemo(
    () =>
      markSvg
        .replace(/mx-/g, `mx${id}-`)
        .replace('<svg ', `<svg width="${size}" height="${size}" focusable="false" aria-hidden="true" `),
    [id, size],
  );
  return <span className={`mark ${className}`} role="img" aria-label="密匣" dangerouslySetInnerHTML={{ __html: html }} />;
}

/* ---------- 工作界面的静止星空 ---------- */

let starsReady = false;

/** 画两张不同尺寸的星空小图平铺叠在一起，重复的痕迹就看不出来。只画一次。 */
export function useStarfield() {
  useEffect(() => {
    if (starsReady) return;
    starsReady = true;
    const tile = (size: number, count: number, seed: number) => {
      const c = document.createElement('canvas');
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      c.width = c.height = Math.round(size * dpr);
      const g = c.getContext('2d');
      if (!g) return '';
      g.scale(dpr, dpr);
      let s = seed;
      const r = () => (s = (s * 16807) % 2147483647) / 2147483647;
      for (let i = 0; i < count; i++) {
        const x = r() * size;
        const y = r() * size;
        const big = r() ** 9;
        const rad = 0.35 + big * 1.1;
        const warm = r();
        g.globalAlpha = 0.22 + r() * 0.5 + big * 0.3;
        g.fillStyle = warm > 0.7 ? '#ffd9b0' : warm > 0.35 ? '#e6e4ff' : '#b9cdff';
        g.beginPath();
        g.arc(x, y, rad, 0, Math.PI * 2);
        g.fill();
      }
      return c.toDataURL('image/png');
    };
    const a = tile(512, 70, 11);
    const b = tile(347, 26, 29);
    const root = document.documentElement.style;
    if (a) root.setProperty('--stars-a', `url(${a})`);
    if (b) root.setProperty('--stars-b', `url(${b})`);
  }, []);
}

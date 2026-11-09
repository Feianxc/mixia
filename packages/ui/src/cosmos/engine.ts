/**
 * 黑洞与虫洞渲染器：沿每个像素反向追踪光线。
 *
 * 黑洞按史瓦西度规弯折（视界半径取 1）：星空、星云、被引力透镜弯到黑洞上方的吸积盘背面、
 * 从黑洞前方横穿的吸积盘正面，以及贴着光子球掠过的细光环。
 *
 * 虫洞按 Ellis 度规（喉部半径取 1）：它是一个看得穿的球，球里是另一个宇宙，黑洞就在那边；
 * 球外这边宇宙的星系和星云被拉成弧绕着它。镜头穿过喉部后，两个宇宙的天空互换。
 *
 * 两个场景各在一张较低分辨率的纹理里算好，第二遍铺满画布时按比例混合，
 * 再加转场用的径向拖影、色散、时空涟漪，以及渐黑、暗角和抖动噪点（暗色渐变不起色带）。
 *
 * 只依赖 WebGL 1，Android WebView 和 Electron 都能跑。
 */

export interface View {
  /** 相机到黑洞的距离 */
  dist: number;
  /** 相机高出吸积盘平面的角度（弧度），越小吸积盘越接近侧视 */
  incl: number;
  /** 绕黑洞的方位角（弧度） */
  yaw: number;
  /** 黑洞在画面上的位置，单位是短边的一半，向上为正 */
  shiftX: number;
  shiftY: number;
  /** 视野：短边一半对应的 tan(半视角) */
  fov: number;
  /** 镜头绕视线的旋转（弧度） */
  roll: number;
  /** 径向拖影 0..1 */
  streak: number;
  /** 虫洞画面所占比例 0..1，其余是黑洞 */
  worm: number;
  /** 相机在虫洞里的位置：正数在我们这边，0 是喉部，负数已经到了另一边 */
  wl: number;
  /** 色散 0..1 */
  aberr: number;
  /** 时空涟漪的进度 0..1，负数表示没有 */
  ripple: number;
  /** 渐黑 0..1 */
  fade: number;
  exposure: number;
}

const VERT = `
attribute vec2 aPos;
varying vec2 vUv;
void main() {
  vUv = aPos * 0.5 + 0.5;
  gl_Position = vec4(aPos, 0.0, 1.0);
}`;

const COMMON = `
precision highp float;
float hash13(vec3 p) {
  p = fract(p * 0.1031);
  p += dot(p, p.zyx + 31.32);
  return fract((p.x + p.y) * p.z);
}
vec3 hash33(vec3 p) {
  p = fract(p * vec3(0.1031, 0.1030, 0.0973));
  p += dot(p, p.yxz + 33.33);
  return fract((p.xxy + p.yxx) * p.zyx);
}
float noise3(vec3 x) {
  vec3 i = floor(x);
  vec3 f = fract(x);
  f = f * f * (3.0 - 2.0 * f);
  return mix(
    mix(mix(hash13(i), hash13(i + vec3(1.0, 0.0, 0.0)), f.x),
        mix(hash13(i + vec3(0.0, 1.0, 0.0)), hash13(i + vec3(1.0, 1.0, 0.0)), f.x), f.y),
    mix(mix(hash13(i + vec3(0.0, 0.0, 1.0)), hash13(i + vec3(1.0, 0.0, 1.0)), f.x),
        mix(hash13(i + vec3(0.0, 1.0, 1.0)), hash13(i + vec3(1.0, 1.0, 1.0)), f.x), f.y),
    f.z);
}
`;

const SKYLIB = `float fbm(vec3 p) {
  float a = 0.5;
  float s = 0.0;
  for (int i = 0; i < OCTAVES; i++) {
    s += a * noise3(p);
    p = p * 2.07 + vec3(1.7, 9.2, 3.1);
    a *= 0.5;
  }
  return s;
}

vec3 starLayer(vec3 d, float scale, float keep, float seed) {
  vec3 g = d * scale;
  vec3 id = floor(g) + seed;
  vec3 f = g - (id - seed) - 0.5;
  if (hash13(id + 17.0) > keep) return vec3(0.0);
  vec3 off = (hash33(id) - 0.5) * 0.7;
  float dd = length(f - off);
  float rad = max(uPx * scale * 0.85, 0.035);
  float b = pow(hash13(id + 3.1), 7.0) * 2.2 + 0.07;
  b *= 0.78 + 0.22 * sin(uTime * (0.6 + hash13(id + 5.0) * 2.0) + hash13(id) * 6.28);
  vec3 tint = mix(vec3(1.0, 0.80, 0.60), vec3(0.72, 0.82, 1.0), hash13(id + 9.0));
  return tint * b * exp(-dd * dd / (rad * rad));
}

/* 黑洞所在的宇宙：紫色星云，带一点暖光 */
vec3 homeSky(vec3 d) {
  vec3 c = starLayer(d, 70.0, 0.10, 0.0) + starLayer(d, 150.0, 0.07, 0.0) + starLayer(d, 320.0, 0.035, 0.0) * 0.8;
  float band = exp(-pow(dot(d, normalize(vec3(0.32, 1.0, 0.42))) * 3.0, 2.0));
  float n = fbm(d * 2.3 + vec3(0.0, 0.0, 3.0));
  float m = fbm(d * 5.1 + vec3(4.0, 1.0, 0.0));
  vec3 neb = mix(vec3(0.20, 0.07, 0.34), vec3(0.04, 0.13, 0.36), n);
  c += neb * pow(m, 2.4) * (0.18 + band * 1.4) * 1.15;
  c += vec3(0.010, 0.009, 0.022) * (0.5 + band);
  return c;
}

/* 温度到颜色：暗红、橙、金、白，再往上偏一点蓝白 */
vec3 heat(float t) {
  vec3 c = mix(vec3(0.42, 0.05, 0.02), vec3(1.0, 0.36, 0.06), smoothstep(0.12, 0.42, t));
  c = mix(c, vec3(1.0, 0.72, 0.34), smoothstep(0.42, 0.72, t));
  c = mix(c, vec3(1.0, 0.95, 0.86), smoothstep(0.72, 1.08, t));
  c = mix(c, vec3(0.80, 0.87, 1.0), smoothstep(1.15, 1.7, t));
  return c;
}

`;

const SCENE = `${COMMON}
uniform vec2 uRes;
uniform float uTime;
uniform vec3 uCamPos;
uniform vec3 uCamF;
uniform vec3 uCamR;
uniform vec3 uCamU;
uniform vec2 uShift;
uniform float uFov;
uniform float uExposure;
uniform float uPx;

#define RIN 2.25
#define ROUT 11.5
#define STEPS 200

${SKYLIB}
/* 吸积盘：越靠里转得越快。两层相位交替淡入淡出，转多久都不会被拉成一团乱纹 */
float swirl(float r, float phi, float tau, float seed) {
  float a = phi - tau * 1.9 * pow(r, -1.5);
  return fbm(vec3(cos(a) * 3.2, sin(a) * 3.2, r * 2.6 + seed));
}

vec4 disk(vec3 q, vec3 dir, float r) {
  float phi = atan(q.z, q.x);
  float T = 14.0;
  float ph = fract(uTime / T);
  float n = mix(swirl(r, phi, ph * T, 0.0), swirl(r, phi, fract(ph + 0.5) * T, 7.3), abs(1.0 - 2.0 * ph));

  /* 多普勒增亮按物理算会让一侧几乎全黑，这里收着用：保留明暗差，两边都看得见 */
  float beta = min(sqrt(0.5 / (r - 1.0)), 0.42);
  vec3 tang = normalize(vec3(-q.z, 0.0, q.x));
  float gamma = inversesqrt(1.0 - beta * beta);
  float g = 1.0 / (gamma * (1.0 - beta * dot(tang, -normalize(dir))));
  g *= sqrt(max(0.0, 1.0 - 1.0 / r));

  float inner = smoothstep(RIN * 0.92, RIN + 0.55, r);
  float outer = 1.0 - smoothstep(ROUT * 0.5, ROUT, r);
  float prof = pow(RIN / r, 1.45);
  float lanes = 0.3 + 1.2 * smoothstep(0.26, 0.8, n);
  float I = prof * lanes * inner * outer * pow(g, 1.7);
  float temp = pow(RIN / r, 0.6) * pow(g, 0.8) * (0.84 + 0.32 * n);
  vec3 col = heat(temp) * I * 2.6;
  float a = clamp(I * 1.5 + inner * outer * 0.12, 0.0, 0.97);
  return vec4(col, a);
}

void main() {
  vec2 uv = (gl_FragCoord.xy - 0.5 * uRes) / (0.5 * min(uRes.x, uRes.y)) - uShift;
  vec3 rd = normalize(uCamF + uFov * (uv.x * uCamR + uv.y * uCamU));
  vec3 p = uCamPos;
  vec3 v = rd;
  vec3 hv = cross(p, v);
  float h2 = dot(hv, hv);
  vec3 col = vec3(0.0);
  float alpha = 0.0;
  float minR = 1e4;
  bool captured = false;
  float far = max(40.0, length(uCamPos) + 4.0);
  for (int i = 0; i < STEPS; i++) {
    float r2 = dot(p, p);
    float r = sqrt(r2);
    minR = min(minR, r);
    float dt = clamp(0.06 * r, 0.02, 3.0);
    vec3 acc = -1.5 * h2 * p / (r2 * r2 * r);
    vec3 v2 = v + acc * dt;
    vec3 p2 = p + v2 * dt;
    if (p.y * p2.y < 0.0) {
      float t = p.y / (p.y - p2.y);
      vec3 q = mix(p, p2, t);
      float rq = length(q.xz);
      if (rq > RIN * 0.9 && rq < ROUT) {
        vec4 dc = disk(q, v2, rq);
        col += (1.0 - alpha) * dc.rgb * dc.a;
        alpha += (1.0 - alpha) * dc.a;
        if (alpha > 0.985) break;
      }
    }
    p = p2;
    v = v2;
    if (r < 1.01) { captured = true; break; }
    if (r > far && dot(p, v) > 0.0) break;
  }
  if (!captured) col += (1.0 - alpha) * homeSky(normalize(v));
  /* 光子环：贴着光子球掠过的光线 */
  float ring = exp(-abs(minR - 1.52) * 9.0);
  col += vec3(1.0, 0.80, 0.56) * ring * 0.22 * (1.0 - alpha * 0.6);
  col *= uExposure;
  /* 胶片式压缩：亮部不爆白，暗部保留 */
  col = col * (2.51 * col + 0.03) / (col * (2.43 * col + 0.59) + 0.14);
  gl_FragColor = vec4(clamp(col, 0.0, 1.0), 1.0);
}`;

const WORM = `${COMMON}
uniform vec2 uRes;
uniform float uTime;
uniform vec2 uShift;
uniform float uFov;
uniform float uExposure;
uniform float uPx;
uniform float uL;
uniform float uRoll;

#define THROAT 1.0
#define WSTEPS 180

${SKYLIB}

/* 远处的星系：一团椭圆的光。经过虫洞时会被拉成弧，空间被扭曲的样子全靠它们显出来 */
vec3 galaxy(vec3 d, vec3 g, float size, float tilt, vec3 tint) {
  float k = dot(d, g);
  if (k < 0.0) return vec3(0.0);
  vec3 ax = normalize(cross(g, vec3(0.0, 1.0, 0.0)));
  vec3 ay = cross(ax, g);
  vec2 q = vec2(dot(d, ax), dot(d, ay)) / size;
  q = vec2(cos(tilt) * q.x - sin(tilt) * q.y, sin(tilt) * q.x + cos(tilt) * q.y);
  q.y *= 2.6;
  float r = length(q);
  float arms = 0.6 + 0.4 * sin(atan(q.y, q.x) * 2.0 + r * 5.0);
  return tint * (exp(-r * r * 5.0) * 1.3 + exp(-r * 1.5) * 0.35 * arms);
}

/* 我们这边的宇宙：偏冷的青蓝，和黑洞那边的紫金一眼能分开。
   星系、亮星和暗色尘埃带要够多：透镜把它们拉成弧、复制成环，空间被扭曲的样子才看得出来 */
vec3 farSky(vec3 d) {
  vec3 c = starLayer(d, 83.0, 0.11, 41.0) * vec3(0.85, 0.95, 1.1) + starLayer(d, 171.0, 0.08, 73.0) + starLayer(d, 300.0, 0.04, 19.0) * 0.8;
  c += starLayer(d, 26.0, 0.05, 7.0) * vec3(0.9, 0.95, 1.2) * 2.2;
  float band = exp(-pow(dot(d, normalize(vec3(-0.22, 1.0, 0.18))) * 2.3, 2.0));
  float n = fbm(d * 2.0 + vec3(5.0, 1.0, 2.0));
  float m = fbm(d * 4.4 + vec3(2.0, 7.0, 1.0));
  float dust = smoothstep(0.48, 0.66, fbm(d * 7.0 + vec3(9.0, 3.0, 4.0)));
  vec3 neb = mix(vec3(0.02, 0.13, 0.26), vec3(0.12, 0.36, 0.5), n);
  c += neb * pow(m, 1.6) * (0.3 + band * 2.1) * 1.3 * (1.0 - dust * 0.85);
  c += galaxy(d, normalize(vec3(0.18, 0.12, -1.0)), 0.085, 0.5, vec3(0.78, 0.88, 1.0));
  c += galaxy(d, normalize(vec3(-0.24, -0.16, -1.0)), 0.06, -0.9, vec3(1.0, 0.86, 0.72)) * 0.9;
  c += galaxy(d, normalize(vec3(0.05, -0.34, -1.0)), 0.05, 0.2, vec3(0.7, 0.9, 1.0)) * 0.9;
  c += galaxy(d, normalize(vec3(-0.42, 0.3, -1.0)), 0.07, 1.4, vec3(0.85, 0.8, 1.0)) * 0.8;
  c += galaxy(d, normalize(vec3(0.45, -0.1, -1.0)), 0.055, -0.3, vec3(0.6, 0.85, 1.0)) * 0.8;
  c += galaxy(d, normalize(vec3(-0.75, -0.3, -0.6)), 0.14, -0.4, vec3(0.62, 0.82, 1.0)) * 0.8;
  c += galaxy(d, normalize(vec3(0.6, 0.55, -0.55)), 0.07, 1.1, vec3(1.0, 0.85, 0.7)) * 0.6;
  return c;
}

/* 另一边远处的黑洞：从虫洞里望过去只是一小圈金光，穿过去以后才看清它 */
vec3 distantHole(vec3 d, vec3 c) {
  if (d.z < 0.95) return c;
  vec2 q = d.xy / 0.045;
  float r = length(q);
  c *= smoothstep(0.92, 1.06, r);
  float ring = exp(-pow((r - 1.08) / 0.07, 2.0));
  float halo = exp(-pow((r - 1.34) / 0.25, 2.0)) * (0.4 + 0.6 * smoothstep(-0.6, 0.9, q.y / max(r, 0.001)));
  float band = exp(-pow((q.y + 0.1) / (0.07 + 0.02 * abs(q.x)), 2.0)) * (1.0 - smoothstep(1.4, 4.6, abs(q.x)));
  float side = 0.75 + 0.3 * clamp(q.x / 3.0, -1.0, 1.0);
  vec3 gold = vec3(1.0, 0.7, 0.36);
  c += (gold * (ring * 1.3 + halo * 0.9) + vec3(1.0, 0.9, 0.74) * band * 1.5) * side;
  c += gold * exp(-r * 0.6) * 0.12;
  return c;
}

void main() {
  vec2 uv = (gl_FragCoord.xy - 0.5 * uRes) / (0.5 * min(uRes.x, uRes.y)) - uShift;
  float cr = cos(uRoll);
  float sr = sin(uRoll);
  uv = vec2(cr * uv.x - sr * uv.y, sr * uv.x + cr * uv.y);
  /* 相机在 z 轴上，朝 l 减小的方向看：这边看向虫洞，穿过去后背对它继续往前 */
  float s = uL >= 0.0 ? 1.0 : -1.0;
  vec3 n = normalize(vec3(uFov * uv.x, uFov * uv.y, -s));
  float nphi = length(n.xy);
  vec2 td = nphi > 1e-6 ? n.xy / nphi : vec2(1.0, 0.0);
  float l = uL;
  float r2 = THROAT * THROAT + l * l;
  /* 角动量守恒：小于喉部半径的光线穿过去，大于的被弹回这边 */
  float h = sqrt(r2) * nphi;
  float p = n.z * s;
  float phi = 0.0;
  float far = max(30.0, abs(uL) + 12.0);
  float minL = abs(l);
  for (int i = 0; i < WSTEPS; i++) {
    float dl = clamp(0.07 * sqrt(r2), 0.02, 2.0);
    p += 0.5 * dl * h * h * l / (r2 * r2);
    l += dl * p;
    r2 = THROAT * THROAT + l * l;
    p += 0.5 * dl * h * h * l / (r2 * r2);
    phi += dl * h / r2;
    minL = min(minL, abs(l));
    if (abs(l) > far && l * p > 0.0) break;
  }
  float r = sqrt(r2);
  vec3 ta = vec3(td, 0.0);
  vec3 u = cos(phi) * vec3(0.0, 0.0, 1.0) + sin(phi) * ta;
  vec3 up = -sin(phi) * vec3(0.0, 0.0, 1.0) + cos(phi) * ta;
  vec3 d = normalize((l / r) * p * u + (h / r) * up);
  /* 球里看到的是另一个宇宙，稍微提亮，像一扇透光的窗 */
  vec3 col = l >= 0.0 ? farSky(d) : distantHole(d, homeSky(d) * 1.35);
  /* 贴着喉部掠过的光线勾出虫洞的轮廓：只算真的到过喉部附近的光线 */
  col += vec3(0.55, 0.72, 1.0) * exp(-abs(h - THROAT) * 16.0) * exp(-minL * 2.5) * 0.22;
  col *= uExposure;
  col = col * (2.51 * col + 0.03) / (col * (2.43 * col + 0.59) + 0.14);
  gl_FragColor = vec4(clamp(col, 0.0, 1.0), 1.0);
}`;

const POST = `${COMMON}
varying vec2 vUv;
uniform sampler2D uTex;
uniform sampler2D uTex2;
uniform vec2 uRes;
uniform vec2 uCenter;
uniform float uStreak;
uniform float uWorm;
uniform float uAberr;
uniform float uRipple;
uniform float uFade;
uniform float uTime;
uniform float uBloom;

vec3 scene(vec2 uv) {
  if (uWorm <= 0.001) return texture2D(uTex, uv).rgb;
  if (uWorm >= 0.999) return texture2D(uTex2, uv).rgb;
  return mix(texture2D(uTex, uv).rgb, texture2D(uTex2, uv).rgb, uWorm);
}

void main() {
  vec2 asp = uRes / min(uRes.x, uRes.y);
  vec2 uv = vUv;
  /* 时空涟漪：穿过喉部时一圈波纹从中心向外推开，整片画面跟着起伏 */
  if (uRipple > 0.0 && uRipple < 1.0) {
    vec2 q = (uv - uCenter) * asp;
    float rr = length(q);
    float w = rr - uRipple * 2.2;
    float env = exp(-w * w * 9.0) * (1.0 - uRipple) * (1.0 - uRipple);
    uv -= (q / max(rr, 0.0001)) * sin(w * 22.0) * env * 0.07 / asp;
  }
  vec2 dir = uv - uCenter;
  vec3 c = vec3(0.0);
  float ws = 0.0;
  for (int i = 0; i < 12; i++) {
    if (i > 0 && uStreak <= 0.002) break;
    float t = float(i) / 11.0;
    float w = 1.0 - t * 0.7;
    vec2 b = dir * (1.0 - uStreak * 0.22 * t);
    vec3 v;
    if (uAberr > 0.002) {
      /* 色散：红光和蓝光被弯得不一样多 */
      v.r = scene(uCenter + b * (1.0 + uAberr * 0.04)).r;
      v.g = scene(uCenter + b).g;
      v.b = scene(uCenter + b * (1.0 - uAberr * 0.04)).b;
    } else {
      v = scene(uCenter + b);
    }
    c += v * w;
    ws += w;
  }
  c /= ws;
  /* 辉光：只取亮部，在两圈上取样 */
  vec2 px = uBloom / uRes * min(uRes.x, uRes.y);
  vec3 bl = vec3(0.0);
  for (int i = 0; i < 8; i++) {
    float a = float(i) * 0.7854 + 0.39;
    vec2 o = vec2(cos(a), sin(a));
    bl += max(scene(uv + o * px) - 0.42, 0.0);
    bl += max(scene(uv + o * px * 2.6) - 0.42, 0.0) * 0.6;
  }
  c += bl * 0.16 * vec3(1.0, 0.86, 0.7);
  vec2 q = vUv - 0.5;
  c *= 1.0 - dot(q, q) * 0.55;
  c *= 1.0 - uFade;
  c += (hash13(vec3(gl_FragCoord.xy, fract(uTime * 7.0) * 91.0)) - 0.5) / 255.0 * 2.0;
  gl_FragColor = vec4(c, 1.0);
}`;

function compile(gl: WebGLRenderingContext, type: number, src: string) {
  const s = gl.createShader(type)!;
  gl.shaderSource(s, src);
  gl.compileShader(s);
  if (!gl.getShaderParameter(s, gl.COMPILE_STATUS) && !gl.isContextLost()) {
    throw new Error(gl.getShaderInfoLog(s) ?? 'shader');
  }
  return s;
}

function program(gl: WebGLRenderingContext, frag: string) {
  const p = gl.createProgram()!;
  gl.attachShader(p, compile(gl, gl.VERTEX_SHADER, VERT));
  gl.attachShader(p, compile(gl, gl.FRAGMENT_SHADER, frag));
  gl.bindAttribLocation(p, 0, 'aPos');
  gl.linkProgram(p);
  if (!gl.getProgramParameter(p, gl.LINK_STATUS) && !gl.isContextLost()) {
    throw new Error(gl.getProgramInfoLog(p) ?? 'link');
  }
  const loc = new Map<string, WebGLUniformLocation | null>();
  return {
    p,
    u: (name: string) => {
      if (!loc.has(name)) loc.set(name, gl.getUniformLocation(p, name));
      return loc.get(name)!;
    },
  };
}

type Prog = ReturnType<typeof program>;

/** 一张离屏纹理：场景先画在这里，再由第二遍铺满画布 */
class Target {
  readonly tex: WebGLTexture;
  readonly fbo: WebGLFramebuffer;
  w = 0;
  h = 0;
  constructor(private gl: WebGLRenderingContext) {
    this.tex = gl.createTexture()!;
    this.fbo = gl.createFramebuffer()!;
    // 先放一个 1×1，免得还没画过时被采样，控制台报纹理不完整
    this.size(1, 1);
  }
  size(w: number, h: number) {
    if (w === this.w && h === this.h) return;
    const gl = this.gl;
    this.w = w;
    this.h = h;
    gl.bindTexture(gl.TEXTURE_2D, this.tex);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, w, h, 0, gl.RGBA, gl.UNSIGNED_BYTE, null);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.bindFramebuffer(gl.FRAMEBUFFER, this.fbo);
    gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, this.tex, 0);
  }
}

export class BlackHole {
  readonly gl: WebGLRenderingContext;
  private scene: Prog;
  private worm: Prog;
  private post: Prog;
  private hole: Target;
  private pass: Target;
  /** 场景分辨率相对画布的比例，由调用方按帧时间调整 */
  scale = 0.6;

  constructor(readonly canvas: HTMLCanvasElement, quality: 'high' | 'low' = 'high') {
    const opts: WebGLContextAttributes = { antialias: false, depth: false, stencil: false, alpha: false, powerPreference: 'high-performance', preserveDrawingBuffer: false };
    const gl = (canvas.getContext('webgl', opts) ?? canvas.getContext('experimental-webgl', opts)) as WebGLRenderingContext | null;
    if (!gl) throw new Error('webgl_unavailable');
    this.gl = gl;
    const octaves = String(quality === 'high' ? 4 : 3);
    const fill = (src: string) => src.replace(/OCTAVES/g, octaves);
    this.scene = program(gl, fill(SCENE));
    this.worm = program(gl, fill(WORM));
    this.post = program(gl, POST);
    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
    gl.enableVertexAttribArray(0);
    gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);
    this.hole = new Target(gl);
    this.pass = new Target(gl);
  }

  render(time: number, v: View) {
    const gl = this.gl;
    const W = this.canvas.width;
    const H = this.canvas.height;
    if (!W || !H) return;
    const sw = Math.max(32, Math.round(W * this.scale));
    const sh = Math.max(32, Math.round(H * this.scale));
    const px = v.fov / (0.5 * Math.min(sw, sh));

    if (v.worm < 0.999) {
      // 相机：从 (yaw, incl) 方向看向黑洞，再绕视线转 roll
      const ci = Math.cos(v.incl);
      const [cx, cy, cz] = [v.dist * ci * Math.sin(v.yaw), v.dist * Math.sin(v.incl), v.dist * ci * Math.cos(v.yaw)];
      const len = Math.hypot(cx, cy, cz);
      const [fx, fy, fz] = [-cx / len, -cy / len, -cz / len];
      // 右方向在水平面内，上方向由右和前叉乘得到
      const rl = Math.hypot(fx, fz) || 1;
      const [rx, ry, rz] = [-fz / rl, 0, fx / rl];
      const [ux, uy, uz] = [ry * fz - rz * fy, rz * fx - rx * fz, rx * fy - ry * fx];
      const [c, s] = [Math.cos(v.roll), Math.sin(v.roll)];
      const t = this.hole;
      t.size(sw, sh);
      gl.bindFramebuffer(gl.FRAMEBUFFER, t.fbo);
      gl.viewport(0, 0, sw, sh);
      const p = this.scene;
      gl.useProgram(p.p);
      gl.uniform2f(p.u('uRes'), sw, sh);
      gl.uniform1f(p.u('uTime'), time);
      gl.uniform3fv(p.u('uCamPos'), [cx, cy, cz]);
      gl.uniform3fv(p.u('uCamF'), [fx, fy, fz]);
      gl.uniform3fv(p.u('uCamR'), [rx * c + ux * s, ry * c + uy * s, rz * c + uz * s]);
      gl.uniform3fv(p.u('uCamU'), [ux * c - rx * s, uy * c - ry * s, uz * c - rz * s]);
      gl.uniform2f(p.u('uShift'), v.shiftX, v.shiftY);
      gl.uniform1f(p.u('uFov'), v.fov);
      gl.uniform1f(p.u('uExposure'), v.exposure);
      gl.uniform1f(p.u('uPx'), px);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    }

    if (v.worm > 0.001) {
      const t = this.pass;
      t.size(sw, sh);
      gl.bindFramebuffer(gl.FRAMEBUFFER, t.fbo);
      gl.viewport(0, 0, sw, sh);
      const p = this.worm;
      gl.useProgram(p.p);
      gl.uniform2f(p.u('uRes'), sw, sh);
      gl.uniform1f(p.u('uTime'), time);
      gl.uniform2f(p.u('uShift'), v.shiftX, v.shiftY);
      gl.uniform1f(p.u('uFov'), v.fov);
      gl.uniform1f(p.u('uExposure'), v.exposure);
      gl.uniform1f(p.u('uPx'), px);
      gl.uniform1f(p.u('uL'), v.wl);
      gl.uniform1f(p.u('uRoll'), v.roll);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    }

    gl.bindFramebuffer(gl.FRAMEBUFFER, null);
    gl.viewport(0, 0, W, H);
    const p = this.post;
    gl.useProgram(p.p);
    gl.activeTexture(gl.TEXTURE0);
    gl.bindTexture(gl.TEXTURE_2D, this.hole.tex);
    gl.uniform1i(p.u('uTex'), 0);
    gl.activeTexture(gl.TEXTURE1);
    gl.bindTexture(gl.TEXTURE_2D, this.pass.tex);
    gl.uniform1i(p.u('uTex2'), 1);
    gl.activeTexture(gl.TEXTURE0);
    gl.uniform2f(p.u('uRes'), W, H);
    const m = Math.min(W, H);
    gl.uniform2f(p.u('uCenter'), 0.5 + (v.shiftX * 0.5 * m) / W, 0.5 + (v.shiftY * 0.5 * m) / H);
    gl.uniform1f(p.u('uStreak'), v.streak);
    gl.uniform1f(p.u('uWorm'), v.worm);
    gl.uniform1f(p.u('uAberr'), v.aberr);
    gl.uniform1f(p.u('uRipple'), v.ripple);
    gl.uniform1f(p.u('uFade'), v.fade);
    gl.uniform1f(p.u('uTime'), time);
    gl.uniform1f(p.u('uBloom'), 0.012);
    gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
  }

  dispose() {
    this.gl.getExtension('WEBGL_lose_context')?.loseContext();
  }
}

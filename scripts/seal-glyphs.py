"""从本机思源宋体提取印章字形为 SVG 路径（OFL 字体）。输出 packages/ui/src/seal-glyphs.ts"""
import json, sys
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen

src = r"C:\Windows\Fonts\NotoSerifSC-VF.ttf"
f = TTFont(src)
inst = instancer.instantiateVariableFont(f, {"wght": 900})
cmap = inst.getBestCmap()
gs = inst.getGlyphSet()
upm = inst["head"].unitsPerEm
out = {}
for ch in "云本冷匣":
    g = gs[cmap[ord(ch)]]
    pen = SVGPathPen(gs, ntos=lambda v: ("%.1f" % v).rstrip("0").rstrip("."))
    # 字体 y 向上，SVG y 向下；缩放到 100x100 画布
    s = 100 / upm
    tp = TransformPen(pen, (s, 0, 0, -s, 0, 88))
    g.draw(tp)
    out[ch] = pen.getCommands()
with open(sys.argv[1], "w", encoding="utf-8", newline="\n") as w:
    w.write("// 由 scripts/seal-glyphs.py 生成，字形来自思源宋体 Noto Serif SC（SIL OFL 1.1）\n")
    w.write("export const SEAL_GLYPHS: Record<string, string> = ")
    w.write(json.dumps(out, ensure_ascii=False, indent=2))
    w.write(";\n")
print({k: len(v) for k, v in out.items()})

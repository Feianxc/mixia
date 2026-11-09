"""把界面实际用到的汉字从思源宋体（OFL）子集化，用于标题。正文走系统字体。"""
import re, pathlib, sys
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer
from fontTools import subset

root = pathlib.Path(__file__).resolve().parent.parent
chars = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ·“”，。：、？！（）")
for f in (root / "packages/ui/src").rglob("*.tsx"):
    chars |= set(re.findall(r"[\u3000-\u9fff\uff00-\uffef]", f.read_text(encoding="utf-8")))
font = TTFont(r"C:\Windows\Fonts\NotoSerifSC-VF.ttf")
inst = instancer.instantiateVariableFont(font, {"wght": 600})
opts = subset.Options()
opts.flavor = "woff2"
opts.layout_features = ["kern", "liga", "palt"]
opts.hinting = False
sub = subset.Subsetter(opts)
sub.populate(text="".join(sorted(chars)))
sub.subset(inst)
inst.flavor = "woff2"
out = root / "packages/ui/public/fonts/mixia-serif.woff2"
inst.save(out)
print(len(chars), "chars", out.stat().st_size // 1024, "KB")

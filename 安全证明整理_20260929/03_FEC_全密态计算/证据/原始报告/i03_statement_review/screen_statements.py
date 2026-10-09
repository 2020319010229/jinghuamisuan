# -*- coding: utf-8 -*-
"""不依赖 python-pptx:直接解 pptx 的 XML 提取文字,按 I-03 规则筛查措辞。"""
import html
import re
import sys
import zipfile
from pathlib import Path

src = Path(sys.argv[1])
zf = zipfile.ZipFile(src)
names = sorted([n for n in zf.namelist() if re.match(r'ppt/slides/slide\d+\.xml$', n)],
               key=lambda x: int(re.search(r'(\d+)', x).group(1)))

PATTERNS = {
    '绝对化安全表述': r'(无法破解|绝对安全|完全安全|不可能破解|零风险|100%\s*安全|万无一失|无法还原|不可窃取)',
    '信息论/一次一密主张': r'(信息论|香农|一次一密|理论上不可破|完美保密)',
    '加密与隔离混用': r'(全链路加密|全程加密|全链路密态|显存加密|总线加密|链路加密)',
    'GPU-TEE 表述': r'(GPU[- ]?TEE|GPU\s*机密计算|机密显存)',
    '性能主张': r'(性能几乎无损|几乎无损|提升\s*\d[\d,]*\s*余?倍|\d[\d,]*\s*余?倍|零开销|几乎不影响)',
    '认证合规主张': r'(通过[^。;,]{0,10}认证|权威认证|国家[^。;,]{0,6}认证|已备案|等保|密评)',
}

slides = []
for n in names:
    xml = zf.read(n).decode('utf-8', 'replace')
    parts = re.findall(r'<a:t>(.*?)</a:t>', xml, re.S)
    texts = [html.unescape(p).strip() for p in parts if html.unescape(p).strip()]
    slides.append(texts)

print("文件: %s" % src.name)
print("总页数: %d" % len(slides))
print("=" * 72)
hits = {k: [] for k in PATTERNS}
for i, texts in enumerate(slides, 1):
    body = ' '.join(texts)
    for name, pat in PATTERNS.items():
        for m in re.finditer(pat, body):
            start = max(0, m.start() - 45)
            ctx = body[start:m.end() + 45]
            hits[name].append((i, m.group(0), ctx))

total = 0
for name, items in hits.items():
    seen = set()
    uniq = []
    for page, word, ctx in items:
        if (page, word) in seen:
            continue
        seen.add((page, word))
        uniq.append((page, word, ctx))
    total += len(uniq)
    print("\n### %s : %d 处" % (name, len(uniq)))
    for page, word, ctx in uniq[:12]:
        print("  P%-3d [%s]" % (page, word))
        print("        …%s…" % ctx)
print("\n合计命中 %d 处" % total)
print("=" * 72)
print("### 各页首行")
for i, texts in enumerate(slides, 1):
    if texts:
        print("  P%-3d %s" % (i, ' / '.join(texts[:2])[:70]))

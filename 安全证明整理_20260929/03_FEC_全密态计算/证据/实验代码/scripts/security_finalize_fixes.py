"""Freeze remediation sources and verify report links and local artifact hashes."""
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
from urllib.parse import unquote, urlparse

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'results/security_fix_20260916'


class Links(HTMLParser):
    def __init__(self):super().__init__();self.links=[]
    def handle_starttag(self,tag,attrs):
        if tag=='a':self.links.extend(v for k,v in attrs if k=='href')


def main():
    snap=OUT/'snapshot_fix_01';snap.mkdir(exist_ok=False)
    sources=list((ROOT/'security_fixes/20260916').rglob('*'))
    sources += [ROOT/'otp_rng.h',ROOT/'docs/SECURITY_EXECUTION_TRACKER.md']
    sources += [ROOT/'scripts'/name for name in ('security_rng_boundary_test.c','security_run_rng_boundary.py','security_verify_fixes.py','security_finalize_fixes.py')]
    for source in sources:
        if not source.is_file() or '__pycache__' in source.parts:continue
        target=snap/source.relative_to(ROOT);target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
    entries=[]
    for path in sorted(OUT.rglob('*')):
        if path.is_file() and '__pycache__' not in path.parts:
            entries.append({'path':path.relative_to(OUT).as_posix(),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    manifest=OUT/'manifest_fix_01.json'
    with manifest.open('x',encoding='utf-8') as f:json.dump({'scope':'local hashes, not signed provenance','files':entries},f,ensure_ascii=False,indent=2)
    parser=Links();parser.feed((OUT/'fix_report.htm').read_text(encoding='utf-8'))
    missing=[link for link in parser.links if not urlparse(link).scheme and not (OUT/unquote(link.split('#')[0])).exists()]
    if missing:raise RuntimeError('Missing report link: '+repr(missing))
    for entry in entries:
        assert hashlib.sha256((OUT/entry['path']).read_bytes()).hexdigest()==entry['sha256']
    print(json.dumps({'files_verified':len(entries),'report_links_verified':len(parser.links)}))


if __name__=='__main__':main()

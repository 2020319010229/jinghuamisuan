"""Archive current test drivers and generate a hash manifest without overwrites."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
from html.parser import HTMLParser
from urllib.parse import unquote,urlparse

PROJECT=Path(__file__).resolve().parents[1]

class Links(HTMLParser):
    def __init__(self): super().__init__(); self.targets=[]
    def handle_starttag(self,tag,attrs):
        if tag=='a': self.targets.extend(value for key,value in attrs if key=='href')

def main():
    p=argparse.ArgumentParser(); p.add_argument('--directory',type=Path,required=True); p.add_argument('--batch',required=True); p.add_argument('--report',default='experiment_progress_02.htm'); a=p.parse_args()
    directory=a.directory.resolve(); snapshot=directory/('scripts_snapshot_'+a.batch)
    snapshot.mkdir(exist_ok=False)
    for source in sorted((PROJECT/'scripts').glob('security_*')):
        if source.suffix in ('.py','.c','.cpp'): shutil.copyfile(source,snapshot/source.name)
    document_snapshot=directory/('documents_snapshot_'+a.batch)
    document_snapshot.mkdir(exist_ok=False)
    for name in ('SECURITY_EXECUTION_TRACKER.md','SECURITY_EVIDENCE_PROTOCOL.md','SECURITY_TRUST_BOUNDARIES.md'):
        shutil.copyfile(PROJECT/'docs'/name,document_snapshot/name)
    report={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'local artifact integrity only; not signed provenance','files':[]}
    for file in sorted(directory.rglob('*')):
        if not file.is_file() or '__pycache__' in file.parts or file.name.startswith('manifest_'): continue
        report['files'].append({'path':file.relative_to(directory).as_posix(),'bytes':file.stat().st_size,'sha256':hashlib.sha256(file.read_bytes()).hexdigest()})
    report['documents']=[]
    for name in ('SECURITY_EXECUTION_TRACKER.md','SECURITY_EVIDENCE_PROTOCOL.md','SECURITY_TRUST_BOUNDARIES.md'):
        file=PROJECT/'docs'/name
        report['documents'].append({'path':'../../docs/'+name,'sha256':hashlib.sha256(file.read_bytes()).hexdigest()})
    manifest=directory/('manifest_'+a.batch+'.json')
    with manifest.open('x',encoding='utf-8') as f: json.dump(report,f,ensure_ascii=False,indent=2)
    page=directory/a.report; parser=Links(); parser.feed(page.read_text(encoding='utf-8'))
    missing=[href for href in parser.targets if not urlparse(href).scheme and not (page.parent/unquote(href.split('#')[0])).exists()]
    if missing: raise RuntimeError('Broken report links: '+repr(missing))
    for item in report['files']:
        if hashlib.sha256((directory/item['path']).read_bytes()).hexdigest()!=item['sha256']: raise RuntimeError('Hash mismatch')
    print(json.dumps({'manifest':str(manifest),'files_verified':len(report['files']),'report_links_verified':len(parser.targets)}))

if __name__=='__main__': main()

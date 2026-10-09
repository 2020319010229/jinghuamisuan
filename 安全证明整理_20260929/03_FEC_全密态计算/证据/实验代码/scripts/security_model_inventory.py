"""Read only mapped model files; report digests/metadata, never weight content."""
import argparse
import hashlib
import json
from pathlib import Path
import time

def digest(path):
    value=hashlib.sha256()
    with path.open('rb') as f:
        for data in iter(lambda:f.read(8*1024*1024),b''):value.update(data)
    return value.hexdigest()

def main():
    p=argparse.ArgumentParser();p.add_argument('--hash-weights',action='store_true');a=p.parse_args()
    root=Path('/data/Qwen3.5-35B-A3B-w8a8-mtp').resolve()
    out={'started_ns':time.time_ns(),'scope':'read-only mapped-file manifest; observed digests are not approved model reference values','processes':[],'metadata':[],'weights':[]}
    paths=set()
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:
            if (proc/'comm').read_text().strip()!='serve35_cb':continue
            mapped=set()
            for line in (proc/'maps').read_text().splitlines():
                fields=line.split(maxsplit=5)
                if len(fields)==6 and fields[5].startswith(str(root)+'/'):
                    path=Path(fields[5]).resolve()
                    if path.parent==root and path.suffix=='.safetensors':mapped.add(path)
            paths.update(mapped)
            out['processes'].append({'pid':proc.name,'exe_sha256':digest(proc/'exe'),'mapped_files':[x.name for x in sorted(mapped)]})
        except (FileNotFoundError,PermissionError):continue
    index_candidates=[root/name for name in ('model.safetensors.index.json','quant_model_weights.safetensors.index.json') if (root/name).is_file()]
    if len(index_candidates)!=1:raise RuntimeError('Model shard index absent or ambiguous')
    index=index_candidates[0];out['index_name']=index.name
    for name in ('config.json',index.name,'tokenizer_config.json','generation_config.json'):
        path=root/name
        if path.is_file():out['metadata'].append({'name':name,'bytes':path.stat().st_size,'sha256':digest(path)})
    expected=set(json.loads(index.read_text()).get('weight_map',{}).values()) if index.exists() else set()
    out['index_shards']=sorted(expected)
    for path in sorted(paths):
        before=path.stat();row={'name':path.name,'bytes':before.st_size,'mtime_ns':before.st_mtime_ns,'inode':before.st_ino}
        if a.hash_weights:row['sha256']=digest(path)
        after=path.stat();row['metadata_stable_during_read']=(before.st_size,before.st_mtime_ns,before.st_ino)==(after.st_size,after.st_mtime_ns,after.st_ino)
        out['weights'].append(row)
        print(json.dumps({'event':'shard_hashed' if a.hash_weights else 'shard_metadata','name':path.name}),flush=True)
    out['mapped_shards_match_index']=bool(expected) and expected=={x.name for x in paths}
    out['all_stable']=bool(paths) and all(x['metadata_stable_during_read'] for x in out['weights'])
    out['finished_ns']=time.time_ns();print(json.dumps({'event':'result','result':out}),flush=True)
    return 0 if out['processes'] and out['mapped_shards_match_index'] and out['all_stable'] else 1

if __name__=='__main__':raise SystemExit(main())

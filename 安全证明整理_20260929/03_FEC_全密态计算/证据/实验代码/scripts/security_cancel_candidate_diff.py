"""Generate a reviewable overlay diff and source identities; no runtime mutation."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = ROOT / 'security_fixes/20260917_cancel'
BASE = ROOT / 'results/security_cancel_fix_20260917/baseline'


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--output-dir', type=Path, required=True)
    args = p.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    originals = {
        'engine/serve35_cb.c': ROOT / 'delivery/OTP35B_CB_V11_20260903/serve35_cb.c',
        'gateway/tee_gateway.py': BASE / 'tee_gateway.py',
        'server/session.py': BASE / 'session.py',
        'server/vllm_backend.py': BASE / 'vllm_backend.py',
        'server/http_api.py': BASE / 'http_api.py',
        'server/generation.py': ROOT / 'security_fixes/20260916/server/generation.py',
    }
    chunks, entries = [], []
    for file in sorted(CANDIDATE.rglob('*')):
        if not file.is_file() or file.suffix not in ('.py', '.c', '.cpp', '.h'):
            continue
        relative = file.relative_to(CANDIDATE).as_posix()
        base = originals.get(relative)
        old = base.read_text(encoding='utf-8').splitlines(keepends=True) if base else []
        new = file.read_text(encoding='utf-8').splitlines(keepends=True)
        chunks.extend(difflib.unified_diff(old, new, fromfile='a/' + relative if base else '/dev/null', tofile='b/' + relative))
        entries.append({'path': relative, 'sha256': hashlib.sha256(file.read_bytes()).hexdigest(),
                        'base_path': str(base.relative_to(ROOT)) if base else None,
                        'base_sha256': hashlib.sha256(base.read_bytes()).hexdigest() if base else None})
    with (args.output_dir / 'candidate.diff').open('x', encoding='utf-8') as f:
        f.write(''.join(chunks))
    with (args.output_dir / 'candidate_identity.json').open('x', encoding='utf-8') as f:
        json.dump({'scope': 'overlay candidate, not applied to runtime', 'files': entries}, f, ensure_ascii=False, indent=2)
    print(json.dumps({'files': len(entries), 'diff': str(args.output_dir / 'candidate.diff')}))


if __name__ == '__main__':
    main()

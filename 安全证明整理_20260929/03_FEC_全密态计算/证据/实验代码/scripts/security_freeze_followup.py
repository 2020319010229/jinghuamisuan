"""Freeze this follow-up batch without modifying earlier evidence."""
import ast
import hashlib
import json
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BATCH = ROOT / 'results/security_followup_20260917'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    checked = {}
    for name in ('security_deploy_20260917', 'security_fix_20260916'):
        directory = ROOT / 'results' / name
        manifest_name = 'manifest_fix_01.json' if name == 'security_fix_20260916' else 'manifest.json'
        manifest = json.loads((directory / manifest_name).read_text(encoding='utf-8'))
        rows = manifest['files']
        for row in rows:
            path = directory / row['path']
            assert path.is_file() and digest(path) == row['sha256'], str(path)
        checked[name] = len(rows)
    files = ['docs/SECURITY_EXECUTION_TRACKER.md', 'docs/SECURITY_EVIDENCE_PROTOCOL.md',
             'docs/SECURITY_TRUST_BOUNDARIES.md', 'docs/SECURITY_CUSTOMER_SELFCHECK.htm']
    scripts = ['security_model_inventory.py', 'security_run_remaining_inventory.py',
               'security_firmware_query.py', 'security_npu_extended_probe.cpp',
               'security_run_npu_extended.py', 'security_sdk_cancel_probe.py',
               'security_run_sdk_cancel.py', 'security_customer_selfcheck.py',
               'security_sdk_probe.py', 'security_workspace_probe.cpp',
               'security_run_workspace_probe.py', 'security_freeze_followup.py']
    files += ['scripts/' + name for name in scripts]
    canonical = Path('C:/Users/孙凯/AppData/Local/Temp/codex-security-scans/otp_c35/workspace_20260917/artifacts/05_findings/FEC-RNS-WS-01')
    shutil.copytree(canonical, BATCH / 'workspace_validation')
    snapshot = BATCH / 'snapshot'
    snapshot.mkdir(exist_ok=False)
    for relative in files:
        source = ROOT / relative
        if source.suffix == '.py':
            ast.parse(source.read_text(encoding='utf-8-sig'))
        target = snapshot / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    for page in (BATCH / 'progress_report.htm', ROOT / 'docs/SECURITY_CUSTOMER_SELFCHECK.htm'):
        for ref in re.findall(r'href="([^"]+)"', page.read_text(encoding='utf-8')):
            if ref == 'manifest.json':
                continue
            assert (page.parent / ref).resolve().is_file(), (str(page), ref)
    report = {'prior_manifests_verified': checked, 'snapshot_files': len(files),
              'python_syntax': 'passed', 'report_local_links': 'passed',
              'customer_live_execution': False}
    with (BATCH / 'verification.json').open('x', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    rows = [{'path': p.relative_to(BATCH).as_posix(), 'sha256': digest(p)}
            for p in sorted(BATCH.rglob('*')) if p.is_file() and p.name != 'manifest.json']
    with (BATCH / 'manifest.json').open('x', encoding='utf-8') as f:
        json.dump({'scope': 'local integrity hashes, not signed provenance', 'files': rows}, f, indent=2)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

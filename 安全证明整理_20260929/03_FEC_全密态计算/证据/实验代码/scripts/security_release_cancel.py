"""Deploy the 20260917_cancel candidate (engine + gateway + cvm_server) with backup and rollback.

Scope: replaces the running NPU engine binary, the encrypted gateway and the CVM server
cancellation path so that a client cancellation actually stops device work. Keeps the previous
files and images; never clears the replay ledger. Not a claim of full security acceptance.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
import tempfile
import time

from security_remote import Remote, PROJECT

RELEASE = 'security-20260918-01'
ENGINE_CONTAINER = 'otp-c35-cb'
CVM_CONTAINER = 'cvm-server'
BACKUP_ROOT = '/data/' + RELEASE                      # CVM persistent volume, also /data in engine container
CVM_BACKUP_ROOT = '/opt/cvm/data/' + RELEASE          # cvm-server persistent bind mount
CANCEL_KEY = '/data/otp_c35/.otp_cancel.key'

LIVE_ENGINE = '3cdae626266c4955003eb3f33f2ce4a466c819604472b5e56c4a0806bdd40e98'
LIVE_GATEWAY = '04cea42935a608f5d1887b73ee9c2a6e3c8030858d35a45e80e351b903f95311'

CANDIDATE = PROJECT / 'security_fixes/20260917_cancel'

# container path -> local source
GATEWAY_FILES = {
    '/opt/otp35/tee_gateway.py': CANDIDATE / 'gateway/tee_gateway.py',
    '/opt/otp35/otp_cancel_registry.py': CANDIDATE / 'gateway/otp_cancel_registry.py',
    '/opt/otp35/otp_cancel_auth.py': CANDIDATE / 'protocol/otp_cancel_auth.py',
}
CVM_FILES = {
    '/opt/cvm/cvm_server/generation.py': CANDIDATE / 'server/generation.py',
    '/opt/cvm/cvm_server/http_api.py': CANDIDATE / 'server/http_api.py',
    '/opt/cvm/cvm_server/session.py': CANDIDATE / 'server/session.py',
    '/opt/cvm/cvm_server/vllm_backend.py': CANDIDATE / 'server/vllm_backend.py',
}

ENTRYPOINT = '/opt/otp35/docker-entrypoint.sh'
# Injected right after the existing LD_LIBRARY_PATH export; engine and gateway inherit it.
ENTRYPOINT_INJECT = '''
CANCEL_KEY_FILE=${OTP_CANCEL_KEY_FILE:-/data/otp_c35/.otp_cancel.key}
export OTP_CANCEL_KEY_FILE="$CANCEL_KEY_FILE"
mkdir -p "$(dirname "$CANCEL_KEY_FILE")"
if [[ ! -s "$CANCEL_KEY_FILE" ]]; then
  ( umask 077; od -An -tx1 -N32 /dev/urandom | tr -d " \\n" > "$CANCEL_KEY_FILE" )
fi
chmod 600 "$CANCEL_KEY_FILE"
'''


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


class Release:
    def __init__(self, remote, report):
        self.r = remote
        self.report = report
        self.steps = report.setdefault('steps', [])

    def run(self, name, command, *, timeout=60, check=True, target='cvm'):
        result = self.r.run(target, command, timeout=timeout)
        self.steps.append({'name': name, 'exit_code': result['exit_code'],
                           'stdout': result['stdout'][-4000:], 'stderr': result['stderr'][-2000:]})
        if check and result['exit_code']:
            raise RuntimeError(name + ' failed: ' + result['stderr'][-400:])
        return result['stdout'].strip()

    def inside(self, name, container, command, *, timeout=60, check=True):
        return self.run(name, 'docker exec ' + container + ' sh -c ' + shlex.quote(command),
                        timeout=timeout, check=check)

    def digest(self, container, path):
        out = self.inside('sha_' + path.replace('/', '_'), container,
                          'sha256sum ' + shlex.quote(path) + ' 2>/dev/null || echo MISSING', check=False)
        return out.split()[0] if out and out != 'MISSING' else 'MISSING'

    def wait_health(self, url, name, tries=600):
        for _ in range(tries):
            out = self.run(name, "curl --noproxy '*' -fsS --max-time 5 " + url + " 2>/dev/null || true",
                           timeout=20, check=False)
            if out.strip():
                return out.strip()
            time.sleep(1)
        raise RuntimeError(name + ' did not become healthy')


def stage_files(rel, mapping, stage, container, extra=None):
    """Upload a name->bytes mapping into the container via a tar staged on the CVM."""
    payload = dict(extra or {})
    for target, source in mapping.items():
        payload[target] = source.read_bytes()
    with tempfile.TemporaryDirectory(prefix='otp-cancel-release-') as local:
        bundle = Path(local) / 'release.tar'
        with tarfile.open(bundle, 'w') as tar:
            for target, data in payload.items():
                info = tarfile.TarInfo(target.lstrip('/').replace('/', '__'))
                info.size = len(data)
                info.mode = 0o600
                tar.addfile(info, io.BytesIO(data))
        rel.r.put('cvm', bundle, stage + '/release.tar')
    dest = rel.inside('mktemp_' + container, container,
                      'mktemp -d /tmp/otp-security-release-20260918.XXXXXX')
    if not dest.startswith('/tmp/otp-security-release-20260918.'):
        raise RuntimeError('Unexpected staging path')
    rel.run('copy_' + container, 'docker cp ' + shlex.quote(stage + '/release.tar') + ' '
            + shlex.quote(container + ':' + dest + '/release.tar'))
    rel.inside('extract_' + container, container,
               'cd ' + shlex.quote(dest) + ' && tar -xf release.tar')
    return dest, {t: sha256_bytes(d) for t, d in payload.items()}


def install(rel, container, dest, targets, backup_dir):
    """Backup then atomically move each staged file into place, verifying digests."""
    for target in targets:
        staged = dest + '/' + target.lstrip('/').replace('/', '__')
        before = rel.digest(container, target)
        if before != 'MISSING':
            rel.inside('backup_' + target.replace('/', '_'), container,
                       'mkdir -p ' + shlex.quote(backup_dir) + ' && cp -p ' + shlex.quote(target)
                       + ' ' + shlex.quote(backup_dir + '/' + Path(target).name))
        # mv keeps the running process on the old inode; direct cp over a live binary is ETXTBSY.
        rel.inside('install_' + target.replace('/', '_'), container,
                   'chmod --reference=' + shlex.quote(target) + ' ' + shlex.quote(staged)
                   + ' 2>/dev/null; mv -f ' + shlex.quote(staged) + ' ' + shlex.quote(target))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--skip-cvm', action='store_true', help='deploy engine+gateway only')
    parser.add_argument('--engine-binary', help='container path of a prebuilt candidate engine')
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)

    report = {'release': RELEASE, 'started_ns': time.time_ns(), 'passed': False,
              'scope': 'production deployment of cancellation propagation fix'}
    remote = None
    try:
        # ---- build the candidate engine (also proves the baseline reproduces byte-for-byte) ----
        engine_path = args.engine_binary
        if not engine_path:
            build_dir = args.output_dir / 'build'
            proc = subprocess.run([sys.executable, str(Path(__file__).with_name('security_build_cancel_candidate.py')),
                                   '--output-dir', str(build_dir)], capture_output=True, text=True)
            report['build_stdout'] = proc.stdout.strip()
            if proc.returncode:
                raise RuntimeError('Candidate build failed: ' + proc.stderr[-400:])
            built = json.loads(proc.stdout.strip().splitlines()[-1])
            if built.get('baseline_sha256') != LIVE_ENGINE:
                raise RuntimeError('Baseline build does not reproduce the live binary')
            engine_path = built['candidate_path']
            report['candidate_sha256'] = built['candidate_sha256']
        report['candidate_engine_path'] = engine_path

        remote = Remote()
        rel = Release(remote, report)

        # ---- preflight: identity and idle state ----
        pre = {'engine': rel.digest(ENGINE_CONTAINER, '/opt/otp35/bin/serve35_cb'),
               'gateway': rel.digest(ENGINE_CONTAINER, '/opt/otp35/tee_gateway.py')}
        for target in CVM_FILES:
            pre[target] = rel.digest(CVM_CONTAINER, target)
        report['preflight_digests'] = pre
        if pre['engine'] != LIVE_ENGINE or pre['gateway'] != LIVE_GATEWAY:
            raise RuntimeError('Live files drifted from the reviewed baseline')
        metrics = json.loads(rel.run('metrics_before',
                                     "curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/metrics"))
        report['metrics_before'] = metrics
        if metrics['active'] or metrics['queued']:
            raise RuntimeError('Backend is busy; refusing to restart')

        # ---- cancellation key (64 hex, 0600, owned by the service user) ----
        rel.inside('cancel_key', ENGINE_CONTAINER,
                   'mkdir -p "$(dirname ' + shlex.quote(CANCEL_KEY) + ')"; '
                   'if [ ! -s ' + shlex.quote(CANCEL_KEY) + ' ]; then '
                   '(umask 077; od -An -tx1 -N32 /dev/urandom | tr -d " \\n" > ' + shlex.quote(CANCEL_KEY) + '); fi; '
                   'chmod 600 ' + shlex.quote(CANCEL_KEY) + '; '
                   'wc -c < ' + shlex.quote(CANCEL_KEY) + '; stat -c "%a %U" ' + shlex.quote(CANCEL_KEY))
        report['cancel_key_state'] = rel.steps[-1]['stdout'].strip()

        # ---- new entrypoint: export the key path so engine and gateway both see it ----
        current = rel.inside('read_entrypoint', ENGINE_CONTAINER, 'cat ' + shlex.quote(ENTRYPOINT))
        if 'OTP_CANCEL_KEY_FILE' in current:
            new_entrypoint = current
        else:
            anchor = 'export LD_LIBRARY_PATH='
            index = current.index(anchor)
            end = current.index('\n', index) + 1
            new_entrypoint = current[:end] + ENTRYPOINT_INJECT + current[end:]
        report['entrypoint_sha256'] = sha256_bytes(new_entrypoint.encode())

        stage = rel.run('stage_dir', 'mktemp -d /tmp/otp-security-release-20260918.XXXXXX')
        if not stage.startswith('/tmp/otp-security-release-20260918.'):
            raise RuntimeError('Unexpected stage path')

        # ---- engine container: binary + gateway modules + entrypoint ----
        extra = {ENTRYPOINT: new_entrypoint.encode()}
        dest, digests = stage_files(rel, GATEWAY_FILES, stage, ENGINE_CONTAINER, extra)

        # The built engine already lives inside the container; copy it in place instead of
        # round-tripping 150 KiB of base64 through the SSH channel.
        engine_target = '/opt/otp35/bin/serve35_cb'
        engine_staged = dest + '/' + engine_target.lstrip('/').replace('/', '__')
        rel.inside('stage_engine', ENGINE_CONTAINER,
                   'cp ' + shlex.quote(engine_path) + ' ' + shlex.quote(engine_staged))
        staged_engine_sha = rel.inside('stage_engine_sha', ENGINE_CONTAINER,
                                       'sha256sum ' + shlex.quote(engine_staged)).split()[0]
        if report.get('candidate_sha256') and staged_engine_sha != report['candidate_sha256']:
            raise RuntimeError('Candidate engine digest mismatch')
        digests[engine_target] = staged_engine_sha
        report['staged_digests'] = digests
        install(rel, ENGINE_CONTAINER, dest, list(GATEWAY_FILES) + list(extra) + [engine_target],
                BACKUP_ROOT + '/engine-backup')
        after = {p: rel.digest(ENGINE_CONTAINER, p)
                 for p in list(GATEWAY_FILES) + list(extra) + [engine_target]}
        report['engine_container_after'] = after
        for path, want in digests.items():
            if after.get(path) != want:
                raise RuntimeError('Installed digest mismatch for ' + path)

        rel.run('restart_engine', 'docker restart -t 90 ' + ENGINE_CONTAINER, timeout=180)
        report['engine_health'] = rel.wait_health('http://127.0.0.1:8020/healthz', 'engine_health')
        report['gateway_health'] = rel.wait_health('http://127.0.0.1:8000/healthz', 'gateway_health')

        # ---- cvm-server: cancellation propagation ----
        if not args.skip_cvm:
            cvm_dest, cvm_digests = stage_files(rel, CVM_FILES, stage, CVM_CONTAINER)
            install(rel, CVM_CONTAINER, cvm_dest, list(CVM_FILES), CVM_BACKUP_ROOT + '/server-backup')
            cvm_after = {p: rel.digest(CVM_CONTAINER, p) for p in CVM_FILES}
            report['cvm_after'] = cvm_after
            for path, want in cvm_digests.items():
                if cvm_after.get(path) != want:
                    raise RuntimeError('Installed digest mismatch for ' + path)
            rel.run('restart_cvm', 'docker restart -t 30 ' + CVM_CONTAINER, timeout=120)
            time.sleep(5)
            report['cvm_running'] = rel.run('cvm_state',
                                            "docker inspect -f '{{.State.Running}} {{.State.Health.Status}}' "
                                            + CVM_CONTAINER, check=False)

        # ---- post checks ----
        report['engine_has_cancel'] = rel.inside('engine_strings', ENGINE_CONTAINER,
                                                 'strings /opt/otp35/bin/serve35_cb | grep -c "internal/cancel"',
                                                 check=False)
        report['gateway_cancel_env'] = rel.inside('gateway_env', ENGINE_CONTAINER,
                                                  'tr "\\0" "\\n" < /proc/1/environ | grep OTP_CANCEL_KEY_FILE || true',
                                                  check=False)
        report['unauthorized_cancel'] = rel.run('unauth_cancel',
            "curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST "
            "-H 'Content-Type: application/json' -d '{\"request_id\":\"probe\"}' "
            "http://127.0.0.1:8000/infer/cancel", check=False)
        report['metrics_after'] = json.loads(rel.run('metrics_after',
                                                     "curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8020/metrics"))

        # ---- persist images so a container recreate keeps the fix ----
        images = {}
        for container, repo in ((ENGINE_CONTAINER, 'vllm-otp'), (CVM_CONTAINER, 'cvm-server')):
            before_tag = repo + ':' + RELEASE + '-before'
            current_image = rel.run('image_' + container,
                                    "docker inspect -f '{{.Config.Image}}' " + container)
            rel.run('tag_before_' + container, 'docker tag ' + shlex.quote(current_image) + ' '
                    + shlex.quote(before_tag), check=False)
            new_tag = repo + ':' + RELEASE
            rel.run('commit_' + container, 'docker commit ' + container + ' ' + shlex.quote(new_tag), timeout=300)
            rel.run('retag_' + container, 'docker tag ' + shlex.quote(new_tag) + ' ' + shlex.quote(current_image))
            images[container] = {'previous_tag': before_tag, 'new_tag': new_tag, 'deploy_tag': current_image}
        report['images'] = images

        report['passed'] = (report['unauthorized_cancel'] == '403'
                            and report['engine_has_cancel'].strip() not in ('', '0'))
    except Exception as exc:
        report['error_type'] = type(exc).__name__
        report['error'] = str(exc)
    finally:
        if remote:
            remote.close()
        report['finished_ns'] = time.time_ns()
        with (args.output_dir / 'result.json').open('x', encoding='utf-8') as out:
            json.dump(report, out, ensure_ascii=False, indent=2)
    print(json.dumps({k: report.get(k) for k in
                      ('passed', 'error', 'candidate_sha256', 'engine_has_cancel',
                       'unauthorized_cancel', 'engine_health', 'cvm_running')}, ensure_ascii=False))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

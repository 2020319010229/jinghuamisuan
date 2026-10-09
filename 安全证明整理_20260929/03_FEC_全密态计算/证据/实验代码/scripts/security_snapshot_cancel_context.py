"""Read only the exact deployed cancellation callers; never read environment files."""
import hashlib
import json
from pathlib import Path
from security_remote import Remote, PROJECT


def main():
    directory = PROJECT / 'results/security_cancel_fix_20260917/baseline'
    r = Remote()
    out = {}
    try:
        for name in ('latency.py', 'http_api.py', 'server.py'):
            result = r.run('cvm', 'docker exec cvm-server cat /opt/cvm/cvm_server/' + name)
            if result['exit_code']:
                raise RuntimeError('Source read failed')
            with (directory / name).open('x', encoding='utf-8') as f:
                f.write(result['stdout'])
            out[name] = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        print(json.dumps(out))
    finally:
        r.close()


if __name__ == '__main__':
    main()

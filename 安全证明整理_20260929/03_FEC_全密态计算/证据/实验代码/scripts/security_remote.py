"""Shared SSH transport for scoped experiments. Never print credential values."""
import sys
import base64
import shlex
from pathlib import Path
import paramiko

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'benchmark' / 'three_way_controlled_rerun'))
from run_controlled_three_way_remote import OuterHost, credentials, cvm_shell, cvm_scp_to


class NestedShell:
    """Use the established nested-SSH command path, not SSH port forwarding."""
    def __init__(self, host):
        self.host = host

    def exec_command(self, command, timeout=40):
        return self.host.exec_command(cvm_shell(command), timeout=timeout)

    def close(self):
        pass


class Remote:
    def __init__(self):
        self.outer = OuterHost()
        self.host = self.outer.ensure()
        self.cvm = NestedShell(self.host)
        self.staging = None

    def close(self):
        self.cvm.close()
        self.outer.close()

    def run(self, target, command, timeout=40):
        client = self.host if target == 'host' else self.cvm
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode('utf-8', 'replace')
        err = stderr.read().decode('utf-8', 'replace')
        return {'exit_code': stdout.channel.recv_exit_status(), 'stdout': out, 'stderr': err}

    def get(self, target, remote, local):
        local = Path(local)
        if local.exists():
            raise FileExistsError(local)
        local.parent.mkdir(parents=True, exist_ok=True)
        if target == 'host':
            with self.host.open_sftp() as sftp:
                sftp.get(remote, str(local))
        else:
            result = self.run('cvm', 'base64 -- '+shlex.quote(remote))
            if result['exit_code']:
                raise RuntimeError('Remote download failed')
            local.write_bytes(base64.b64decode(result['stdout']))

    def put(self, target, local, remote):
        # Uploads are only allowed into this task's fresh temporary directories.
        if not remote.startswith('/tmp/otp-security-') or '/..' in remote:
            raise ValueError('Not an experiment temporary path')
        if target == 'host':
            with self.host.open_sftp() as sftp:
                sftp.put(str(local), remote)
        else:
            if self.staging is None:
                result = self.run('host', 'mktemp -d /tmp/otp-security-stage-20260916.XXXXXX')
                self.staging = result['stdout'].strip()
                if result['exit_code'] or not self.staging.startswith('/tmp/otp-security-stage-20260916.'):
                    raise RuntimeError('Cannot prepare staging directory')
            staged = self.staging+'/'+Path(local).name
            with self.host.open_sftp() as sftp:
                sftp.put(str(local), staged)
            result = self.run('host', cvm_scp_to(staged, remote))
            if result['exit_code']:
                raise RuntimeError('CVM upload failed')

"""One bounded TCP check of the already configured SSH endpoint; no login."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import socket
import time
from security_remote import credentials

def main():
    p=argparse.ArgumentParser(); p.add_argument('--output',type=Path,required=True); a=p.parse_args()
    report={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'endpoint_config_hash':hashlib.sha256((str(credentials.HOST)+':'+str(credentials.HPORT)).encode()).hexdigest(),
            'timeout_s':5,'scope':'configured SSH TCP reachability only, not service or machine health'}
    with a.output.open('x',encoding='utf-8') as f:
        start=time.monotonic()
        try:
            with socket.create_connection((credentials.HOST,credentials.HPORT),timeout=5):
                report['tcp_connected']=True
        except OSError as exc:
            report.update(tcp_connected=False,error_type=type(exc).__name__,errno=exc.errno)
        report['elapsed_s']=time.monotonic()-start
        json.dump(report,f,indent=2)
    print(json.dumps(report))

if __name__=='__main__': main()

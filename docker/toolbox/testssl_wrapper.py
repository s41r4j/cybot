#!/usr/bin/env python3
"""Emit one bounded JSON document from Debian's TestSSL engine."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

ENGINE=Path('/usr/bin/testssl')
DATA=Path('/etc/testssl')
OPENSSL=Path('/usr/bin/openssl')
VERSION='3.2.1'
MAXIMUM=16*1024*1024


def endpoint(value):
    if not isinstance(value,str) or not value or len(value)>512 or any(c.isspace() or ord(c)<32 for c in value):
        raise ValueError('Expected one hostname/IP with an optional TCP port')
    host,port=value,443
    if '%' in value:raise ValueError('Scoped IPv6 addresses are not supported')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if value.startswith('['):
            match=re.fullmatch(r'\[([^\]]+)\]:([0-9]{1,5})',value)
            if not match:raise ValueError('IPv6 ports require [address]:port')
            host,port=match[1],int(match[2])
            if ipaddress.ip_address(host).version!=6:raise ValueError('Expected bracketed IPv6 address')
        elif ':' in value:
            if value.count(':')!=1:raise ValueError('Invalid TLS endpoint')
            host,raw=value.split(':')
            if not re.fullmatch(r'[0-9]{1,5}',raw):raise ValueError('Invalid TCP port')
            port=int(raw)
        try:ipaddress.ip_address(host)
        except ValueError:
            if len(host)>253 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',label) for label in host.split('.')):
                raise ValueError('Invalid hostname')
    if not 1<=port<=65535:raise ValueError('Invalid TCP port')
    return ('['+host+']' if ':' in host else host)+':'+str(port)


def limits():
    resource.setrlimit(resource.RLIMIT_FSIZE,(MAXIMUM,MAXIMUM))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version',action='version',version='testssl '+VERSION+' (CYBOT structured adapter)')
    parser.add_argument('--target',required=True)
    parser.add_argument('--checks',choices=('full','protocols'),default='full')
    options=parser.parse_args()
    try:target=endpoint(options.target)
    except ValueError as error:parser.error(str(error))
    result={'schema':1,'engine':'testssl','version':VERSION,'target':options.target,'checks':options.checks,
            'completed':False,'exit_code':1,'report':None,'error':''}
    with tempfile.TemporaryDirectory(prefix='cybot-tls-') as temp:
        root=Path(temp);report=root/'scan.json'
        env={'PATH':'/usr/bin:/bin','HOME':str(root),'TMPDIR':str(root),'LC_ALL':'C',
             'OPENSSL':str(OPENSSL),'TESTSSL_INSTALL_DIR':str(DATA)}
        args=[str(ENGINE),'--warnings','batch','--color','0','--quiet','--ip','one',
              '--connect-timeout','5','--openssl-timeout','5','--jsonfile-pretty',str(report)]
        if options.checks=='protocols':args+=['--protocols']
        args+=[target]
        try:
            with (root/'diagnostic.txt').open('wb') as output:
                process=subprocess.run(args,cwd=root,env=env,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,
                                       timeout=900,preexec_fn=limits)
            result['exit_code']=process.returncode
            result['completed']=process.returncode==0
            if process.returncode:result['error']='TestSSL engine failed; no complete TLS assessment is established'
        except (OSError,subprocess.TimeoutExpired):
            result['error']='TestSSL engine failed or timed out; no complete TLS assessment is established'
        if report.is_file() and not report.is_symlink() and report.stat().st_size<=MAXIMUM:
            try:
                data=json.loads(report.read_bytes())
                if not isinstance(data,dict):raise ValueError('Expected report object')
                # These headers expose local host paths and the scratch command.
                data.pop('Invocation',None);data.pop('at',None)
                result['report']=data
            except (ValueError,UnicodeError):result['error']='TestSSL did not emit a complete bounded JSON report'
        else:result['error']='TestSSL did not emit a complete bounded JSON report'
        if result['error']:result['completed']=False
    encoded=json.dumps(result,separators=(',',':'))
    if len(encoded.encode())>MAXIMUM:
        result.update(completed=False,report=None,error='TestSSL structured output exceeded its bound')
        encoded=json.dumps(result,separators=(',',':'))
    print(encoded)
    return 0 if result['completed'] else 1


if __name__=='__main__':raise SystemExit(main())

"""Single-target Dirsearch API with bounded anonymous requests and JSONL progress."""
import argparse
import json
import os
from pathlib import Path
import sys
import time
from urllib.parse import urlsplit, unquote

import requests
from dirsearch import DirsearchFuzzer,FuzzerConfig,Wordlist
from lib.core.settings import VERSION


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version',action='version',version='Dirsearch '+VERSION+' (CYBOT sequential library adapter)')
    parser.add_argument('-u','--url',required=True)
    parser.add_argument('-w','--wordlist',required=True)
    args=parser.parse_args()
    count=0
    def emit(kind,**fields):
        print(json.dumps(dict(record=kind,engine='Dirsearch',version=VERSION,target=args.url,**fields),separators=(',',':')),flush=True)
    try:
        target=urlsplit(args.url)
        if len(args.url)>8192 or any(c in args.url for c in '\r\n\0') or target.scheme not in ('http','https') or not target.hostname or target.username or target.password or target.fragment:
            raise ValueError('Invalid target')
        words=Path(args.wordlist)
        if words.is_symlink() or not words.is_file() or words.stat().st_size>1024*1024:raise ValueError('Invalid bounded wordlist')
        with words.open('rb') as f: raw=f.read(1024*1024+1)
        if len(raw)>1024*1024:raise ValueError('Wordlist grew beyond its bound')
        wordlist=Wordlist(raw.decode('utf-8').splitlines(),max_entries=10000)
        if not len(wordlist):raise ValueError('Empty wordlist')
        ca=os.environ.get('REQUESTS_CA_BUNDLE') or os.environ.get('SSL_CERT_FILE')
        if ca:
            path=Path(ca)
            if not path.is_absolute() or path.is_symlink() or not path.is_file() or path.stat().st_size>1024*1024:raise ValueError('Invalid explicit CA file')
        origin=(target.scheme,target.hostname,target.port or (443 if target.scheme=='https' else 80))
        prefix=target.path.rstrip('/')+'/'
        class BoundedSession(requests.Session):
            def __init__(self):
                super().__init__();self.trust_env=False;self.next_request=0
            def request(self,method,url,**kwargs):
                parsed=urlsplit(url);decoded=parsed.path
                for _ in range(4):decoded=unquote(decoded)
                if (parsed.scheme,parsed.hostname,parsed.port or (443 if parsed.scheme=='https' else 80))!=origin or not parsed.path.startswith(prefix) or '..' in decoded.split('/') or '\\' in decoded or method!='GET':
                    raise requests.RequestException('Wordlist request exceeds target scope')
                time.sleep(max(0,self.next_request-time.monotonic()));self.next_request=time.monotonic()+0.1
                kwargs.update(stream=True,verify=ca or True,allow_redirects=False,timeout=5)
                response=super().request(method,url,**kwargs)
                try:
                    body=response.raw.read(1024*1024+1,decode_content=True)
                    if len(body)>1024*1024:raise requests.RequestException('Response body exceeds bound')
                    if response.status_code>=500:raise requests.RequestException('Target returned an HTTP server error')
                    response._content=body;response._content_consumed=True
                    return response
                finally:response.close()
        def observed(result,matched):
            nonlocal count
            count+=1;emit('response',url=result.url,status=result.status,matched=matched)
        accepted=frozenset(range(200,300))|frozenset({301,302,303,307,308,401,403,405})
        config=FuzzerConfig(url=args.url,wordlist=wordlist,http_method='GET',timeout=5,follow_redirects=False,verify_tls=True,
                            include_status_codes=accepted,session_factory=BoundedSession,raise_on_error=True)
        DirsearchFuzzer(config,on_result=lambda result:observed(result,True),on_not_found=lambda result:observed(result,False)).run()
        if count!=len(wordlist):raise RuntimeError('Incomplete wordlist coverage')
        emit('complete',count=count)
        return 0
    except Exception as error:
        emit('error',error=type(error).__name__)
        print('Dirsearch operation failed; retained responses are incomplete.',file=sys.stderr)
        return 1


if __name__=='__main__':sys.exit(main())

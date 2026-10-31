"""Run CORScanner's complete sequential single-target check list as strict JSON.

Anonymous requests only, verified TLS, no redirects, no body downloads or
network suffix-list refresh. A candidate describes headers, not exploitability.
"""
import argparse
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit


class QuietLog:
    def info(self, _): pass
    def warning(self, _): pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version',action='version',version='CORScanner 0.9.7 (CYBOT sequential library adapter)')
    parser.add_argument('-u','--url',required=True)
    args = parser.parse_args()
    try:
        url = urlsplit(args.url)
        if len(args.url)>8192 or any(c in args.url for c in '\r\n\0') or url.scheme not in ('http','https') or not url.hostname or url.username or url.password or url.fragment:
            raise ValueError('Invalid single-target URL')
        ca = os.environ.get('REQUESTS_CA_BUNDLE') or os.environ.get('SSL_CERT_FILE')
        if ca:
            path = Path(ca)
            if not path.is_absolute() or path.is_symlink() or not path.is_file() or path.stat().st_size>1024*1024:
                raise ValueError('Invalid explicit CA file')
        from CORScanner.common.corscheck import CORSCheck
        engine = CORSCheck(args.url,{'headers':None,'logger':QuietLog(),'ca_file':ca or True})
        try:
            result = engine.check_one_by_one()
        finally:
            engine.session.close()
        if not 1 <= engine.request_count <= 128 or len(engine.status_codes) != engine.request_count:
            raise RuntimeError('Missing completed request evidence')
        report = {'schema':1,'engine':'CORScanner','version':'0.9.7','target':args.url,'completed':True,
                  'requests':engine.request_count,'status_codes':engine.status_codes,'candidates':[result] if result else []}
        print(json.dumps(report,separators=(',',':')))
    except Exception as error:
        print('CORS operation failed ('+type(error).__name__+'); no complete policy assessment is established.',file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

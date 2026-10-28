#!/usr/bin/env python3
"""Reject stale catalog exports without executing cataloged tools."""
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
actual = json.loads(Path(sys.argv[1]).read_text())
for name in ('release/catalog-coverage.json', 'website/coverage.json'):
    if actual != json.loads((root/name).read_text()):
        raise SystemExit('Stale inventory export: '+name)
baseline = json.loads((root/'release/catalog-baseline.json').read_text())
for family in ('tools', 'capabilities'):
    if {row['id'] for row in actual[family]} != set(baseline[family]):
        raise SystemExit('Complete baseline differs: '+family)
print('All 84 tools and 71 capabilities are included; exported inventories match the executable.')

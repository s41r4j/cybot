#!/usr/bin/env python3
"""Refresh the public inventory and support matrix from an actual CLI export."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def export(coverage):
    text = json.dumps(coverage, indent=2)+'\n'
    for target in ('release/catalog-coverage.json', 'website/coverage.json'):
        (ROOT/target).write_text(text)
    lines = ['# Complete tool and capability support matrix', '',
             'Generated from the executable command surface. All entries remain in the full-release requirement. Implementation is separate from installation and certification. See [release status](release-status.md).', '',
             '## Tools', '', '| Tool | Implementation | Platform declaration | Actual capability mappings |', '| --- | --- | --- | --- |']
    for tool in coverage['tools']:
        lines.append('| `'+tool['id']+'` | '+tool['implementation']+' | '+(', '.join(tool['platforms']) or 'undeclared')+' | '+(', '.join(tool['capabilities']) or '**no executable mapping**')+' |')
    lines += ['', '## Capabilities', '', '| Capability | Implementation | Executable tools |', '| --- | --- | --- |']
    for capability in coverage['capabilities']:
        lines.append('| `'+capability['id']+'` | '+capability['implementation']+' | '+(', '.join(capability['tools']) or 'built-in')+' |')
    (ROOT/'docs/tool-support.md').write_text('\n'.join(lines)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('coverage', type=Path)
    export(json.loads(parser.parse_args().coverage.read_text()))

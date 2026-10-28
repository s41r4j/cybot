#!/usr/bin/env python3
"""Run real core-tool integration tests in a network-isolated, bounded container."""
import argparse
import toolbox
from toolbox_validation import validate_image

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-cli', action='store_true', help='Test a freshly compiled CLI overlay instead of the pinned installed CLI')
    options = parser.parse_args()
    with toolbox.operation_lock():
        validate_image(toolbox.current_image(), source_cli=options.source_cli)

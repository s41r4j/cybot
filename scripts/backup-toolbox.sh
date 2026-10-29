#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$script_dir/toolbox.py" --profile "${CYBOT_TOOLBOX_PROFILE:-core}" backup "$@"

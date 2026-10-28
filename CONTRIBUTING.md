# Contributing to CYBOT

Use Go 1.26.10, Python 3.11+ and a compatible Docker environment for integration
work. Only use synthetic data and explicitly authorized isolated fixtures.

```sh
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
python3 -m unittest discover -s scripts -p 'test_*.py'
```

An adapter contribution needs a precise operation and target/resource contract,
pinned tool version and data dependencies, structured normalization, positive and
negative fixtures, failure behavior, secret hygiene, and real-operation evidence
from each supported release platform. Include missing-credential, timeout and
incompatible-version cases where relevant. Help/version probes prove presence
only. Never change a status/count to bypass the full-catalog release gate.

Keep private engagement data, credentials, runtime databases, generated reports,
reference clones and machine-local images out of Git. Public snapshots are
exported with `python3 scripts/public_source.py /absolute/empty/destination`.
Report product vulnerabilities privately using SECURITY.md.

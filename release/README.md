# Full-catalog release evidence

The baseline includes every catalog tool and capability. Run the release gate
from the repository root. Missing, stale or partial evidence blocks publishing
stable releases; normal source CI and the development website are independent.

`validation/evidence.json` may contain `source_sha256` from
`scripts/public_source.py --digest` and a `records` array. Each record identifies
`kind` (tool/capability), `id`, `status` (passed), `mode` (real-operation),
`platform`, `version` for tools, `binary_sha256`, `cases` (positive/negative/failure),
`report` (path relative to validation/) and `report_sha256`.

The JSON report itself must repeat kind, ID, source digest, binary digest and
platform and contain `cases` records with matching types, passed status and
real-operation mode. Retain the underlying fixture test logs and provenance.
Never fabricate records from catalog presence or parser-only fixtures.

Source digests deliberately include product code, tests, configuration, catalogs,
schemas, runtime scripts and Docker inputs. Editing these invalidates evidence.
Published image references must use registry digests. Machine-local validated
pins belong under .cybot/, not the tracked release contract.

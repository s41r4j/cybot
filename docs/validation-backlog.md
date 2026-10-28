# Validation environments and remaining work

Updated 2026-10-28. Windows/Active Directory and cloud labs are unavailable and
their specialist validation is explicitly deferred. These entries remain in the
full catalog and full-release gate; deferral does not certify or remove them.

## Environment-dependent validation

| Environment | Status | Required evidence |
| --- | --- | --- |
| Linux AMD64 and ARM64 | GitHub-hosted isolated runtime fixtures available | Current-source real tool operations, clean controls and failure behavior |
| Windows native CLI | Hosted portable source CI available | CLI portability checks; these do not certify Windows security tools |
| Windows security tools | Deferred: no dedicated lab | Pinned runtimes and safe local fixtures on compatible Windows hosts |
| Windows storage ACLs | Not certified | Verify private NTFS ACLs; Unix 0600/0700 mode assertions do not establish Windows access control |
| Active Directory | Deferred: no dedicated lab | Disposable domain, test identities and explicit operation/resource scope |
| Cloud accounts | Deferred: no designated test accounts | Isolated account/project, least-privilege test identity and resource fixtures |
| External providers | Not certified | Mock/local provider contracts plus separately authorized credential/provider tests |

## Implementation backlog

`docs/tool-support.md` and `release/catalog-coverage.json` enumerate every
unfinished adapter and unmapped tool. Remaining work includes replacing
help/status/startup placeholders with real scoped operation contracts, adding
operation-specific normalization, declaring verified platform support, supplying
runtime/data dependencies, and retaining positive/negative/failure evidence.

Priorities for Linux expansion are static code analysis and supply-chain tools,
then web/DNS specialist adapters. A new binary in an image does not by itself
complete a capability. Keep the independent full-product release gate blocked
until the entire declared scope is supported and validated.

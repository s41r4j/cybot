# Security policy

CYBOT is under active development. No stable public release or complete
tool/capability certification is currently claimed. The release validation
report identifies exactly what has and has not been tested.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/s41r4j/cybot/security/advisories/new)
for vulnerabilities in CYBOT. Include the affected commit/version, platform,
configuration, a minimal reproduction using synthetic data or an isolated lab,
and the expected versus observed behavior. Never attach live credentials,
customer evidence or private assessment targets to a public issue.

For a vulnerability in a bundled third-party tool, contact that tool's
maintainers and identify the affected CYBOT profile/version in the private
report. Catalog inclusion does not establish upstream security or support.

## Execution and evidence

Only use CYBOT on systems you own or have explicit authorization to assess.
Choose `configs/cybot.strict.yaml` to enforce scope and approval. The default
suggestive policy emits advisories and does not enforce target denials.
Local and interface-wide adapters require typed resource targets and explicit
approval even in suggestive mode. Review sanitized evidence before sharing;
redaction cannot recognize every encoded or unlabeled secret.

Unix storage uses restricted file/directory modes. Windows storage ACLs and
specialist security tools remain outside the certified scope; a successful
Windows CLI build/test run does not establish private NTFS access control.

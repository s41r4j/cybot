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

Local file scopes use explicit entry points such as `/workspace/source` or
`./source`; hostname allowlists do not authorize similarly named files.
Scope checks resolve the target and pattern prefixes through symlinks and
preserve filesystem path case. These checks validate the requested entry point;
native tools still run with the current user's OS permissions. Use isolated
toolbox profiles for untrusted assessment inputs.
Each toolbox profile mounts its own `.cybot/runtimes/PROFILE` state directory.
The repository's private research and unrelated `.cybot` state are not mounted
into the toolbox. Existing state is preserved in its original location.

Unix storage uses restricted file/directory modes. Windows storage ACLs and
specialist security tools remain outside the certified scope; a successful
Windows CLI build/test run does not establish private NTFS access control.

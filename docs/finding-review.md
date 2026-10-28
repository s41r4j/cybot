# Evidence-backed finding review

`classify.endpoint` supplies routing candidates in observations and decisions.
It never asserts a vulnerability from URL text.

`validate.finding` reviews a stored finding and seven explicit operator
assertions. It does not infer scope, novelty or demonstrated impact from prose.
Provide JSON using `--input-file review.json`:

```json
{
  "source_run_id": "SOURCE_RUN_ID",
  "finding_id": "FINDING_ID",
  "checks": {
    "actionable": "pass",
    "accepted_impact": "pass",
    "in_scope": "pass",
    "no_privileged_assumption": "pass",
    "novel": "pass",
    "impact_evidenced": "pass",
    "not_excluded": "pass"
  }
}
```

Use `pass`, `fail`, or `unknown` for each assertion. The source run must exist,
the finding must belong to it, and all linked evidence must be readable inside
the configured evidence store with matching SHA-256 hashes. Source runs marked
failed cannot be reviewed as complete findings.

```sh
cybot run validate.finding --target review --input-file review.json --approve
```

The verdict is CHECKLIST_PASS only with all assertions passed and evidence
integrity verified. Missing assertions/evidence produce UNVERIFIED. Excluded
scope, privileges or program rules produce KILL regardless of other answers;
missing accepted impact or novelty produces DOWNGRADE; missing actionable or
impact evidence produces CHAIN-REQUIRED. Hash mismatch and missing references
are errors. Every decision identifies assertions as operator-supplied. None of
these verdicts independently proves exploitability or warrants submission.

Local tools require `local://HOSTNAME`, naming the executing machine. Interface
operations require `interface://INTERFACE`. These need explicit approval even
with suggestive policy. Strict target policies must allow the full resource
identifier; a hostname allowlist does not grant local/interface authorization.

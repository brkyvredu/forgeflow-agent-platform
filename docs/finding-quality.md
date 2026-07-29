# Agent finding quality

ForgeFlow separates four different claims that were previously collapsed into a single
`supported` state:

- `evidence_matched`: the excerpt exists at the reported file and line range.
- `semantically_verified`: a bounded repository-level verifier confirmed the specialist claim.
- `deterministically_confirmed`: a deterministic scanner produced or confirmed the finding.
- `human_review_required`: the excerpt exists, but the semantic claim is ambiguous or contradicted
  by related repository evidence.

Only `semantically_verified` and `deterministically_confirmed` findings are eligible for the
engineering score and `--fail-on` quality gate. Human-review candidates remain visible in
`findings.json` and `review.md`, but their claimed severity is reduced to `info` and they do not
change automation outcomes.

## Current semantic verifiers

The security verifier recognizes bounded, explicit cases such as Python `eval`, `shell=True`, and
Compose credential fallbacks. A quoted environment-variable expansion in a shell command is not,
by itself, treated as proof of command injection.

The test verifier locates the affected Python symbol and searches repository test files for direct
references and selected boundary scenarios. A claim that tests are absent is not score-eligible
when related coverage is found. These checks establish a higher bar than literal evidence matching,
but they do not replace human review or a complete static-analysis engine.

## Output fields

Every published finding includes:

```json
{
  "validation_status": "semantically_verified",
  "scoring_eligible": true,
  "validation_messages": []
}
```

The execution summary reports counts for each verification level and a separate
`scoring_eligible_severity_counts` object.
